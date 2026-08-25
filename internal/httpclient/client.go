// Package httpclient provides an HTTP client that captures redirect chains.
//
// The key insight: we need to see every hop in a redirect chain, not just
// the final URL. The standard http.Client only gives us resp.Request.URL
// (the final destination). By cloning the client per-request and overriding
// CheckRedirect, we capture each hop's URL and status code without races.
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client wraps http.Client with config-driven behaviour.
// Safe for concurrent use — each Follow() call clones the client internally.
type Client struct {
	HTTP        *http.Client      // The underlying stdlib client; cloned per request.
	UserAgent   string            // Sent as User-Agent on every request; empty = Go default.
	Method      string            // HTTP verb for probes (HEAD default, GET for body work).
	Headers     map[string]string // Extra static headers applied to every request.
	MaxRedirect int               // Hard cap on hops per probe; exceeding it yields an error result.
}

// Hop stores one redirect hop for chain analysis.
//
// Semantics: Status is the redirect response that LED TO URL — i.e. "we
// got this status, therefore we went to this URL". The final landing
// response is not a hop; it lives in Result.Final/FinalStatus.
type Hop struct {
	URL    string // Absolute URL of the hop destination (the Location target).
	Status int    // Status code of the response that redirected to URL. 0 if unknown.
}

// Options configures the HTTP client. Zero values fall back to sensible
// defaults in New() — callers only set what they care about.
type Options struct {
	Timeout     time.Duration     // Per-request wall-clock budget (default 10s).
	MaxRedirect int               // Hop cap per probe (default 10).
	Method      string            // HTTP verb (default HEAD — cheap, bodyless probes).
	Proxy       string            // Optional proxy URL, e.g. "http://127.0.0.1:8080" for Burp.
	Headers     map[string]string // Static headers merged into every request.
	UserAgent   string            // User-Agent header; empty leaves the Go default.
}

// New creates a Client from options. Applies sensible defaults for
// zero-valued fields (10s timeout, 10 max redirects, HEAD method).
func New(opts Options) (*Client, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxRedirect == 0 {
		opts.MaxRedirect = 10
	}
	if opts.Method == "" {
		opts.Method = http.MethodHead
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", opts.Proxy, err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	httpClient := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirect {
				return fmt.Errorf("stopped after %d redirects", opts.MaxRedirect)
			}
			return nil
		},
	}

	return &Client{
		HTTP:        httpClient,
		UserAgent:   opts.UserAgent,
		Method:      opts.Method,
		Headers:     opts.Headers,
		MaxRedirect: opts.MaxRedirect,
	}, nil
}

// Result holds the outcome of following redirects for one URL.
type Result struct {
	Chain       []Hop  // Redirect hops (excludes the final response)
	Final       string // Final landing URL
	FinalStatus int    // HTTP status code of the final response
	Error       error  // Non-nil on network/DNS/TLS failure
}

// Follow sends a request and captures the full redirect chain.
//
// We clone the http.Client for each call so we can override CheckRedirect
// without mutating the shared instance. The closure captures `chain` and
// `lastStatus` by reference — each clone gets its own closure, so there's
// no data race between concurrent workers.
func (c *Client) Follow(ctx context.Context, rawURL string) Result {
	var chain []Hop
	var lastStatus int

	req, err := http.NewRequestWithContext(ctx, c.Method, rawURL, nil)
	if err != nil {
		return Result{Error: err}
	}

	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	// Clone the client to avoid mutating CheckRedirect on the shared instance.
	// Each goroutine gets its own clone with its own closure — no races.
	cc := *c.HTTP
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= c.MaxRedirect {
			return fmt.Errorf("stopped after %d redirects", c.MaxRedirect)
		}
		// req.Response is the redirect response that produced this request,
		// so its status code belongs to the previous hop. This is the only
		// point where per-hop statuses are observable — resp.StatusCode is
		// not available until after cc.Do() returns, and CheckRedirect runs
		// while Do() is still in flight.
		if req.Response != nil {
			lastStatus = req.Response.StatusCode
		}
		chain = append(chain, Hop{
			URL:    req.URL.String(),
			Status: lastStatus,
		})
		return nil
	}

	resp, err := cc.Do(req)
	if err != nil {
		return Result{Chain: chain, Error: err}
	}
	// Body close errors after classification are connection noise.
	defer func() { _ = resp.Body.Close() }()
	// Drain the body so the connection returns to the keep-alive pool.
	// Errors here are connection-teardown noise, not probe failures — the
	// status/chain we need is already captured — so discard deliberately.
	_, _ = io.Copy(io.Discard, resp.Body)

	return Result{
		Chain:       chain,
		Final:       resp.Request.URL.String(),
		FinalStatus: resp.StatusCode,
	}
}

// ContainsStatus reports whether any hop in the chain has the given status code.
func (r *Result) ContainsStatus(code int) bool {
	for _, h := range r.Chain {
		if h.Status == code {
			return true
		}
	}
	return false
}

// AnyRedirectStatus returns the first 3xx status in the chain, or 0.
func (r *Result) AnyRedirectStatus() int {
	for _, h := range r.Chain {
		if h.Status >= 300 && h.Status < 400 {
			return h.Status
		}
	}
	return 0
}
