// Package scanner orchestrates the scan lifecycle.
//
// It wires together URL collection, payload loading, HTTP client creation,
// baseline requests, the worker pool, and result output. This is the only
// package that knows about all the others — it's the composition root.
//
// The worker pool pattern here is intentional: we use a fixed number of
// goroutines consuming from a buffered jobs channel. This bounds memory
// usage, TCP connections, and file descriptors. With 100k URLs at -c 5,
// RSS stays under 20MB instead of blowing up with unbounded fan-out.
package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yourpwnguy/redirx/internal/config"
	"github.com/yourpwnguy/redirx/internal/detector"
	"github.com/yourpwnguy/redirx/internal/httpclient"
	"github.com/yourpwnguy/redirx/internal/output"
	"github.com/yourpwnguy/redirx/internal/payload"
)

// Run is the top-level scan entry point. It blocks until the scan
// completes or the context is cancelled (e.g. Ctrl-C).
//
// The flow:
//  1. Collect URLs from flags, files, and stdin
//  2. Load payloads (built-in or custom)
//  3. Create the HTTP client
//  4. Optionally run baseline control requests
//  5. Spin up a fixed worker pool
//  6. Feed mutation jobs into the pool
//  7. Drain results and write them
//  8. Print the summary
//
// Why a drain loop instead of writing results inline? Because workers
// produce results on a channel, and we need to close that channel after
// all workers finish. The drain loop naturally terminates when the
// channel closes — no extra coordination needed.
func Run(ctx context.Context, cfg config.Config, writer output.Writer) error {
	start := time.Now()

	// --- Collect URLs -----------------------------------------------------------
	urls, err := collectURLs(cfg)
	if err != nil {
		return fmt.Errorf("collect URLs: %w", err)
	}
	if len(urls) == 0 {
		return fmt.Errorf("no URLs provided (use -u, -l, or pipe via stdin)")
	}

	// --- Collect payloads -------------------------------------------------------
	payloads := cfg.Payloads
	if len(payloads) == 0 {
		payloads = payload.Default
	}

	// --- HTTP client ------------------------------------------------------------
	client, err := httpclient.New(httpclient.Options{
		Timeout:     cfg.Timeout,
		MaxRedirect: cfg.MaxRedirect,
		Method:      cfg.Method,
		Proxy:       cfg.Proxy,
		Headers:     cfg.Headers,
		UserAgent:   cfg.UserAgent,
	})
	if err != nil {
		return fmt.Errorf("create HTTP client: %w", err)
	}

	// --- Baseline requests (optional) ------------------------------------------
	// When --baseline is enabled, we send one unmodified request per URL
	// and record where it lands. During the actual scan, if a mutation
	// lands on the same domain as the baseline, it's not a finding.
	baselineDomains := make(map[string]bool)
	var baselineMu sync.Mutex

	if cfg.Baseline {
		fmt.Fprintln(os.Stderr, "running baseline control requests...")
		for _, u := range urls {
			br := detector.RunBaseline(ctx, client, u)
			if br.Error == nil && br.FinalDomain != "" {
				baselineMu.Lock()
				baselineDomains[br.FinalDomain] = true
				baselineMu.Unlock()
			}
		}
	}

	// --- Parse original domains ------------------------------------------------
	// We need the eTLD+1 of each original URL to compare against landing
	// domains later. Pre-computing avoids repeated publicsuffix lookups.
	origDomains := make(map[string]string, len(urls))
	for _, u := range urls {
		d, err := detector.GetRegistrableDomain(u)
		if err != nil {
			d = u
		}
		origDomains[u] = d
	}

	// --- Worker pool -----------------------------------------------------------
	// Fixed pool of N goroutines consuming from a buffered jobs channel.
	// This bounds memory, TCP connections, and file descriptors.
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	jobs := make(chan detector.MutatedURL, 256)
	results := make(chan output.Result, 256)

	// In-flight mutations — surfaced in the live counter as "active N".
	// Optional capability: only the console writer knows what to do with it.
	var inflight int64
	if cw, ok := writer.(*output.ConsoleWriter); ok {
		cw.SetInFlight(&inflight)
	}

	// Start workers — they consume jobs until the channel is closed.
	var workerWg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for mu := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				origDomain := origDomains[mu.OriginalURL]
				if origDomain == "" {
					origDomain = mu.OriginalURL
				}

				atomic.AddInt64(&inflight, 1)
				dr := detector.Check(ctx, client, mu, origDomain, baselineDomains)
				atomic.AddInt64(&inflight, -1)
				results <- output.ResultFromDetection(dr)
			}
		}()
	}

	// Feed jobs in a background goroutine. This keeps the main goroutine
	// free to drain results — avoids deadlock on bounded channels.
	go func() {
		defer close(jobs)
		for _, u := range urls {
			muts, err := detector.Mutate(u, payloads)
			if err != nil {
				results <- output.Result{
					OriginalURL:  u,
					Verdict:      detector.Error,
					ErrorMessage: err.Error(),
				}
				continue
			}
			for _, m := range muts {
				select {
				case <-ctx.Done():
					return
				case jobs <- m:
				}
			}
		}
	}()

	// Close results channel after all workers finish.
	// This signals the drain loop below to stop.
	go func() {
		workerWg.Wait()
		close(results)
	}()

	// Drain results and write them.
	// Start the live counter before draining — it shows real-time progress.
	totalMuts := len(urls) * len(payloads)
	if totalMuts > 0 {
		writer.StartLiveCounter(totalMuts)
	}

	for r := range results {
		writer.Write(r)
	}

	// Stop the live counter before printing the summary — clears the
	// progress line so the summary doesn't overlap.
	writer.StopLiveCounter()

	// --- Summary ---------------------------------------------------------------
	mut, safe, vuln, errs := writer.Counts()
	writer.WriteSummary(output.Summary{
		TotalURLs:      len(urls),
		TotalMutations: mut,
		Safe:           safe,
		Vulnerable:     vuln,
		Errors:         errs,
		Duration:       time.Since(start),
	})

	return nil
}
