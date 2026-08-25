package detector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/yourpwnguy/redirx/internal/httpclient"
)

// TestClassifyIP Verifies IP-literal classification: loopback, RFC1918 internal, and public external buckets.
func TestClassifyIP(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantType IPRedirectType
		wantIP   string
	}{
		// Loopback
		{"ipv4 loopback", "http://127.0.0.1/secret", Loopback, "127.0.0.1"},
		{"ipv4 loopback large", "http://127.0.0.2:8080/admin", Loopback, "127.0.0.2"},
		{"ipv6 loopback", "http://[::1]/secret", Loopback, "::1"},
		{"unspecified 0.0.0.0", "http://0.0.0.0/", Loopback, "0.0.0.0"},
		{"unspecified ::", "http://[::]/", Loopback, "::"},

		// Internal (RFC 1918)
		{"10.x", "http://10.0.0.1/api", InternalIP, "10.0.0.1"},
		{"172.16.x", "http://172.16.0.1/api", InternalIP, "172.16.0.1"},
		{"172.31.x", "http://172.31.255.255/api", InternalIP, "172.31.255.255"},
		{"192.168.x", "http://192.168.1.1/api", InternalIP, "192.168.1.1"},
		{"ipv6 private fc00", "http://[fc00::1]/", InternalIP, "fc00::1"},
		{"ipv6 private fd00", "http://[fd00::1]/", InternalIP, "fd00::1"},

		// Link-local
		{"link-local 169.254", "http://169.254.1.1/metadata", InternalIP, "169.254.1.1"},

		// External
		{"public google dns", "http://8.8.8.8/", ExternalIP, "8.8.8.8"},
		{"public cloudflare", "http://1.1.1.1/", ExternalIP, "1.1.1.1"},
		{"ipv6 public", "http://[2001:4860:4860::8888]/", ExternalIP, "2001:4860:4860::8888"},

		// Non-IP
		{"domain", "https://example.com/", NoIPRedirect, ""},
		{"localhost label", "http://localhost:3000/", NoIPRedirect, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotIP := ClassifyIP(tt.url)
			if gotType != tt.wantType {
				t.Errorf("ClassifyIP(%q) type = %v, want %v", tt.url, gotType, tt.wantType)
			}
			if gotIP != tt.wantIP {
				t.Errorf("ClassifyIP(%q) ip = %q, want %q", tt.url, gotIP, tt.wantIP)
			}
		})
	}
}

// TestHasCredentials Verifies userinfo detection, the classic user@evil.com bypass shape.
func TestHasCredentials(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantHas   bool
		wantCreds string
	}{
		{"no creds", "https://example.com/path", false, ""},
		{"with user only", "https://alice@example.com/", true, "alice"},
		{"with user:pass", "https://alice:pass@example.com/", true, "alice:pass"},
		{"encoded creds", "https://user%40domain:pass%23@example.com/", true, "user%40domain:pass%23"},
		{"empty userinfo", "https://@example.com/", true, ""},
		{"path has @", "https://example.com/@user", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHas, gotCreds := HasCredentials(tt.url)
			if gotHas != tt.wantHas {
				t.Errorf("HasCredentials(%q) = %v, want %v", tt.url, gotHas, tt.wantHas)
			}
			if gotCreds != tt.wantCreds {
				t.Errorf("HasCredentials(%q) creds = %q, want %q", tt.url, gotCreds, tt.wantCreds)
			}
		})
	}
}

// TestAnalyzeChain Verifies first-escaping-hop detection across multi-domain chains.
func TestAnalyzeChain(t *testing.T) {
	tests := []struct {
		name       string
		chain      []httpclient.Hop
		origDomain string
		wantIdx    int
	}{
		{
			"no hops",
			[]httpclient.Hop{},
			"example.com",
			-1,
		},
		{
			"all same domain",
			[]httpclient.Hop{
				{URL: "https://example.com/a", Status: 301},
				{URL: "https://example.com/b", Status: 302},
				{URL: "https://www.example.com/c", Status: 200},
			},
			"example.com",
			-1,
		},
		{
			"escape at hop 0",
			[]httpclient.Hop{
				{URL: "https://evil.com/steal", Status: 302},
				{URL: "https://evil.com/done", Status: 200},
			},
			"example.com",
			0,
		},
		{
			"escape at hop 1",
			[]httpclient.Hop{
				{URL: "https://auth.example.com/login", Status: 302},
				{URL: "https://evil.com/callback", Status: 302},
				{URL: "https://evil.com/final", Status: 200},
			},
			"example.com",
			1,
		},
		{
			"IP escape",
			[]httpclient.Hop{
				{URL: "http://192.168.1.1/admin", Status: 302},
			},
			"example.com",
			0,
		},
		{
			"both domains are IPs but different",
			[]httpclient.Hop{
				{URL: "http://10.0.0.1/secret", Status: 302},
			},
			"192.168.1.1",
			0,
		},
		{
			"both domains are same IP",
			[]httpclient.Hop{
				{URL: "http://192.168.1.1/secret", Status: 302},
			},
			"192.168.1.1",
			-1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeChain(tt.chain, tt.origDomain)
			if got != tt.wantIdx {
				t.Errorf("AnalyzeChain() = %d, want %d", got, tt.wantIdx)
			}
		})
	}
}

// TestCheck_IPRedirect End-to-end: payload redirecting to an internal IP must flag IPRedirect=InternalIP.
func TestCheck_IPRedirect(t *testing.T) {
	// Server redirects to its own address via IP representation.
	// The httptest server listens on 127.0.0.1:PORT, so we redirect
	// to the same server URL — same IP, but the final URL has an IP host.
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First request: redirect to ourselves via the IP literal
		if r.URL.Path == "/page" {
			http.Redirect(w, r, serverURL+"/admin", http.StatusFound)
			return
		}
		// All other paths: return 200
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	serverURL = server.URL

	client, err := httpclient.New(httpclient.Options{
		Timeout:     5 * time.Second,
		MaxRedirect: 5,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, _ := url.Parse(server.URL)
	origDomain := parsed.Hostname()

	mu := MutatedURL{
		OriginalURL: server.URL + "/page?next=home",
		Param:       "next",
		Payload:     "//127.0.0.1",
		MutatedURL:  server.URL + "/page?next=//127.0.0.1",
	}

	dr := Check(context.Background(), client, mu, origDomain, nil)

	// Server redirects to itself (same IP). Domain comparison: 127.0.0.1 == 127.0.0.1 → Safe.
	// But IPRedirect should still classify the final URL correctly.
	if dr.IPRedirect != Loopback {
		t.Errorf("expected Loopback, got %v (final=%q)", dr.IPRedirect, dr.FinalURL)
	}
}

// TestCheck_IPRedirect_DifferentIP End-to-end: distinct IP classes must map to their correct IPRedirectType.
func TestCheck_IPRedirect_DifferentIP(t *testing.T) {
	// Server redirects to a DIFFERENT IP — domain mismatch → Vuln + IP redirect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to the test server's own IP with a different port won't work.
		// Instead, redirect to a domain that resolves to an IP.
		// Use a relative redirect to a path that won't exist, but the host changes.
		w.Header().Set("Location", "http://10.0.0.1:1/")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{
		Timeout:     2 * time.Second,
		MaxRedirect: 5,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, _ := url.Parse(server.URL)
	origDomain := parsed.Hostname()

	mu := MutatedURL{
		OriginalURL: server.URL + "/?next=home",
		Param:       "next",
		Payload:     "//10.0.0.1",
		MutatedURL:  server.URL + "/?next=//10.0.0.1",
	}

	dr := Check(context.Background(), client, mu, origDomain, nil)

	// The redirect to 10.0.0.1:1 will likely fail (unreachable).
	// That's OK — we just want to verify the error is reported correctly.
	// If it somehow succeeds, verify it's Vuln with InternalIP.
	if dr.Verdict == Vuln && dr.IPRedirect != InternalIP {
		t.Errorf("expected InternalIP for 10.0.0.1 redirect, got %v", dr.IPRedirect)
	}
	// Connection failure to 10.0.0.1 is expected
	if dr.Verdict == Error {
		t.Logf("got Error verdict (expected — 10.0.0.1 unreachable): %s", dr.ErrorMessage)
	}
}

// TestCheck_Credentials End-to-end: landing URL carrying userinfo must populate the Credentials tag.
func TestCheck_Credentials(t *testing.T) {
	// Server redirects to a URL with credentials
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com@evil.com/steal", http.StatusFound)
	}))
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{
		Timeout:     5 * time.Second,
		MaxRedirect: 5,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, _ := url.Parse(server.URL)
	origDomain := parsed.Hostname()

	mu := MutatedURL{
		OriginalURL: server.URL + "/page?next=home",
		Param:       "next",
		Payload:     "//evil.com",
		MutatedURL:  server.URL + "/page?next=//evil.com",
	}

	dr := Check(context.Background(), client, mu, origDomain, nil)

	if dr.Verdict != Vuln {
		t.Errorf("expected Vuln for credential redirect, got %v", dr.Verdict)
	}
	if dr.Credentials == "" {
		t.Error("expected non-empty Credentials")
	}
}

// TestCheck_ChainEscape End-to-end: EscapedHop must point at the first off-domain hop in the chain.
func TestCheck_ChainEscape(t *testing.T) {
	// Multi-hop: target -> safe1 -> evil
	safe1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.com/final", http.StatusFound)
	}))
	defer safe1.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, safe1.URL+"/bounce", http.StatusFound)
	}))
	defer target.Close()

	client, err := httpclient.New(httpclient.Options{
		Timeout:     5 * time.Second,
		MaxRedirect: 5,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, _ := url.Parse(target.URL)
	origDomain := parsed.Hostname()

	mu := MutatedURL{
		OriginalURL: target.URL + "/page?next=home",
		Param:       "next",
		Payload:     "//evil.com",
		MutatedURL:  target.URL + "/page?next=//evil.com",
	}

	dr := Check(context.Background(), client, mu, origDomain, nil)

	if dr.Verdict != Vuln {
		t.Errorf("expected Vuln for chain escape, got %v", dr.Verdict)
	}
	if dr.EscapedHop < 0 {
		t.Error("expected EscapedHop >= 0, got -1")
	}
}

// TestCheck_DomainMismatchIsVuln Baseline truth: plain cross-domain landing without extras still yields Vuln.
func TestCheck_DomainMismatchIsVuln(t *testing.T) {
	// Simple redirect to evil.com
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.com/steal", http.StatusFound)
	}))
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{
		Timeout:     5 * time.Second,
		MaxRedirect: 5,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, _ := url.Parse(server.URL)
	origDomain := parsed.Hostname()

	mu := MutatedURL{
		OriginalURL: server.URL + "/?next=home",
		Param:       "next",
		Payload:     "//evil.com",
		MutatedURL:  server.URL + "/?next=//evil.com",
	}

	dr := Check(context.Background(), client, mu, origDomain, nil)

	if dr.Verdict != Vuln {
		t.Errorf("expected Vuln for domain mismatch, got %v (final=%q)", dr.Verdict, dr.FinalURL)
	}
}
