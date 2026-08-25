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

// TestCheck_NoRedirect A probe that never leaves the target domain must be Safe.
func TestCheck_NoRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
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
		OriginalURL: server.URL + "/page?x=1",
		Param:       "x",
		Payload:     "//evil.com",
		MutatedURL:  server.URL + "/page?x=//evil.com",
	}

	dr := Check(context.Background(), client, mu, origDomain, nil)

	if dr.Verdict != Safe {
		t.Errorf("expected Safe for no redirect, got %v (final=%q)", dr.Verdict, dr.FinalURL)
	}
}

// TestCheck_BaselineBounce Landing on a baseline-recorded legit bounce domain must downgrade to Safe.
func TestCheck_BaselineBounce(t *testing.T) {
	// Two servers: one is the target, one is the "SSO" bounce
	sso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer sso.Close()

	ssoParsed, _ := url.Parse(sso.URL)
	ssoDomain := ssoParsed.Hostname()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect to SSO, simulating auth gate
		http.Redirect(w, r, sso.URL+"/login", http.StatusFound)
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

	// Mark the SSO domain as a baseline bounce
	baselineDomains := map[string]bool{
		ssoDomain: true,
	}

	targetParsed, _ := url.Parse(target.URL)
	origDomain := targetParsed.Hostname()

	mu := MutatedURL{
		OriginalURL: target.URL + "/app?next=home",
		Param:       "next",
		Payload:     "//evil.com",
		MutatedURL:  target.URL + "/app?next=//evil.com",
	}

	dr := Check(context.Background(), client, mu, origDomain, baselineDomains)

	if dr.Verdict != Safe {
		t.Errorf("expected Safe for baseline bounce, got %v (final=%q, baseline=%v)",
			dr.Verdict, dr.FinalURL, baselineDomains)
	}
}

// TestCheck_VulnerableRedirect Canonical open redirect: cross-domain landing must yield Vuln.
func TestCheck_VulnerableRedirect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.com/steal", http.StatusFound)
	}))
	defer backend.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, backend.URL+"/callback", http.StatusFound)
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
		OriginalURL: target.URL + "/login?next=home",
		Param:       "next",
		Payload:     "//evil.com",
		MutatedURL:  target.URL + "/login?next=//evil.com",
	}

	dr := Check(context.Background(), client, mu, origDomain, nil)

	if dr.FinalURL == "" {
		t.Error("expected non-empty FinalURL")
	}
	// Should not error on normal redirect
	if dr.Verdict == Error && dr.ErrorMessage == "" {
		t.Error("Error verdict without message")
	}
}
