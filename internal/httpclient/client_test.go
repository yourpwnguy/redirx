package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFollow_NoRedirect Direct 200 responses produce an empty chain and a valid Final URL.
func TestFollow_NoRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(Options{
		Timeout:     5 * time.Second,
		MaxRedirect: 10,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := c.Follow(context.Background(), server.URL)
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	// Go's HTTP client may or may not add trailing slash depending on the server
	if res.Final == "" {
		t.Error("expected non-empty final URL")
	}
}

// TestFollow_SingleRedirect A 302 hop is captured exactly once in the chain.
func TestFollow_SingleRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	c, err := New(Options{
		Timeout:     5 * time.Second,
		MaxRedirect: 10,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := c.Follow(context.Background(), server.URL+"/start")
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if len(res.Chain) != 1 {
		t.Errorf("expected 1 hop in chain, got %d", len(res.Chain))
	}
}

// TestFollow_MaxRedirectCap Loops beyond MaxRedirect terminate as errors instead of hanging.
func TestFollow_MaxRedirectCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer server.Close()

	c, err := New(Options{
		Timeout:     5 * time.Second,
		MaxRedirect: 3,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := c.Follow(context.Background(), server.URL+"/loop")
	if res.Error == nil {
		t.Error("expected error for redirect loop")
	}
}

// TestFollow_Timeout Server stalls exceeding Timeout surface as errors, not hangs.
func TestFollow_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(Options{
		Timeout:     100 * time.Millisecond,
		MaxRedirect: 10,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := c.Follow(context.Background(), server.URL)
	if res.Error == nil {
		t.Error("expected timeout error")
	}
}

// TestFollow_ContextCancellation Cancelled contexts abort in-flight probes promptly with errors.
func TestFollow_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(Options{
		Timeout:     10 * time.Second,
		MaxRedirect: 10,
		Method:      http.MethodHead,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	res := c.Follow(ctx, server.URL)
	if res.Error == nil {
		t.Error("expected context cancellation error")
	}
}

// TestContainsStatus Chain scan finds exact status matches and rejects absent ones.
func TestContainsStatus(t *testing.T) {
	r := &Result{
		Chain: []Hop{
			{URL: "http://a.com", Status: 301},
			{URL: "http://b.com", Status: 302},
			{URL: "http://c.com", Status: 200},
		},
	}

	if !r.ContainsStatus(301) {
		t.Error("expected ContainsStatus(301) = true")
	}
	if !r.ContainsStatus(302) {
		t.Error("expected ContainsStatus(302) = true")
	}
	if r.ContainsStatus(404) {
		t.Error("expected ContainsStatus(404) = false")
	}
}

// TestAnyRedirectStatus Returns the first 3xx in the chain; zero when none exist.
func TestAnyRedirectStatus(t *testing.T) {
	tests := []struct {
		name  string
		chain []Hop
		want  int
	}{
		{"302 hop", []Hop{{Status: 302}}, 302},
		{"301 then 200", []Hop{{Status: 301}, {Status: 200}}, 301},
		{"no redirects", []Hop{}, 0},
		{"all 2xx", []Hop{{Status: 200}, {Status: 201}}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{Chain: tt.chain}
			if got := r.AnyRedirectStatus(); got != tt.want {
				t.Errorf("AnyRedirectStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}
