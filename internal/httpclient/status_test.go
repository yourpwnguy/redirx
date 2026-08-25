package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFollow_HopStatuses pins the per-hop status capture: every hop must
// record the status code of the response that redirected to it, and the
// final response's own status lands in FinalStatus. Regression test —
// statuses used to be assigned after cc.Do() returned, so every hop
// recorded 0.
func TestFollow_HopStatuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/mid", http.StatusFound) // 302
		case "/mid":
			http.Redirect(w, r, "/end", http.StatusMovedPermanently) // 301
		case "/end":
			w.WriteHeader(http.StatusOK) // 200
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

	if len(res.Chain) != 2 {
		t.Fatalf("expected 2 hops in chain, got %d", len(res.Chain))
	}

	// Hop i's status is the redirect status that LED TO hop i's URL.
	if res.Chain[0].Status != 302 {
		t.Errorf("hop[0] status = %d, want 302 (the /start -> /mid redirect)", res.Chain[0].Status)
	}
	if res.Chain[1].Status != 301 {
		t.Errorf("hop[1] status = %d, want 301 (the /mid -> /end redirect)", res.Chain[1].Status)
	}
	if res.FinalStatus != 200 {
		t.Errorf("FinalStatus = %d, want 200", res.FinalStatus)
	}
	if res.Chain[0].URL == "" || res.Chain[1].URL == "" {
		t.Error("expected non-empty hop URLs")
	}
}

// TestFollow_NoRedirectFinalStatus verifies FinalStatus is populated even
// with zero hops (direct 200 response).
func TestFollow_NoRedirectFinalStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()

	c, err := New(Options{Timeout: 5 * time.Second, Method: http.MethodHead})
	if err != nil {
		t.Fatal(err)
	}

	res := c.Follow(context.Background(), server.URL)
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if len(res.Chain) != 0 {
		t.Errorf("expected empty chain, got %d hops", len(res.Chain))
	}
	if res.FinalStatus != http.StatusTeapot {
		t.Errorf("FinalStatus = %d, want 418", res.FinalStatus)
	}
}
