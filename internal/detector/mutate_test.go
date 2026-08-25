package detector

import (
	"net/url"
	"testing"
)

// TestMutate_Basic One param x N payloads must produce exactly N ordered mutations.
func TestMutate_Basic(t *testing.T) {
	rawURL := "https://example.com/login?next=dashboard&user=alice"
	payloads := []string{"//google.com", "https://evil.com"}

	muts, err := Mutate(rawURL, payloads)
	if err != nil {
		t.Fatalf("Mutate() error: %v", err)
	}

	// 2 params x 2 payloads = 4 mutations
	if len(muts) != 4 {
		t.Fatalf("expected 4 mutations, got %d", len(muts))
	}

	// Verify first mutation replaces 'next' with first payload
	if muts[0].Param != "next" {
		t.Errorf("expected param 'next', got %q", muts[0].Param)
	}
	if muts[0].Payload != "//google.com" {
		t.Errorf("expected payload '//google.com', got %q", muts[0].Payload)
	}

	// Verify mutated URL contains the payload
	parsed, err := url.Parse(muts[0].MutatedURL)
	if err != nil {
		t.Fatalf("mutated URL is not valid: %v", err)
	}
	q := parsed.Query()
	if q.Get("next") != "//google.com" {
		t.Errorf("expected next=//google.com, got next=%s", q.Get("next"))
	}
	// Original param should be preserved
	if q.Get("user") != "alice" {
		t.Errorf("expected user=alice, got user=%s", q.Get("user"))
	}
}

// TestMutate_NoParams URLs without query strings yield no mutations and no error.
func TestMutate_NoParams(t *testing.T) {
	rawURL := "https://example.com/"
	muts, err := Mutate(rawURL, []string{"//x"})
	if err != nil {
		t.Fatalf("Mutate() error: %v", err)
	}
	if len(muts) != 0 {
		t.Errorf("expected 0 mutations for no params, got %d", len(muts))
	}
}

// TestMutate_InvalidURL Unparseable input surfaces as a wrapped error, not a panic.
func TestMutate_InvalidURL(t *testing.T) {
	_, err := Mutate("://bad", []string{"//x"})
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// TestMutate_DuplicateParams Repeated ?k=v&k=v2 mutates the param once, not once per instance.
func TestMutate_DuplicateParams(t *testing.T) {
	rawURL := "https://example.com/?q=1&q=2&x=3"
	payloads := []string{"PAYLOAD"}

	muts, err := Mutate(rawURL, payloads)
	if err != nil {
		t.Fatalf("Mutate() error: %v", err)
	}

	// 2 unique params (q, x) x 1 payload = 2 mutations
	if len(muts) != 2 {
		t.Fatalf("expected 2 mutations, got %d", len(muts))
	}

	// Verify q=payload and x=payload are both present
	found := make(map[string]bool)
	for _, m := range muts {
		found[m.Param] = true
		parsed, _ := url.Parse(m.MutatedURL)
		q := parsed.Query()
		if q.Get(m.Param) != "PAYLOAD" {
			t.Errorf("param %s not replaced with PAYLOAD", m.Param)
		}
	}
	if !found["q"] || !found["x"] {
		t.Error("expected mutations for both q and x")
	}
}

// TestMutate_PreservesOtherParams Non-target params survive mutation with values intact and ordered.
func TestMutate_PreservesOtherParams(t *testing.T) {
	rawURL := "https://example.com/?a=1&b=2&c=3"
	payloads := []string{"EVIL"}

	muts, err := Mutate(rawURL, payloads)
	if err != nil {
		t.Fatalf("Mutate() error: %v", err)
	}

	// Mutate b
	var bMut *MutatedURL
	for _, m := range muts {
		if m.Param == "b" {
			bMut = &m
			break
		}
	}
	if bMut == nil {
		t.Fatal("no mutation for param b")
	}

	parsed, _ := url.Parse(bMut.MutatedURL)
	q := parsed.Query()
	if q.Get("a") != "1" {
		t.Errorf("param a lost, got %q", q.Get("a"))
	}
	if q.Get("b") != "EVIL" {
		t.Errorf("param b not mutated, got %q", q.Get("b"))
	}
	if q.Get("c") != "3" {
		t.Errorf("param c lost, got %q", q.Get("c"))
	}
}
