package output

import (
	"strings"
	"testing"

	"github.com/yourpwnguy/redirx/internal/detector"
	"github.com/yourpwnguy/redirx/internal/httpclient"
)

// TestConsoleWriter_Vuln VULN lines render verdict, final URL, and increment mut+vuln counters.
func TestConsoleWriter_Vuln(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, VulnOnly: false}

	r := Result{
		OriginalURL: "https://example.com/login?next=home",
		Param:       "next",
		Payload:     "//evil.com",
		MutatedURL:  "https://example.com/login?next=%2F%2Fevil.com",
		FinalURL:    "https://evil.com/",
		Status:      302,
		Verdict:     detector.Vuln,
		Chain: []httpclient.Hop{
			{URL: "https://evil.com/", Status: 302},
		},
	}

	w.Write(r)

	out := buf.String()
	if !strings.Contains(out, "VULN") {
		t.Error("expected VULN in output")
	}
	if !strings.Contains(out, "https://evil.com/") {
		t.Error("expected final URL in output")
	}

	mut, safe, vuln, errs := w.Counts()
	if mut != 1 {
		t.Errorf("expected 1 mutation, got %d", mut)
	}
	if vuln != 1 {
		t.Errorf("expected 1 vuln, got %d", vuln)
	}
	if safe != 0 {
		t.Errorf("expected 0 safe, got %d", safe)
	}
	if errs != 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
}

// TestConsoleWriter_VulnChain Multi-hop VULN results include the labeled chain evidence row.
func TestConsoleWriter_VulnChain(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf}

	r := Result{
		OriginalURL: "https://example.com/?r=x",
		Param:       "r",
		Payload:     "//evil.com",
		MutatedURL:  "https://example.com/?r=%2F%2Fevil.com",
		FinalURL:    "https://evil.com/",
		Status:      302,
		Verdict:     detector.Vuln,
		Chain: []httpclient.Hop{
			{URL: "https://tracker.example/", Status: 302},
			{URL: "https://evil.com/", Status: 301},
		},
	}

	w.Write(r)

	out := buf.String()
	if !strings.Contains(out, "chain:") {
		t.Error("expected chain info in vuln output")
	}
}

// TestConsoleWriter_Safe SAFE lines render with the mutated request URL.
func TestConsoleWriter_Safe(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, VulnOnly: false}

	r := Result{
		OriginalURL: "https://example.com/page?x=1",
		Param:       "x",
		Payload:     "//evil.com",
		MutatedURL:  "https://example.com/page?x=%2F%2Fevil.com",
		FinalURL:    "https://example.com/page",
		Status:      200,
		Verdict:     detector.Safe,
	}

	w.Write(r)

	out := buf.String()
	if !strings.Contains(out, "SAFE") {
		t.Error("expected SAFE in output")
	}
}

// TestConsoleWriter_VulnOnly --vuln-only suppresses SAFE lines but keeps counting them.
func TestConsoleWriter_VulnOnly(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, VulnOnly: true}

	safe := Result{
		Verdict:    detector.Safe,
		MutatedURL: "https://example.com/page?x=1",
	}
	vuln := Result{
		Verdict:     detector.Vuln,
		MutatedURL:  "https://example.com/page?x=evil",
		OriginalURL: "https://example.com/page?x=1",
		Param:       "x",
		Payload:     "evil",
		FinalURL:    "https://evil.com",
		Status:      302,
	}

	w.Write(safe)
	w.Write(vuln)

	out := buf.String()
	if strings.Contains(out, "SAFE") {
		t.Error("SAFE should not appear in vuln-only mode")
	}
	if !strings.Contains(out, "VULN") {
		t.Error("VULN should appear in vuln-only mode")
	}
}

// TestConsoleWriter_Error ERR lines surface the mutated URL plus the failure reason.
func TestConsoleWriter_Error(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf}

	r := Result{
		MutatedURL:   "https://badhost.invalid/x",
		Verdict:      detector.Error,
		ErrorMessage: "connection refused",
	}

	w.Write(r)

	out := buf.String()
	if !strings.Contains(out, "ERR") {
		t.Error("expected ERR in output")
	}
	if !strings.Contains(out, "connection refused") {
		t.Error("expected error message in output")
	}
}
