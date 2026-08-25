package output

import (
	"strings"
	"testing"

	"github.com/yourpwnguy/redirx/internal/detector"
)

// vulnResult builds a representative vulnerable result for emission tests.
func vulnResult() Result {
	return Result{
		OriginalURL: "https://example.com/login?next=home",
		Param:       "next",
		Payload:     "//evil.com",
		MutatedURL:  "https://example.com/login?next=%2F%2Fevil.com",
		FinalURL:    "https://evil.com/",
		Status:      302,
		Verdict:     detector.Vuln,
	}
}

// TestConsoleWriter_PlainModeNoEscapes verifies that without a live counter
// (non-TTY / quiet), result lines are plain text terminated by exactly one
// newline — no carriage returns, no ANSI cursor control codes. This is what
// lands in files and pipes when output is redirected.
func TestConsoleWriter_PlainModeNoEscapes(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, tty: false}

	w.Write(vulnResult())

	out := buf.String()
	if strings.Contains(out, "\r") {
		t.Error("plain mode must not emit carriage returns")
	}
	for _, esc := range []string{"\033[1A", "\033[2K", "\033[K"} {
		if strings.Contains(out, esc) {
			t.Errorf("plain mode must not emit cursor control sequence %q", esc)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("result line must be newline-terminated")
	}
}

// TestConsoleWriter_LiveCounterPreservesResults is the core regression test
// for the broken progress display: every written result line must still be
// present in the final byte stream after the progress row has been stopped.
// The old \033[1A/-clear scheme erased the most recent result line on every
// redraw; the wipe-and-print discipline must not.
func TestConsoleWriter_LiveCounterPreservesResults(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, tty: true, VulnOnly: true}

	w.StartLiveCounter(10)
	defer w.StopLiveCounter()

	for i := 0; i < 5; i++ {
		w.Write(vulnResult())
	}
	// Suppressed safe results change counters but print nothing — the
	// progress row must still refresh without corrupting anything.
	safe := Result{MutatedURL: "https://example.com/?x=1", Verdict: detector.Safe}
	w.Write(safe)
	w.Write(safe)
	w.Write(vulnResult())

	out := buf.String()
	if got := strings.Count(out, "VULN"); got != 6 {
		t.Errorf("expected 6 VULN lines to survive, got %d", got)
	}
	if strings.Contains(out, "SAFE") {
		t.Error("suppressed SAFE lines must not appear in vuln-only mode")
	}
	if strings.Count(out, "mut") < 6 {
		t.Error("expected progress rows in the stream")
	}
}

// TestConsoleWriter_LiveCounterWipeAndRedraw checks the terminal discipline
// end-to-end: the FIRST visible result grows downward from the counter row
// (\r\033[2K) to preserve the banner separator; later results consume the
// moving gap row (\r\033[1A); every landing row is cleared before becoming
// the fresh gap.
func TestConsoleWriter_LiveCounterWipeAndRedraw(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, tty: true}

	w.StartLiveCounter(2)
	w.Write(vulnResult())
	w.Write(vulnResult())
	w.StopLiveCounter()

	out := buf.String()

	firstK := strings.Index(out, "\r\033[2K")
	firstA := strings.Index(out, "\r\033[1A")
	if firstK < 0 {
		t.Fatal("first result must replace the counter in place via \\r\\033[2K")
	}
	if strings.Contains(out[:firstK], "\n") {
		t.Error("initial state must be a single parked counter row before the first result")
	}
	if firstA >= 0 && firstA < firstK {
		t.Error("gap-jump must never precede the first in-place result")
	}
	if n := strings.Count(out, "\r\033[2K"); n != 1 {
		t.Errorf("in-place growth must happen exactly once (first result only), found %d", n)
	}
	// Later results must clear their landing row before it becomes the gap.
	body := out[firstK:]
	if !strings.Contains(body, "\n\033[2K\n") {
		t.Error("expected landing-row clear + fresh gap after each result block")
	}
}

// TestConsoleWriter_StopLiveCounterReclaimsRows verifies StopLiveCounter
// reclaims both the gap row and the counter row, leaving the cursor one
// blank line below the last result so WriteSummary can print directly.
func TestConsoleWriter_StopLiveCounterReclaimsRows(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, tty: true}

	w.StartLiveCounter(1)
	w.StopLiveCounter()

	out := buf.String()
	want := "\r\033[1A\033[2K\n\033[2K"
	if !strings.HasSuffix(out, want) {
		t.Errorf("stop must reclaim gap+counter rows with %q, got suffix %q", want, tail(out, 20))
	}
	// Stopping twice must be a no-op, not extra output or a panic.
	w.StopLiveCounter()
	if n := strings.Count(buf.String(), want); n != 1 {
		t.Errorf("second StopLiveCounter must not emit anything, found %d stop sequences", n)
	}
}

// TestConsoleWriter_LiveCounterTightResults pins the vertical rhythm of
// live mode: result blocks must be packed with NO blank rows between them,
// while exactly one reserved gap row separates the last result from the
// counter. Byte-exact contract between two consecutive results:
//
//	"<block>\n" + "\n" (fresh gap) + "\r\033[1A" (jump onto gap)
func TestConsoleWriter_LiveCounterTightResults(t *testing.T) {
	var buf strings.Builder
	w := &ConsoleWriter{W: &buf, tty: true, VulnOnly: true}

	w.StartLiveCounter(3)
	for i := 0; i < 3; i++ {
		w.Write(vulnResult())
	}
	// Pre-stop: the last block must be followed by cleared-row + fresh gap,
	// then the counter. The \033[2K is what erases the stale counter row.
	withGap := buf.String()
	last := strings.LastIndex(withGap, "%2F%2Fevil.com") + len("%2F%2Fevil.com")
	tailBytes := withGap[last:]
	if !strings.HasPrefix(tailBytes, "\n\033[2K\n  ") {
		t.Errorf("expected stale-row clear then gap then counter, got %q",
			tailBytes[:min(len(tailBytes), 16)])
	}

	w.StopLiveCounter()

	out := buf.String()
	// Exactly one in-place growth: the first result preserves the banner
	// separator; everything after moves via the gap-jump.
	if n := strings.Count(out, "\r\033[2K"); n != 1 {
		t.Errorf("expected exactly one first-result in-place growth, found %d", n)
	}
	blocks := strings.Count(out, "%2F%2Fevil.com")
	if blocks < 3 {
		t.Fatalf("expected 3 result blocks, got %d:\n%s", blocks, out)
	}
	first := strings.Index(out, "%2F%2Fevil.com") + len("%2F%2Fevil.com")
	second := strings.Index(out[first:], "%2F%2Fevil.com") + first
	between := out[first:second]
	// Contract: end of block → clear the stale row ("\033[2K") → newline
	// making it the fresh gap → one-line counter draw → jump onto the gap
	// row ("\r\033[1A") for the next result. Missing \033[2K leaks stale
	// counter snapshots into scrollback (regression).
	if !strings.HasPrefix(between, "\n\033[2K\n") {
		t.Errorf("expected stale-row clear then gap after result block, got %q", head(between, 20))
	}
	if !strings.Contains(between, "\r\033[1A") {
		t.Error("expected gap-jump sequence before the next result")
	}
	// The counter redraw between blocks must stay on a single physical row.
	counterDraw := between[strings.Index(between, "\n\033[2K\n")+len("\n\033[2K\n"):]
	if i := strings.Index(counterDraw, "\r\033[1A"); i >= 0 {
		counterDraw = counterDraw[:i]
	}
	if strings.Contains(counterDraw, "\n") {
		t.Errorf("counter draw must be a single row, got multi-line: %q", counterDraw)
	}
}

// min returns the smaller of two ints (pre-generics convenience).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// head returns the first n bytes of s for truncated test output.
func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// tail returns the last n bytes of s for suffix assertions.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
