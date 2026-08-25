package output

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatih/color"
)

// withNoColor forces fatih/color to emit plain text for the duration of fn,
// letting tests assert on exact rune-level layout.
func withNoColor(t *testing.T, fn func()) {
	t.Helper()
	old := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = old }()
	fn()
}

// TestWriteSummary_Content pins the end-of-scan chip line: single line,
// no box drawing, thousands separators, rate, duration, verdict counts —
// and a ⚠ glyph only when findings exist (✓ otherwise).
func TestWriteSummary_Content(t *testing.T) {
	withNoColor(t, func() {
		var buf strings.Builder
		w := &ConsoleWriter{W: &buf}

		w.WriteSummary(Summary{
			TotalURLs:      3,
			TotalMutations: 111,
			Safe:           100,
			Vulnerable:     9,
			Errors:         2,
			Duration:       1500 * time.Millisecond,
		})

		out := buf.String()
		for _, bad := range []string{"╭", "│", "╰", "├"} {
			if strings.Contains(out, bad) {
				t.Errorf("summary must not contain box-drawing character %q", bad)
			}
		}
		for _, want := range []string{"⚠ 3 targets", "111 muts", "74.0/s", "in 1.5s", "vuln 9", "err 2"} {
			if !strings.Contains(out, want) {
				t.Errorf("summary missing %q — got:\n%s", want, out)
			}
		}

		buf.Reset()
		w.WriteSummary(Summary{TotalURLs: 1234, TotalMutations: 98765, Duration: time.Second})
		out = buf.String()
		if !strings.Contains(out, "✓ 1,234 targets") {
			t.Errorf("zero-vuln run must use ✓ glyph + comma separators — got:\n%s", out)
		}
		if !strings.Contains(out, "98,765 muts") {
			t.Errorf("expected thousands separator in mutations count — got:\n%s", out)
		}
	})
}

// TestWriteSummary_Spacing pins the vertical rhythm of the stats block:
// it always starts with one blank separator line, in live and non-live
// modes alike.
func TestWriteSummary_Spacing(t *testing.T) {
	withNoColor(t, func() {
		var buf strings.Builder
		w := &ConsoleWriter{W: &buf, tty: true}

		w.StartLiveCounter(1)
		w.StopLiveCounter()
		w.WriteSummary(Summary{TotalURLs: 1, TotalMutations: 1, Duration: time.Second})

		out := buf.String()
		// StopLiveCounter reclaims both rows; WriteSummary must print
		// directly at the reclaimed spot — exactly one blank line between
		// the last result and the stats chip.
		if !strings.Contains(out, "\033[2K\n\033[2K  ✓") {
			t.Errorf("summary after live stop must print at reclaimed row, got:\n%q", out)
		}
		if !strings.Contains(out, "1.0/s") {
			t.Errorf("expected rate in summary, got:\n%s", out)
		}

		buf.Reset()
		w2 := &ConsoleWriter{W: &buf}
		w2.WriteSummary(Summary{TotalURLs: 1, Duration: time.Second})
		if !strings.HasPrefix(buf.String(), "\n") {
			t.Error("standalone summary must start with a blank separator line")
		}
	})
}

// TestDrawProgressLine_Content checks the live counter renders the expected
// fields: counts, percent, per-verdict numbers, rate, elapsed — and no bar.
func TestDrawProgressLine_Content(t *testing.T) {
	withNoColor(t, func() {
		var buf strings.Builder
		w := &ConsoleWriter{W: &buf, tty: false}

		w.StartLiveCounter(0)
		w.StopLiveCounter()
		buf.Reset()

		w.liveMu.Lock()
		w.liveStarted = true // force-enable drawing without a TTY
		w.liveTotalMut = 37
		w.liveStart = time.Now().Add(-2 * time.Second)
		w.counts[idxMut] = 31
		w.counts[idxSaf] = 28
		w.counts[idxVul] = 3
		w.drawProgressLine()
		w.liveMu.Unlock()

		out := buf.String()
		for _, want := range []string{"mut 31/37", "(83%)", "vuln 3", "err 0", "/s", "ETA"} {
			if !strings.Contains(out, want) {
				t.Errorf("progress line missing %q — got: %s", want, out)
			}
		}
		for _, banned := range []string{"█", "░", "["} {
			if strings.Contains(out, banned) {
				t.Errorf("progress line must be plain numbers, found %q — got: %s", banned, out)
			}
		}
	})
}

// TestDrawProgressLine_InFlight verifies the optional "active N" cell only
// appears when the scanner wired up its in-flight counter.
func TestDrawProgressLine_InFlight(t *testing.T) {
	withNoColor(t, func() {
		var buf strings.Builder
		w := &ConsoleWriter{W: &buf, tty: false}

		w.StartLiveCounter(0)
		w.StopLiveCounter()
		buf.Reset()

		var inflight int64
		w.SetInFlight(&inflight)
		atomic.StoreInt64(&inflight, 42)

		w.liveMu.Lock()
		w.liveStarted = true
		w.liveTotalMut = 100
		w.liveStart = time.Now()
		w.drawProgressLine()
		w.liveMu.Unlock()

		if !strings.Contains(buf.String(), "active 42") {
			t.Errorf("expected active cell — got: %s", buf.String())
		}

		buf.Reset()
		w2 := &ConsoleWriter{W: &buf, tty: false}
		w2.liveMu.Lock()
		w2.liveStarted = true
		w2.liveTotalMut = 100
		w2.liveStart = time.Now()
		w2.drawProgressLine()
		w2.liveMu.Unlock()
		if strings.Contains(buf.String(), "active") {
			t.Errorf("active cell must be omitted without SetInFlight — got: %s", buf.String())
		}
	})
}
