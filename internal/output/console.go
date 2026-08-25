package output

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/yourpwnguy/redirx/internal/detector"
)

// Counter indices — named so we don't magic-number array offsets.
const (
	idxMut = 0 // total mutations attempted
	idxSaf = 1 // mutations that landed on the same domain
	idxVul = 2 // mutations that landed on a different domain
	idxErr = 3 // mutations that hit network/DNS/TLS errors
)

// liveTickInterval is how often the progress line refreshes. 100ms matches
// what ffuf and similar tools use — fast enough to feel alive, slow enough
// to not burn CPU redrawing the same numbers.
const liveTickInterval = 100 * time.Millisecond

// Color functions — initialized once at startup. The color package
// auto-detects TTY and disables colors when piped, so we don't need
// to check isatty ourselves.
//
// Palette: SEMANTIC, not decorative — every hue carries meaning, matching
// the conventions of kubectl/cargo/gh so the output reads instantly:
//
//	green  = success        (SAFE verdict, 2xx, clean-scan glyph)
//	red    = danger         (VULN verdict, SSRF-grade tags, injected param)
//	yellow = warning        (ERR verdict, soft tags, 4xx, ⚠ glyph)
//	cyan   = informational  (3xx redirects, landing URL, rate, active)
//	white  = primary data   (the numbers themselves, bold)
//	gray   = chrome         (labels, dots, spinner — never competes)
var (
	okGreen = color.New(color.FgGreen, color.Bold)  // success
	danger  = color.New(color.FgRed, color.Bold)    // findings, SSRF-grade
	warning = color.New(color.FgYellow, color.Bold) // degraded/unknown
	info    = color.New(color.FgCyan, color.Bold)   // redirects, links, rates
	primary = color.New(color.FgWhite, color.Bold)  // numbers
	chrome  = color.New(color.FgHiBlack)            // labels, annotations
)

var (
	// colorStatus returns a colored HTTP status code by outcome class:
	// green 2xx (success), cyan 3xx (redirect), yellow 4xx (client error),
	// red 5xx (server error).
	colorStatus = func(code int) string {
		switch code / 100 {
		case 2:
			return okGreen.Sprint(code)
		case 3:
			return info.Sprint(code)
		case 4:
			return warning.Sprint(code)
		case 5:
			return danger.Sprint(code)
		default:
			return primary.Sprint(code)
		}
	}
	colorBug   = danger.SprintFunc()  // VULN verdict
	colorSafe  = okGreen.SprintFunc() // SAFE verdict
	colorErr   = warning.SprintFunc() // ERR verdict
	colorFinal = info.SprintFunc()    // final landing URL (link semantics)

	// num renders counters: bright, bold, always the loudest thing on the row.
	num = primary.SprintFunc()

	// dim wraps annotations like status brackets. Unlike raw "\033[..."
	// literals it goes through fatih/color, so it degrades to plain text
	// when output is piped instead of leaking escape codes into files.
	dim = chrome.SprintFunc()
)

// ConsoleWriter writes human-readable, color-coded results to a writer.
// It tracks its own counters so the scanner doesn't need to manage state.
type ConsoleWriter struct {
	W        io.Writer
	VulnOnly bool // Suppress SAFE and ERR lines — findings only.
	Quiet    bool // Disable banner and live counter; plain output only.
	counts   [4]int64

	// tty reports whether W is an interactive terminal. The live counter
	// (cursor control codes, redraws) is only enabled when this is true;
	// pipes and files get plain line output with zero escape sequences.
	tty bool

	// Live counter state — all fields below are guarded by liveMu.
	liveMu       sync.Mutex
	liveStarted  bool
	liveTotalMut int64
	liveStart    time.Time
	stopTick     chan struct{}
	tickDone     chan struct{}

	// stoppedLive records that StopLiveCounter reclaimed both the gap row
	// and the counter row — WriteSummary consumes it to avoid stacking a
	// second blank line on top of the reclaimed gap.
	stoppedLive bool

	// resultsShown flips on the first VISIBLE result in a live session.
	// The first result must not consume the banner's blank line (that row
	// is the permanent separator between the header and the results
	// section), so it grows downward from the counter row instead of
	// jumping up onto the gap.
	resultsShown bool

	// inflight, when set by the scanner via SetInFlight, points at a shared
	// counter of mutations currently being processed. Read atomically by
	// drawProgressLine; ownership stays with the scanner.
	inflight *int64
}

// SetInFlight wires the scanner's in-flight mutation counter into the live
// display. Optional — when unset, the "active" cell is omitted.
func (c *ConsoleWriter) SetInFlight(ref *int64) { c.inflight = ref }

// NewConsoleWriter returns a ConsoleWriter that writes to stdout.
//
// On Windows the raw stdout handle is wrapped with colorable so ANSI
// colors actually render; on other platforms it's a passthrough.
func NewConsoleWriter(vulnOnly, quiet bool) *ConsoleWriter {
	return &ConsoleWriter{
		W:        colorable.NewColorableStdout(),
		VulnOnly: vulnOnly,
		Quiet:    quiet,
		tty:      isatty.IsTerminal(os.Stdout.Fd()),
	}
}

// Write formats and writes a single result. Safe for concurrent use.
//
// When the live counter is active, the result line replaces the progress
// line in place (which scrolls it into history above), and a fresh
// progress line is drawn below it. See emit() for the terminal discipline.
func (c *ConsoleWriter) Write(r Result) {
	atomic.AddInt64(&c.counts[idxMut], 1)

	var line string
	switch r.Verdict {
	case detector.Vuln:
		atomic.AddInt64(&c.counts[idxVul], 1)
		line = c.formatVuln(r)
	case detector.Safe:
		atomic.AddInt64(&c.counts[idxSaf], 1)
		if !c.VulnOnly {
			line = c.formatSafe(r)
		}
	case detector.Error:
		atomic.AddInt64(&c.counts[idxErr], 1)
		line = c.formatError(r)
	}

	c.emit(line)
}

// emit prints one result line while keeping the progress bar pinned to
// the bottom of the terminal, separated from the result stream by exactly
// ONE reserved blank row:
//
//	REDIRX v0.1.0 — ...
//	                          ← permanent section separator (never touched)
//	[302] VULN ⇢ ...          ← results scroll up, packed tight
//	       req: ...
//	   chain: ...
//	                          ← moving gap row (exactly one, always)
//	  ⠹ mut 8/37 (21%) ...    ← live row, cursor parked here
//
// Two row disciplines, both under liveMu:
//
//   - First visible result: replaces the counter IN PLACE and grows
//     downward. The banner's blank line above stays untouched as the
//     permanent header separator.
//   - Every later result: jumps UP onto the moving gap row and prints
//     over it — consuming it instead of piling blanks into scrollback —
//     then lays a fresh gap below itself. The landing row is ALWAYS
//     cleared (\033[2K) before becoming the new gap: for 1-line results
//     that row still holds the stale counter text.
//
// The \033[1A is safe because the gap row is a tracked invariant: nothing
// else ever writes there (suppressed writes and ticker redraws stay in
// place), so cursor-up can never land on a wrapped result line.
func (c *ConsoleWriter) emit(line string) {
	c.liveMu.Lock()
	defer c.liveMu.Unlock()

	if !c.liveStarted {
		if line != "" {
			fmt.Fprintln(c.W, line)
		}
		return
	}

	if line == "" {
		fmt.Fprint(c.W, "\r")
		c.drawProgressLine()
		return
	}

	if !c.resultsShown {
		// First visible result — grow downward, keep the separator above.
		c.resultsShown = true
		fmt.Fprint(c.W, "\r\033[2K")
	} else {
		// Later results — consume the moving gap row.
		fmt.Fprint(c.W, "\r\033[1A")
	}
	fmt.Fprintln(c.W, line)
	fmt.Fprint(c.W, "\033[2K\n") // clear stale/stale-free landing row → fresh gap
	c.drawProgressLine()
}

// statusTag renders "[302]" with the brackets dimmed and the code in its
// outcome color. The segments are deliberately NOT nested SGR spans: an
// inner color's trailing reset (\x1b[0m) would wipe the enclosing dim
// attribute, leaving the closing bracket in default terminal white.
func statusTag(code int) string {
	return dim("[") + colorStatus(code) + dim("]")
}

// formatVuln renders a vulnerability finding.
//
// Layout — the landing URL leads because that's the evidence; the request
// that produced it sits indented below, and multi-hop chains get their own
// labeled row:
//
//	[302] VULN ⇢ https://www.google.com/  · escape@hop0
//	       req: https://t.com/?next=<hl>//google.com/%2f..</hl>
//	   chain: https://google.com/ [302] -> https://www.google.com/ [301]
//
// The returned string has NO trailing newline — emit() owns newlines.
func (c *ConsoleWriter) formatVuln(r Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "  %s %s ⇢ %s",
		statusTag(r.Status),
		colorBug("VULN"),
		colorFinal(r.FinalURL),
	)

	// Enhanced detection tags — IP redirects, userinfo tricks, chain escape.
	// SSRF-grade findings (internal/loopback/creds) are RED — they mean
	// "server can reach internal space". Softer escapes get YELLOW —
	// noteworthy but not internal exposure.
	var tags []string
	if r.IPRedirect != detector.NoIPRedirect {
		switch r.IPRedirect {
		case detector.InternalIP:
			tags = append(tags, danger.Sprint("IP:internal"))
		case detector.Loopback:
			tags = append(tags, danger.Sprint("IP:loopback"))
		case detector.ExternalIP:
			tags = append(tags, warning.Sprint("IP:external"))
		}
	}
	if r.Credentials != "" {
		tags = append(tags, danger.Sprint("creds:"+r.Credentials))
	}
	if r.EscapedHop >= 0 {
		tags = append(tags, warning.Sprint(fmt.Sprintf("escape@hop%d", r.EscapedHop)))
	}
	if len(tags) > 0 {
		fmt.Fprintf(&b, "  %s", dim("· "+strings.Join(tags, " ")))
	}

	fmt.Fprintf(&b, "\n       %s %s", dim("req:"), highlightParam(r.MutatedURL, r.Param))

	// Single-hop chains are already visible in the req/landed pair; only
	// show intermediate hops when there's something extra to see.
	if len(r.Chain) > 1 {
		if chain := r.ChainString(); chain != "" {
			fmt.Fprintf(&b, "\n   %s %s", dim("chain:"), chain)
		}
	}

	return b.String()
}

// formatSafe renders a non-vulnerable result. Concise — we don't want
// to flood the terminal with SAFE lines during a big scan.
func (c *ConsoleWriter) formatSafe(r Result) string {
	return fmt.Sprintf("  %s %s ⇢ %s",
		statusTag(r.Status),
		colorSafe("SAFE"),
		r.MutatedURL,
	)
}

// formatError renders a network/DNS/TLS error. These are real problems
// that the user should investigate, not silent failures.
func (c *ConsoleWriter) formatError(r Result) string {
	return fmt.Sprintf("  %s %s ⇢ %s: %s",
		dim("[---]"),
		colorErr("ERR "),
		r.MutatedURL,
		r.ErrorMessage,
	)
}

// WriteSummary prints the end-of-scan stats as one chip line:
//
//	✓ 435 targets · 6,401 muts · 1,001.7/s · 6.39s · vuln 0 · err 0
//
// The glyph turns into ⚠ when findings exist. After a live session,
// StopLiveCounter already reclaimed the counter rows leaving exactly one
// blank line above the cursor — same spacing as live mode. Without a live
// session, emit the separator ourselves.
func (c *ConsoleWriter) WriteSummary(s Summary) {
	if c.stoppedLive {
		c.stoppedLive = false
	} else {
		fmt.Fprintln(c.W)
	}

	glyph := "✓"
	if s.Vulnerable > 0 {
		glyph = "⚠"
	}

	rate := 0.0
	if secs := s.Duration.Seconds(); secs > 0 {
		rate = float64(s.TotalMutations) / secs
	}

	fmt.Fprintf(c.W, "  %s %s %s · %s %s · %s · %s · vuln %s · err %s\n",
		glyphColor(glyph, s.Vulnerable > 0),
		num(comma(int64(s.TotalURLs))), dim("targets"),
		num(comma(s.TotalMutations)), dim("muts"),
		info.Sprint(fmt.Sprintf("%.1f/s", rate)),
		dim("in")+" "+num(s.Duration.Round(time.Millisecond)),
		vulColor(s.Vulnerable),
		errColor(s.Errors),
	)
	fmt.Fprintln(c.W)
}

// StartLiveCounter begins the live progress display: it draws the initial
// progress row and starts a ticker goroutine that refreshes it every
// liveTickInterval. The ticker keeps elapsed time and the spinner moving
// even while slow requests are in flight — without it the display would
// freeze for whole timeouts between results.
//
// Suppressed in quiet mode and on non-terminal output (pipes, files).
func (c *ConsoleWriter) StartLiveCounter(totalMuts int) {
	c.liveMu.Lock()
	defer c.liveMu.Unlock()

	if c.liveStarted || c.Quiet || !c.tty {
		return
	}

	c.liveTotalMut = int64(totalMuts)
	c.liveStart = time.Now()
	c.liveStarted = true

	// Draw the initial progress row directly — the banner's trailing blank
	// line already provides the one-row separation above us. No trailing
	// newline: the cursor stays parked at the end of this row, which is
	// the invariant emit() and the ticker both rely on.
	c.drawProgressLine()

	stop := make(chan struct{})
	done := make(chan struct{})
	c.stopTick = stop
	c.tickDone = done

	go func() {
		defer close(done)
		ticker := time.NewTicker(liveTickInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				c.liveMu.Lock()
				// StopLiveCounter may have flipped liveStarted while we
				// waited on the mutex — never draw after shutdown.
				if c.liveStarted {
					fmt.Fprint(c.W, "\r\033[K")
					c.drawProgressLine()
				}
				c.liveMu.Unlock()
			}
		}
	}()
}

// drawProgressLine writes the progress bar content at the current cursor
// position. Does NOT move the cursor to a new line — callers manage that.
//
// Layout (single row, "labeled dashboard"):
//
//	⠹ mut 3,514/16,095 (21%) · vuln 0 · err 0 · 494.9/s · active 50 · ETA 25s
//
// Must be called with c.liveMu held.
func (c *ConsoleWriter) drawProgressLine() {
	mut := atomic.LoadInt64(&c.counts[idxMut])
	vul := atomic.LoadInt64(&c.counts[idxVul])
	errs := atomic.LoadInt64(&c.counts[idxErr])
	elapsed := time.Since(c.liveStart)

	pct := 0
	if c.liveTotalMut > 0 {
		pct = int(float64(mut) / float64(c.liveTotalMut) * 100)
		if pct > 100 {
			pct = 100
		}
	}

	// Spinner frames — cycled by elapsed-time so the animation stays smooth
	// even when redraws are bursty. Time-based, not tick-based, on purpose:
	// two redraws in the same 100ms window must show the same frame.
	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := int(elapsed.Milliseconds()/100) % len(spin)

	rate := 0.0
	if secs := elapsed.Seconds(); secs > 0 {
		rate = float64(mut) / secs
	}

	// ETA from average rate; "--" until we have a measurement.
	eta := "--"
	if rate > 0 && mut < c.liveTotalMut {
		eta = time.Duration(float64(c.liveTotalMut-mut) / rate * float64(time.Second)).
			Round(time.Second).String()
	}

	// In-flight workers, when the scanner wired up its counter. Cyan =
	// informational, like the rate.
	active := ""
	if c.inflight != nil {
		active = fmt.Sprintf("  %s %s", dim("active"), info.Sprint(atomic.LoadInt64(c.inflight)))
	}

	fmt.Fprintf(c.W, "  %s %s %s/%s (%d%%) · %s %s · %s %s · %s%s · %s %s",
		dim(spin[spinIdx]),
		dim("mut"), num(comma(mut)), num(comma(c.liveTotalMut)), pct,
		dim("vuln"), vulColor(vul),
		dim("err"), errColor(errs),
		info.Sprint(fmt.Sprintf("%.1f/s", rate)),
		active,
		dim("ETA"), dim(eta),
	)
}

// glyphColor picks the summary glyph tone: green when the scan is clean,
// red when vulnerabilities were found, yellow for error-only runs —
// matching the verdict colors used throughout the session.
func glyphColor(glyph string, hasFindings bool) string {
	if hasFindings {
		return danger.Sprint(glyph)
	}
	return okGreen.Sprint(glyph)
}

// vulColor/errColor let the verdict numbers stay quiet at zero and glow
// when something actually needs attention.
var (
	vulColor = func(n int64) string {
		if n > 0 {
			return danger.Sprint(comma(n))
		}
		return num(n)
	}
	errColor = func(n int64) string {
		if n > 0 {
			return warning.Sprint(comma(n))
		}
		return num(n)
	}
)

// comma inserts thousands separators: 16095 -> "16,095". Small enough to
// not justify pulling golang.org/x/text into the dependency tree.
func comma(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	pre := len(s) % 3
	var b strings.Builder
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// StopLiveCounter stops the live counter and reclaims its two rows — the
// reserved gap and the counter row itself — leaving exactly one blank line
// between the last result and wherever the cursor lands. WriteSummary then
// prints directly at that spot, keeping the spacing identical to live mode.
func (c *ConsoleWriter) StopLiveCounter() {
	c.liveMu.Lock()

	if !c.liveStarted {
		c.liveMu.Unlock()
		return
	}

	c.liveStarted = false
	c.stoppedLive = true
	stop := c.stopTick
	done := c.tickDone
	c.stopTick = nil
	c.tickDone = nil

	// Up onto the gap row, clear it, down to the counter row, clear it.
	fmt.Fprint(c.W, "\r\033[1A\033[2K\n\033[2K")

	c.liveMu.Unlock()

	// Wait for the ticker goroutine to observe shutdown. It re-checks
	// liveStarted under the mutex before drawing, so nothing can paint
	// after the lines are reclaimed.
	if stop != nil && done != nil {
		close(stop)
		<-done
	}
}

// Counts returns the final counter values after the drain loop exits:
// total mutations attempted, plus per-verdict breakdowns (safe, vuln, err).
// The scanner reads these right before building the Summary — the writer
// owns counting so neither layer duplicates bookkeeping.
func (c *ConsoleWriter) Counts() (mut, safe, vuln, errs int64) {
	return atomic.LoadInt64(&c.counts[idxMut]),
		atomic.LoadInt64(&c.counts[idxSaf]),
		atomic.LoadInt64(&c.counts[idxVul]),
		atomic.LoadInt64(&c.counts[idxErr])
}

// highlightParam colorizes the mutated parameter in the URL so the user
// can instantly see which parameter was tested. The param gets red+underline,
// the injected value gets yellow+bold.
func highlightParam(rawURL, param string) string {
	if param == "" {
		return rawURL
	}
	pattern := param + "="
	idx := strings.Index(rawURL, pattern)
	if idx == -1 {
		return rawURL
	}
	before := rawURL[:idx]
	after := rawURL[idx+len(param)+1:]
	valEnd := strings.Index(after, "&")
	if valEnd == -1 {
		valEnd = len(after)
	}
	val := after[:valEnd]
	rest := after[valEnd:]
	return before +
		color.New(color.FgRed, color.Bold, color.Underline).Sprint(param+"=") +
		warning.Sprint(val) +
		rest
}

// Summary holds the final scan statistics. The scanner computes this
// from the Writer's counters and passes it back for display.
// Summary is the end-of-scan aggregate. The scanner assembles it from the
// writer's own counters (single source of truth) plus wall-clock timing.
type Summary struct {
	TotalURLs      int           // Distinct input targets scanned.
	TotalMutations int64         // Probes actually executed (param × payload combos).
	Safe           int64         // Landed on/within the original domain.
	Vulnerable     int64         // Escaped domain AND traced back to our payload.
	Errors         int64         // Network/DNS/TLS failures — "unknown", not safe.
	Duration       time.Duration // Wall-clock time from scan start to last result.
}
