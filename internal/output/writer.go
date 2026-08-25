// Package output handles formatting and writing scan results.
//
// The key design decision here is the Writer interface: detection logic
// emits Result structs, and the output layer decides how to present them.
// This means we can swap console/JSON/webhook without touching detection code.
package output

// Writer is the interface the scanner uses to emit results.
// Two implementations exist:
//   - ConsoleWriter: human-readable colored output for terminals
//   - JSONWriter: machine-readable JSON lines for pipelines
type Writer interface {
	// Write emits a single scan result. Must be safe for concurrent use.
	Write(r Result)

	// WriteSummary emits the final scan statistics.
	WriteSummary(s Summary)

	// Counts returns the current counter values (mutations, safe, vuln, errors).
	Counts() (mut, safe, vuln, errs int64)

	// StartLiveCounter begins the live progress display: an initial progress
	// line plus a ticker goroutine that refreshes it every 100ms. Only
	// meaningful for ConsoleWriter on a TTY — JSONWriter and quiet mode get
	// no-ops. Results written via Write() scroll above the progress line.
	StartLiveCounter(totalMuts int)

	// StopLiveCounter stops the live counter and clears the progress line.
	// Must be called before WriteSummary. No-op if not started.
	StopLiveCounter()
}
