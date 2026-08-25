package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/yourpwnguy/redirx/internal/detector"
)

// JSONResult is the JSON-serializable form of a single scan result.
// Written as one line per result (JSON Lines format) so tools like
// jq can process the stream incrementally.
type JSONResult struct {
	Timestamp    string    `json:"timestamp"`
	OriginalURL  string    `json:"original_url"`
	Param        string    `json:"param"`
	Payload      string    `json:"payload"`
	MutatedURL   string    `json:"mutated_url"`
	FinalURL     string    `json:"final_url,omitempty"`
	RedirectURL  string    `json:"redirect_url,omitempty"`
	Status       int       `json:"status"`
	Verdict      string    `json:"verdict"`
	Chain        []JSONHop `json:"chain,omitempty"`
	ErrorMessage string    `json:"error,omitempty"`

	// Enhanced detection fields
	IPRedirect  string `json:"ip_redirect,omitempty"` // "internal", "loopback", "external", or empty
	Credentials string `json:"credentials,omitempty"` // userinfo if present
	EscapedHop  int    `json:"escaped_hop,omitempty"` // -1 means none, omitted from JSON
}

// JSONHop represents one redirect hop in the chain.
type JSONHop struct {
	URL    string `json:"url"`    // Hop destination URL.
	Status int    `json:"status"` // Status of the response that redirected here.
}

// JSONSummary is the final line of JSON output — aggregate stats.
type JSONSummary struct {
	Timestamp       string  `json:"timestamp"`        // UTC RFC3339 scan-completion time.
	TotalURLs       int     `json:"total_urls"`       // Distinct targets scanned.
	TotalMutations  int64   `json:"total_mutations"`  // Probes executed.
	Safe            int64   `json:"safe"`             // Verdict tally: landed within original domain.
	Vulnerable      int64   `json:"vulnerable"`       // Verdict tally: confirmed payload-driven escapes.
	Errors          int64   `json:"errors"`           // Verdict tally: network/DNS/TLS unknowns.
	DurationSeconds float64 `json:"duration_seconds"` // Wall-clock runtime in seconds.
}

// JSONWriter writes results as JSON lines to a file. It satisfies the
// full Writer interface, with terminal-specific methods as no-ops —
// escape codes and \r redraws would corrupt file/pipeline consumers.
type JSONWriter struct {
	file    *os.File      // Destination handle; created by NewJSONWriter.
	encoder *json.Encoder // Wraps file; one Encode call = one JSONL line.
	counts  [4]int64      // Per-verdict tallies (indices mirror console.go).
}

// NewJSONWriter creates a JSONWriter that writes to the given file path.
func NewJSONWriter(path string) (*JSONWriter, error) {
	if path == "" {
		path = "redirx-results.json"
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create output file %q: %w", path, err)
	}
	return &JSONWriter{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// Write appends one result as a JSON line.
func (w *JSONWriter) Write(r Result) {
	atomic.AddInt64(&w.counts[idxMut], 1)

	jr := JSONResult{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		OriginalURL:  r.OriginalURL,
		Param:        r.Param,
		Payload:      r.Payload,
		MutatedURL:   r.MutatedURL,
		FinalURL:     r.FinalURL,
		RedirectURL:  r.RedirectURL,
		Status:       r.Status,
		ErrorMessage: r.ErrorMessage,
		Credentials:  r.Credentials,
	}

	switch r.Verdict {
	case detector.Vuln:
		jr.Verdict = "vulnerable"
		atomic.AddInt64(&w.counts[idxVul], 1)
	case detector.Safe:
		jr.Verdict = "safe"
		atomic.AddInt64(&w.counts[idxSaf], 1)
	case detector.Error:
		jr.Verdict = "error"
		atomic.AddInt64(&w.counts[idxErr], 1)
	}

	// IP redirect classification — only set when non-zero
	switch r.IPRedirect {
	case detector.InternalIP:
		jr.IPRedirect = "internal"
	case detector.Loopback:
		jr.IPRedirect = "loopback"
	case detector.ExternalIP:
		jr.IPRedirect = "external"
	}

	// Escaped hop — only include when a hop actually escaped
	if r.EscapedHop >= 0 {
		jr.EscapedHop = r.EscapedHop
	}

	if len(r.Chain) > 0 {
		jr.Chain = make([]JSONHop, 0, len(r.Chain))
		for _, h := range r.Chain {
			jr.Chain = append(jr.Chain, JSONHop{URL: h.URL, Status: h.Status})
		}
	}

	_ = w.encoder.Encode(jr) // struct encoding cannot fail; see doc above.
}

// WriteSummary appends the aggregate stats as the final JSON line so
// pipeline consumers get machine-readable totals without parsing stdout.
func (w *JSONWriter) WriteSummary(s Summary) {
	_ = w.encoder.Encode(JSONSummary{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		TotalURLs:       s.TotalURLs,
		TotalMutations:  s.TotalMutations,
		Safe:            s.Safe,
		Vulnerable:      s.Vulnerable,
		Errors:          s.Errors,
		DurationSeconds: s.Duration.Seconds(),
	})
}

// Counts returns current counter values.
func (w *JSONWriter) Counts() (mut, safe, vuln, errs int64) {
	return atomic.LoadInt64(&w.counts[idxMut]),
		atomic.LoadInt64(&w.counts[idxSaf]),
		atomic.LoadInt64(&w.counts[idxVul]),
		atomic.LoadInt64(&w.counts[idxErr])
}

// Close flushes and closes the underlying file.
func (w *JSONWriter) Close() error {
	return w.file.Close()
}

// StartLiveCounter is a no-op for JSON output — live counters are a
// terminal feature. JSON output goes to files/pipelines where \r
// would be garbage.
func (w *JSONWriter) StartLiveCounter(totalMuts int) {}

// StopLiveCounter is a no-op for JSON output.
func (w *JSONWriter) StopLiveCounter() {}
