package output

import (
	"strconv"
	"strings"

	"github.com/yourpwnguy/redirx/internal/detector"
	"github.com/yourpwnguy/redirx/internal/httpclient"
)

// Result is the bridge between detection and display. The detector emits
// these, and the Writer decides how to format them. This keeps detection
// logic completely free of terminal/color/formatting concerns.
type Result struct {
	OriginalURL  string           // The URL that was scanned
	Param        string           // Which query parameter was mutated
	Payload      string           // The payload that was injected
	MutatedURL   string           // The full URL that was actually requested
	FinalURL     string           // Where we landed after following redirects
	RedirectURL  string           // The last hop before the final URL
	Status       int              // HTTP status from the redirect chain
	Verdict      detector.Verdict // Vuln, Safe, or Error
	Chain        []httpclient.Hop // Full redirect chain for evidence
	ErrorMessage string           // Non-empty when Verdict == Error

	// Enhanced detection fields — forwarded from detector.
	IPRedirect  detector.IPRedirectType // Non-zero when final URL is an IP literal
	Credentials string                  // Non-empty when final URL has userinfo
	EscapedHop  int                     // Index of first chain hop that escaped domain (-1 = none)
}

// ResultFromDetection adapts a detector.DetectionResult into our output Result.
// This is a one-way bridge — we never convert back.
func ResultFromDetection(dr detector.DetectionResult) Result {
	return Result{
		OriginalURL:  dr.OriginalURL,
		Param:        dr.Param,
		Payload:      dr.Payload,
		MutatedURL:   dr.MutatedURL,
		FinalURL:     dr.FinalURL,
		RedirectURL:  dr.RedirectURL,
		Status:       dr.Status,
		Verdict:      dr.Verdict,
		Chain:        dr.Chain,
		ErrorMessage: dr.ErrorMessage,
		IPRedirect:   dr.IPRedirect,
		Credentials:  dr.Credentials,
		EscapedHop:   dr.EscapedHop,
	}
}

// ChainString renders the redirect chain as a human-readable arrow sequence.
// Example: "https://evil.com/ [302] -> https://google.com/"
func (r *Result) ChainString() string {
	if len(r.Chain) == 0 {
		return ""
	}
	var b strings.Builder
	for i, h := range r.Chain {
		if i > 0 {
			b.WriteString(" -> ")
		}
		b.WriteString(truncateStr(h.URL, 60))
		if h.Status != 0 {
			b.WriteString(" [")
			b.WriteString(strconv.Itoa(h.Status))
			b.WriteByte(']')
		}
	}
	return b.String()
}

// truncateStr shortens a string to n characters, adding "..." if truncated.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
