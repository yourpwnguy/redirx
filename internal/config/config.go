// Package config defines the runtime configuration for a scan.
//
// Config is a pure data struct — no behavior, no validation logic.
// The CLI builds it from flags, scanner reads it, done. This keeps
// config importable by every package without creating circular deps.
package config

import "time"

// Config holds all runtime options for a single scan run.
type Config struct {
	// Inputs — URLs can come from flags, files, or stdin.
	URLs     []string
	URLList  string   // Path to a newline-separated target file (-l).
	Payloads []string // nil means use the built-in set

	// Tuning
	Concurrency int
	Timeout     time.Duration // Per-request timeout applied to the shared client.
	MaxRedirect int           // Hop cap before a chain is declared a loop/error.

	// Network
	Method  string            // HTTP method: HEAD (default), GET, etc.
	Proxy   string            // Optional HTTP proxy URL
	Headers map[string]string // Custom request headers

	// Detection
	Baseline bool // Run control requests before mutating
	VulnOnly bool // Suppress SAFE/ERR lines in output

	// Output
	Output     string // File path for JSON output
	JSONOutput bool   // Route results to a JSONL file instead of stdout.
	Quiet      bool   // Suppress banner and live counter entirely.

	// Derived at startup — don't set this manually
	UserAgent string
}
