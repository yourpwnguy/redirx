// Package cli handles stdin detection and URL reading.
package cli

import (
	"bufio"
	"os"
	"strings"
)

// ReadFromStdin reads URLs from stdin when data is piped (not a TTY).
// Returns nil if stdin is a terminal — we don't want to block waiting
// for input when the user forgot to pipe something.
func ReadFromStdin() []string {
	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice != 0 {
		return nil
	}

	var urls []string
	sc := bufio.NewScanner(os.Stdin)
	// Bump the buffer so we can handle long URLs (some recon lists have
	// URLs with massive query strings).
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	return urls
}
