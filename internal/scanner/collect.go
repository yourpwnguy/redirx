package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/yourpwnguy/redirx/internal/config"
)

// collectURLs gathers URLs from all configured sources: CLI flags, files,
// and stdin. Deduplicates while preserving insertion order.
//
// Why preserve order? Because when you're debugging a scan, you want
// results in the same order you fed them in. Map iteration would give
// you random order every run, which makes debugging miserable.
func collectURLs(cfg config.Config) ([]string, error) {
	var urls []string
	seen := make(map[string]bool)

	// URLs from -u flags
	for _, u := range cfg.URLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	// URLs from -l file
	if cfg.URLList != "" {
		f, err := os.Open(cfg.URLList)
		if err != nil {
			return urls, fmt.Errorf("open URL list %q: %w", cfg.URLList, err)
		}
		// Read-only handle: close failures cannot corrupt anything.
		defer func() { _ = f.Close() }()

		sc := bufio.NewScanner(f)
		// 1MB buffer for long URLs (recon lists sometimes have massive query strings)
		sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !seen[line] {
				seen[line] = true
				urls = append(urls, line)
			}
		}
		if err := sc.Err(); err != nil {
			return urls, fmt.Errorf("read URL list: %w", err)
		}
	}

	return urls, nil
}
