package detector

import (
	"fmt"
	"net/url"
	"strings"
)

// MutatedURL represents a URL with one parameter replaced by a payload.
// The scanner creates one of these for each (param, payload) combination
// and sends it through the detection pipeline.
//
// Why do we need OriginalURL here? Because after mutation we need to know
// what domain the URL *started* on to compare against where it *landed*.
type MutatedURL struct {
	OriginalURL string // The URL before mutation (for domain comparison)
	Param       string // Which parameter was replaced
	Payload     string // The payload that was injected
	MutatedURL  string // The full URL that was actually requested
}

// Mutate generates one MutatedURL for each (param, payload) combination.
//
// This is the combinatorial explosion that makes open-redirect scanning
// expensive: 5 parameters × 44 payloads = 220 probes per URL. The worker
// pool in scanner handles the concurrency, but this function is where
// the mutation list is built.
//
// We preserve the original parameter ordering and handle duplicate keys
// correctly — if the URL has ?q=1&q=2, we mutate q once (not twice)
// and keep the other parameters' values intact.
func Mutate(rawURL string, payloads []string) ([]MutatedURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL %q: %w", rawURL, err)
	}

	q := u.Query()
	if len(q) == 0 {
		return nil, nil
	}

	// Collect params in the order they appear in the raw query string.
	// url.Parse normalizes order; we need the original order for
	// reproducible mutation output.
	type paramEntry struct {
		key    string
		values []string
	}
	var params []paramEntry
	seen := make(map[string]bool)
	for pair := range strings.SplitSeq(u.RawQuery, "&") {
		kv := strings.SplitN(pair, "=", 2)
		k := kv[0]
		if seen[k] {
			continue
		}
		seen[k] = true
		params = append(params, paramEntry{key: k, values: q[k]})
	}

	var results []MutatedURL
	for _, pe := range params {
		for _, payload := range payloads {
			clone := *u
			var rawParts []string
			for _, p := range params {
				if p.key == pe.key {
					// This is the parameter we're mutating — inject the payload.
					rawParts = append(rawParts, p.key+"="+payload)
				} else {
					// Keep other parameters as-is, re-encoding their values.
					for _, val := range p.values {
						rawParts = append(rawParts, p.key+"="+url.QueryEscape(val))
					}
				}
			}
			clone.RawQuery = strings.Join(rawParts, "&")
			results = append(results, MutatedURL{
				OriginalURL: rawURL,
				Param:       pe.key,
				Payload:     payload,
				MutatedURL:  clone.String(),
			})
		}
	}
	return results, nil
}
