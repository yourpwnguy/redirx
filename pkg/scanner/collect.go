package scanner

import (
	"bufio"
	"os"
	"slices"
	"strings"

	"github.com/yourpwnguy/redirx/pkg/globals"
)

// Function to collect all the URLs provided
func collectURLS(cfg globals.Config) ([]string, error) {
	out := slices.Clone(cfg.URLS)

	if cfg.URLSList != "" {
		f, err := os.Open(cfg.URLSList)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		scan := bufio.NewScanner(f)
		for scan.Scan() {
			if line := strings.TrimSpace(scan.Text()); line != "" {
				out = append(out, line)
			}
		}
	}
	return out, nil
}

// Function to collect payloads from the file
func collectPayloads(cfg globals.Config) ([]string, error) {
	p := make([]string, 0)
	if cfg.PayloadList != "" {
		f, err := os.Open(cfg.PayloadList)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		scan := bufio.NewScanner(f)
		for scan.Scan() {
			if line := strings.TrimSpace(scan.Text()); line != "" {
				p = append(p, line)
			}
		}
	}
	return p, nil
}
