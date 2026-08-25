package detector

import (
	"context"

	"github.com/yourpwnguy/redirx/internal/httpclient"
)

// BaselineResult holds the outcome of a control request (unmodified URL).
// Used to determine which domains the target legitimately redirects to,
// so we can exclude them from vulnerability findings.
//
// This is how we cut false positives in half: if the target always bounces
// to auth.example.com before showing content, that's SSO — not a vuln.
// Without baseline, every payload would trigger a "vuln" on that bounce.
type BaselineResult struct {
	FinalDomain string // eTLD+1 of where the unmodified URL lands
	FinalURL    string // Full final URL
	Status      int    // HTTP status code
	Error       error  // Non-nil on failure
}

// RunBaseline sends the unmodified URL through the client and records
// where it lands. This is the control request — the idea is that if the
// target always redirects to auth.example.com regardless of the payload,
// then auth.example.com is a legitimate bounce, not a vulnerability.
//
// We run this once per URL before any mutations. It adds latency but
// saves you from drowning in false positives on sites with auth gates.
func RunBaseline(ctx context.Context, client *httpclient.Client, rawURL string) BaselineResult {
	res := client.Follow(ctx, rawURL)
	if res.Error != nil {
		return BaselineResult{Error: res.Error}
	}

	domain, err := GetRegistrableDomain(res.Final)
	if err != nil {
		return BaselineResult{
			FinalURL: res.Final,
			Error:    err,
		}
	}

	// Extract the most meaningful status from the chain.
	status := res.AnyRedirectStatus()
	if status == 0 {
		status = res.FinalStatus
	}

	return BaselineResult{
		FinalDomain: domain,
		FinalURL:    res.Final,
		Status:      status,
	}
}
