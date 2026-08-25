// Package detector implements the core open-redirect detection logic.
//
// The detection pipeline:
//  1. Mutate: generate (param × payload) URL variants
//  2. Probe: follow redirects for each variant
//  3. Classify: compare landing domain against original (eTLD+1)
//  4. Analyze: check for IP redirects, credentials in URL, chain escapes
//  5. Filter: exclude baseline bounces when --baseline is active
//
// This package is pure detection — it knows nothing about terminals,
// colors, or output formatting. It emits DetectionResult structs and
// lets the output layer decide how to present them.
//
// Why eTLD+1? Because "evil-example.com" ≠ "example.com" and
// "sub.example.co.uk" shares a registrable domain with "example.co.uk".
// Naive string comparison on the host would give you garbage results.
package detector

import (
	"context"
	"strings"

	"github.com/yourpwnguy/redirx/internal/httpclient"
)

// Verdict classifies a scan result. Three outcomes, no ambiguity:
//
//   - Vuln: payload caused a domain hop (the thing we're actually looking for)
//   - Safe: landing domain matches the original (no external redirect)
//   - Error: couldn't even make a determination (DNS fail, TLS error, timeout)
//
// Error is NOT Safe. In a security tool, "we don't know" is never the same as
// "nothing happened." We count and report errors separately.
type Verdict int

const (
	Vuln  Verdict = iota // Landing domain differs from original — potential open redirect
	Safe                 // Landing domain matches original — no issue
	Error                // Network/DNS/TLS failure — could not determine
)

// DetectionResult holds the outcome of checking one mutated URL.
// Fields are additive — the base check fills in OriginalURL through Verdict,
// and the enhanced checks fill in IPRedirect, Credentials, and EscapedHop.
type DetectionResult struct {
	OriginalURL  string           // Unmodified source URL this probe came from.
	Param        string           // Query parameter that was replaced.
	Payload      string           // Raw payload string injected into Param.
	MutatedURL   string           // Full request URL actually sent on the wire.
	RedirectURL  string           // Last hop before final
	FinalURL     string           // Where we actually landed
	Status       int              // HTTP status from the redirect chain
	Verdict      Verdict          // Vuln, Safe, or Error — see type docs above.
	Chain        []httpclient.Hop // Every redirect hop observed during Follow.
	ErrorMessage string           // Human-readable failure reason when Verdict == Error.

	// Enhanced detection fields — populated by the classification pipeline.

	// IPRedirect is non-zero when the final URL is an IP literal.
	// InternalIP/Loopback are SSRF-relevant; ExternalIP is still a domain escape.
	IPRedirect IPRedirectType

	// Credentials is non-empty when the final URL contains userinfo
	// (e.g. "https://example.com@evil.com/"). This is a classic bypass
	// technique — the browser shows "example.com" but requests go to evil.com.
	Credentials string

	// EscapedHop is the index of the first chain hop that escapes the
	// original domain. -1 means no hop escaped (safe or all hops same domain).
	// This pinpoints where the redirect went wrong, not just the final result.
	EscapedHop int
}

// Check runs a single mutation probe and classifies the result.
//
// Classification pipeline:
//  1. Network failure → Error
//  2. Can't parse final domain → Error (not Safe — we don't know)
//  3. Domain comparison: origDomain vs finalDomain
//  4. IP redirect check: is the final URL an IP literal?
//  5. Credential check: does the final URL have userinfo?
//  6. Chain analysis: which hop first escaped the domain?
//  7. Baseline filter: is this a known legitimate bounce?
//  8. Influence gate: did the payload actually cause the landing?
//
// The baseline parameter is a set of domains that the target normally
// redirects to (SSO, auth, geo). If a mutation lands on one of those,
// it's not a finding — the payload didn't cause the redirect.
func Check(ctx context.Context, client *httpclient.Client, mu MutatedURL, origDomain string, baselineDomains map[string]bool) DetectionResult {
	res := client.Follow(ctx, mu.MutatedURL)

	// Step 1: Network failure → Error
	if res.Error != nil {
		return DetectionResult{
			OriginalURL:  mu.OriginalURL,
			Param:        mu.Param,
			Payload:      mu.Payload,
			MutatedURL:   mu.MutatedURL,
			Verdict:      Error,
			Chain:        res.Chain,
			ErrorMessage: res.Error.Error(),
		}
	}

	// Step 2: Can't determine landing domain → Error (NOT Safe)
	// This matters because "we don't know" is never "nothing happened"
	// in a security tool. Reporting unknown as Safe would be a lie.
	finalDomain, err := GetRegistrableDomain(res.Final)
	if err != nil {
		return DetectionResult{
			OriginalURL:  mu.OriginalURL,
			Param:        mu.Param,
			Payload:      mu.Payload,
			MutatedURL:   mu.MutatedURL,
			FinalURL:     res.Final,
			Verdict:      Error,
			Chain:        res.Chain,
			ErrorMessage: err.Error(),
		}
	}

	// Step 3: Extract the most meaningful status code from the chain.
	// Prefer a 3xx redirect status; fall back to the final response status.
	status := 0
	for _, h := range res.Chain {
		if h.Status >= 300 && h.Status < 400 {
			status = h.Status
			break
		}
	}
	if status == 0 {
		status = res.FinalStatus
	}

	// Step 4: Core domain comparison — did the mutation cause a domain change?
	isInfluenced := !strings.EqualFold(origDomain, finalDomain)

	// Step 5: IP redirect check — is the final URL an IP literal?
	ipType, _ := ClassifyIP(res.Final)

	// Step 6: Credential check — does the final URL contain userinfo?
	_, creds := HasCredentials(res.Final)

	// Step 7: Chain analysis — which hop first escaped the domain?
	escapedHop := AnalyzeChain(res.Chain, origDomain)

	// Step 8: Baseline filter — is this a known legitimate bounce?
	isBaselineBounce := false
	if baselineDomains != nil {
		isBaselineBounce = baselineDomains[finalDomain]
	}

	// Step 9: Payload-influence gate — did OUR input cause this redirect?
	//
	// The domain comparison (step 4) only proves the landing domain differs
	// from the original. It can't tell "our payload caused the hop" from
	// "this site bounces every request to its CDN/SSO regardless of input".
	// Requiring a traceable connection between payload and landing kills the
	// most common false-positive class in open-redirect scanning.
	payloadDriven := InfluencedByPayload(mu.Payload, res.Final, res.Chain)

	// Final verdict: domain changed AND not a baseline bounce AND the landing
	// traces back to our payload → Vuln
	verdict := Safe
	if isInfluenced && !isBaselineBounce && payloadDriven {
		verdict = Vuln
	}

	var redirectURL string
	if len(res.Chain) > 0 {
		redirectURL = res.Chain[len(res.Chain)-1].URL
	}

	return DetectionResult{
		OriginalURL: mu.OriginalURL,
		Param:       mu.Param,
		Payload:     mu.Payload,
		MutatedURL:  mu.MutatedURL,
		RedirectURL: redirectURL,
		FinalURL:    res.Final,
		Status:      status,
		Verdict:     verdict,
		Chain:       res.Chain,
		IPRedirect:  ipType,
		Credentials: creds,
		EscapedHop:  escapedHop,
	}
}
