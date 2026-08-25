package detector

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/yourpwnguy/redirx/internal/httpclient"
)

// This file implements the payload-influence gate: the check that separates
// "the target redirected because of OUR input" from "the target redirects
// everything to its CDN regardless of input".
//
// Why it exists: sites like news.playtika.com bounce every thumbnail request
// to filecache.mediaroom.com no matter what the query string contains. The
// domain comparison alone flags that as a Vuln — but our payload had zero
// influence on the landing URL. That's a false positive, and it's the single
// most common one in open-redirect scanning.
//
// The gate runs AFTER the domain comparison. It only ever downgrades a Vuln,
// never upgrades a Safe, and it fails open: when we can't extract any host
// identity from a payload (pure path traversal like `/..%2f`), we keep the
// Vuln rather than silently dropping findings.

var (
	// domainPattern matches dotted host names inside arbitrary payload
	// soup — "example.com@google.com/%2f.." yields example.com and
	// google.com in one pass.
	domainPattern = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}`)

	// ipv4Pattern finds dotted-quad candidates for IP-literal payloads.
	ipv4Pattern = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
)

// PayloadIdentities extracts the set of host identities (registrable
// domains and IPv4 literals) that a payload tries to steer the redirect
// toward.
//
// Payloads are hostile strings by design: percent-encoded ("https://" as
// %68%74%74%70%3a...), glued with control characters ("/\t/example.com"),
// userinfo-confused ("example.com@google.com"), or backslash-mangled.
// So we decode iteratively before scanning for host-shaped tokens.
//
// The returned set contains eTLD+1 forms ("www.google.com" collapses to
// "google.com") so it can be compared directly against landing domains.
func PayloadIdentities(payload string) map[string]bool {
	out := make(map[string]bool)
	if payload == "" {
		return out
	}

	decoded := decodeIteratively(payload)

	for _, m := range domainPattern.FindAllString(decoded, -1) {
		if d, err := GetRegistrableDomain("http://" + m); err == nil {
			out[d] = true
		}
	}

	for _, m := range ipv4Pattern.FindAllString(decoded, -1) {
		if net.ParseIP(m) != nil {
			out[m] = true // GetRegistrableDomain returns IPs unchanged
		}
	}

	return out
}

// InfluencedByPayload reports whether the observed redirect chain (or final
// landing URL) could plausibly have been caused by the injected payload.
//
// Two independent signals count as influence:
//
//  1. Identity match — any registrable domain/IP extracted from the payload
//     appears among the landing identities of the chain hops or final URL.
//     Handles decoded-and-used payloads: inject "%68%74%74%70..." → server
//     decodes it → lands on google.com.
//
//  2. Literal echo — the raw or decoded payload string appears verbatim in
//     any hop URL. Handles servers that reflect the parameter into the
//     Location header without decoding: inject "//evil.example" → Location
//     contains "//evil.example".
//
// Fail-open rule: if the payload carries no extractable identity (pure
// traversal like "/..%2f"), we return true — we have no way to disprove
// influence and must not swallow findings we can't reason about.
func InfluencedByPayload(payload, finalURL string, chain []httpclient.Hop) bool {
	identities := PayloadIdentities(payload)
	if len(identities) == 0 {
		return true // fail open — nothing to verify against
	}

	hops := make([]string, 0, len(chain)+1)
	for _, h := range chain {
		if h.URL != "" {
			hops = append(hops, h.URL)
		}
	}
	if finalURL != "" {
		hops = append(hops, finalURL)
	}

	// Signal 1: semantic identity match between payload hosts and landing hosts.
	landing := make(map[string]bool, len(hops))
	for _, u := range hops {
		if d, err := GetRegistrableDomain(u); err == nil {
			landing[d] = true
		}
	}
	for id := range identities {
		if landing[id] {
			return true
		}
	}

	// Signal 2: literal echo of the raw or decoded payload inside any hop URL.
	lowerPayload := strings.ToLower(payload)
	lowerDecoded := strings.ToLower(decodeIteratively(payload))
	for _, h := range hops {
		lh := strings.ToLower(h)
		if strings.Contains(lh, lowerPayload) || strings.Contains(lh, lowerDecoded) {
			return true
		}
	}

	return false
}

// decodeIteratively percent-decodes up to three times, stopping when the
// string stabilizes or decoding fails. Three rounds covers single encoding,
// double encoding (%2568...), and the practical maximum seen in bypass lists.
func decodeIteratively(s string) string {
	cur := s
	for i := 0; i < 3; i++ {
		next, err := url.QueryUnescape(cur)
		if err != nil || next == cur {
			break
		}
		cur = next
	}
	return cur
}
