package detector

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/yourpwnguy/redirx/internal/httpclient"
	"golang.org/x/net/publicsuffix"
)

// ExtractHost returns the host component (with port) of a URL string.
func ExtractHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

// GetRegistrableDomain returns the eTLD+1 for a URL.
//
// This is the heart of the detection logic — we compare the original
// domain's eTLD+1 against the landing domain's eTLD+1. If they differ,
// the redirect went somewhere external, which is the finding.
//
// We use publicsuffix.EffectiveTLDPlusOne instead of naive string
// comparison because:
//   - "evil-example.com" != "example.com" (different registrable domain)
//   - "sub.example.co.uk" and "example.co.uk" share the same eTLD+1
//   - IP addresses and single-label hosts need special handling
func GetRegistrableDomain(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	host := u.Hostname()

	// Strip trailing dot (FQDN notation: "example.com." -> "example.com")
	host = strings.TrimSuffix(host, ".")

	// IP addresses don't have registrable domains — return as-is.
	// net.ParseIP handles both IPv4 and IPv6, including zone IDs.
	if net.ParseIP(host) != nil {
		return host, nil
	}

	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: if the host contains a dot, treat it as a registrable domain.
		// This handles cases where publicsuffix doesn't recognize the TLD
		// (e.g. custom TLDs, internal domains).
		if strings.Contains(host, ".") {
			return strings.ToLower(host), nil
		}
		return "", fmt.Errorf("cannot determine registrable domain for %q: %w", host, err)
	}

	d = strings.TrimSuffix(d, ".")
	return strings.ToLower(d), nil
}

// NormalizeURL adds a scheme if missing so url.Parse works correctly.
// Without a scheme, "example.com/path" would be parsed as a relative
// path with host "example.com" instead of what the user intended.
func NormalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if !strings.Contains(raw, "://") {
		return "http://" + raw
	}
	return raw
}

// IPRedirectType classifies an IP-based redirect. When a payload causes
// a redirect to an IP literal instead of a domain, the type matters:
//
//   - InternalIP: RFC 1918/4193 ranges (10.x, 172.16-31.x, 192.168.x, fd00::/8)
//     These are typically SSRF targets — the scanner found a way to make the
//     server request an internal resource.
//   - Loopback: 127.x.x.x, ::1, 0.0.0.0 — the payload made the server hit itself.
//     Classic SSRF primitive.
//   - ExternalIP: Any other IP literal. Still suspicious — the redirect escaped
//     the domain entirely, just to an IP instead of a hostname.
type IPRedirectType int

const (
	NoIPRedirect IPRedirectType = iota // Final URL is not an IP literal
	InternalIP                         // RFC 1918/4193 range
	Loopback                           // 127.x.x.x, ::1, 0.0.0.0
	ExternalIP                         // Public IP literal
)

// ClassifyIP checks if a URL points to an IP literal and classifies it.
// Returns the type and the raw IP string. Non-IP hosts return NoIPRedirect.
func ClassifyIP(rawURL string) (IPRedirectType, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return NoIPRedirect, ""
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return NoIPRedirect, ""
	}

	// Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1) to plain IPv4
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Check loopback first (127.x.x.x, ::1, 0.0.0.0)
	if ip.IsLoopback() {
		return Loopback, host
	}

	// 0.0.0.0 and :: — unspecified, treat as loopback-adjacent
	if ip.IsUnspecified() {
		return Loopback, host
	}

	// Check link-local (169.254.x.x, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return InternalIP, host
	}

	// Check RFC 1918 / RFC 4193 private ranges
	if ip.IsPrivate() {
		return InternalIP, host
	}

	return ExternalIP, host
}

// HasCredentials checks if a URL contains embedded credentials
// (userinfo). This is a classic open-redirect bypass: the attacker
// injects "https://example.com@evil.com/" where "example.com" looks
// legitimate in the browser address bar but the actual request goes
// to evil.com.
//
// Returns true + the userinfo string if credentials are present.
func HasCredentials(rawURL string) (bool, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, ""
	}
	if u.User == nil {
		return false, ""
	}
	return true, u.User.String()
}

// AnalyzeChain checks each hop in a redirect chain for domain escapes.
// Returns the index of the first hop that escapes the original domain,
// or -1 if no hop escapes. This is useful for pinpointing exactly where
// the redirect went wrong — not just "the final URL is evil" but
// "hop #3 is where it escaped."
//
// The original domain is compared as eTLD+1, so subdomain changes
// within the same registrable domain are not flagged.
func AnalyzeChain(chain []httpclient.Hop, origDomain string) int {
	for i, hop := range chain {
		hopDomain, err := GetRegistrableDomain(hop.URL)
		if err != nil {
			continue // Can't parse, skip this hop
		}
		// IP literals always count as escapes if original is a domain
		if net.ParseIP(hopDomain) != nil {
			if net.ParseIP(origDomain) == nil {
				return i
			}
		}
		if !strings.EqualFold(origDomain, hopDomain) {
			return i
		}
	}
	return -1
}
