package redirect

import (
	"net"
	"net/url"
)

// Extract Host from an URL
func extractHost(URL string) string {
	h, err := url.Parse(URL)
	if err != nil {
		return ""
	}
	return h.Host
}

// Strip Port from an HOST:PORT.
// Returns HOST
func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
