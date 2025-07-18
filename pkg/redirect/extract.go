package redirect

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Extract Host from an URL
func extractHost(URL string) (string, error) {
	p, err := url.Parse(URL)
	if err != nil {
		return "", err
	}
	return p.Host, nil
}

func getRegistrableDomain(URL string) (string, error) {
	p, err := url.Parse(URL)
	if err != nil {
		return "", err
	}
	host := p.Hostname()

	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		if strings.Contains(host, ".") {
			return host, nil
		}
		return "", fmt.Errorf("Could not get registrable domain")
	}
	return d, nil
}
