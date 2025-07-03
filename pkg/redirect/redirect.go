package redirect

import (
	"net/http"
)

// Checking if there's an open-redirect
func isOpenRedirect(u string) (string, int, error) {

	req, err := http.NewRequest(http.MethodHead, u, nil)
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("User-Agent", "redirx-scan/1.0")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	location, _ := resp.Location()
	if location == nil {
		return "", resp.StatusCode, nil
	}

	return location.String(), resp.StatusCode, nil
}
