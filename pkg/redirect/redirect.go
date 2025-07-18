package redirect

import (
	"net/http"
)

// Checking if there's an open-redirect
func isOpenRedirect(url string) (string, int, error) {

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("User-Agent", "redirx-scan/1.0")

	var finalURL string
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			finalURL = req.URL.String()
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	finalURL = resp.Request.URL.String()

	return finalURL, resp.StatusCode, nil
}
