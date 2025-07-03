package redirect

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/yourpwnguy/redirx/pkg/globals"
	"github.com/yourpwnguy/redirx/pkg/stats"
	"golang.org/x/sync/semaphore"
)

// Mutate the URLs and Check if there's an redirect
func MutateAndCheck(
	ctx context.Context,
	sem *semaphore.Weighted,
	rawURL string,
	cfg *globals.Config,
	payloads []string,
	out chan<- string,
	cntr *stats.Counters,
) ([]string, error) {

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	q := parsed.Query()
	if len(q) == 0 {
		return nil, nil
	}

	// Saving original Host for later use
	origHost := parsed.Host

	var (
		mu   sync.Mutex
		hits []string
		wg   sync.WaitGroup
	)

	for param := range q {
		for _, payload := range payloads {

			if err := sem.Acquire(ctx, 1); err != nil {
				return nil, err
			}

			wg.Add(1)
			go func(param, payload string) {
				defer sem.Release(1)
				defer wg.Done()

				cntr.IncMut()

				clone := *parsed
				cloneQ := clone.Query()
				cloneQ.Set(param, payload)
				clone.RawQuery = cloneQ.Encode()
				testURL := clone.String()

				redirURL, sc, err := isOpenRedirect(testURL)
				if err != nil {
					cntr.IncSafe()
					return
				}

				host := extractHost(redirURL)

				isVuln := host != "" && !strings.EqualFold(stripPort(origHost), stripPort(host))
				toShow := matchCodes(sc, cfg.MatchCodes)

				if isVuln {
					cntr.IncBug()
					mu.Lock()
					hits = append(hits, testURL)
					mu.Unlock()

					if toShow {
						out <- fmt.Sprintf(
							"[%s] %s => %s %s [%s]",
							globals.ColorStatus(sc),
							globals.RedBold("BUG"),
							highlightParam(&clone, param),
							globals.REDIRX,
							globals.PurpleBold(redirURL),
						)
					}
				} else {
					cntr.IncSafe()
					if !cfg.VulnOnly && toShow {
						out <- fmt.Sprintf(
							"[%s] %s => %s",
							globals.ColorStatus(sc),
							globals.CustomBlue("SAFE"),
							testURL,
						)
					}
				}
				out <- ""

			}(param, payload)
		}
	}

	wg.Wait()
	return hits, nil
}
