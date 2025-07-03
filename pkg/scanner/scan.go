package scanner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/yourpwnguy/redirx/pkg/globals"
	"github.com/yourpwnguy/redirx/pkg/redirect"
	"github.com/yourpwnguy/redirx/pkg/stats"
	"golang.org/x/sync/semaphore"
)

// Run scan on the given configuration
func RunScan(cfg globals.Config) error {

	// Hide the cursor cause I use arch btw
	fmt.Print("\033[?25l")

	// Ensure cursor is shown again on Ctrl‑C or normal exit
	cleanup := make(chan os.Signal, 1)
	signal.Notify(cleanup, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-cleanup
		fmt.Print("\033[?25h") // show cursor
		os.Exit(1)
	}()
	defer fmt.Print("\033[?25h") // also show on normal return

	URLS, err := collectURLS(cfg)
	if err != nil {
		return err
	}

	var payloads []string
	if cfg.PayloadList == "" {
		payloads = globals.PAYLOADS
	} else {
		payloads, err = collectPayloads(cfg)
		if err != nil {
			return err
		}
	}

	total := uint64(len(URLS))
	cntr := &stats.Counters{Total: total, Safe: 0, Bug: 0, Mut: 0}

	out := make(chan string, 1000)

	if len(URLS) == 0 {
		return fmt.Errorf("nothing to scan, genius !")
	}

	if len(URLS) == 1 {
		println()
	}

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}

	ctx := context.Background()
	sem := semaphore.NewWeighted(cfg.Concurrency)
	var wg sync.WaitGroup

	// UI goroutine
	go stats.StartUI(cntr, out)

	for _, u := range URLS {

		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			_, err := redirect.MutateAndCheck(ctx, sem, url, &cfg, payloads, out, cntr)
			if err != nil {
				cntr.IncSafe()
				fmt.Printf("%s %s: %v\n", globals.ERR, url, err)
				return
			}
		}(u)
	}

	wg.Wait()
	close(out)

	// Printing the last UPDATE
	stats.PrintFinalCounter(cntr)

	return nil
}
