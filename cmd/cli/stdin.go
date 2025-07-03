package cli

import (
	"bufio"
	"os"
	"strings"
)

func readFromStdin() []string {
	stat, _ := os.Stdin.Stat()

	if stat.Mode()&os.ModeCharDevice != 0 {
		return nil
	}

	var inURLS []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		if url := strings.TrimSpace(sc.Text()); url != "" {
			inURLS = append(inURLS, url)
		}
	}
	return inURLS
}
