package stats

import (
	"fmt"
	"strings"

	"github.com/yourpwnguy/redirx/pkg/globals"
)

const (
	up1     = "\033[1A"
	clearLn = "\033[2K"
	cr      = "\r"
)

func StartUI(c *Counters, in <-chan string) {
	fmt.Println() // 1: blank line
	fmt.Println() // 2: initial counter line

	var buf strings.Builder

	for msg := range in {

		if msg != "" {
			// Only move and print full message if there's one
			buf.WriteString(up1 + clearLn + cr) // to counter
			buf.WriteString(up1 + clearLn + cr) // to gap
			buf.WriteString(msg + "\n")         // print message
			buf.WriteString("\n")               // gap
		} else {
			// No message — just move to counter
			buf.WriteString(up1 + clearLn + cr) // to counter
		}

		printCounter(&buf, c)
		fmt.Print(buf.String())
		buf.Reset()
	}
}

func printCounter(buf *strings.Builder, c *Counters) {
	mut, safe, bug, total := c.Snapshot()

	buf.WriteString(clearLn + cr) // clear counter line first

	// coloured numbers, plain labels
	fmt.Fprintf(buf,
		"%s - %s | %s - %s | %s - %s | %s - %s\n",
		globals.PurpleBold("URLS"),
		globals.BlueBold(total),
		globals.YellowBold("MUTATIONS"),
		globals.GreenBold(mut),
		globals.CustomBlue("SAFE"),
		globals.GreenBold(safe),
		globals.RedBold("BUG"),
		globals.RedBold(bug))
}

func PrintFinalCounter(c *Counters) {

	mut, safe, bug, total := c.Snapshot()
	var buf strings.Builder
	buf.WriteString(up1 + clearLn + cr)

	// Now move up to gap line (line 1), clear it
	buf.WriteString(up1 + clearLn + cr)

	buf.WriteString(clearLn + cr) // clear counter line first
	buf.WriteString("\n")

	// coloured numbers, plain labels
	buf.WriteString(
		fmt.Sprintf("%s - %s | %s - %s | %s - %s | %s - %s\n",
			globals.PurpleBold("URLS"),
			globals.BlueBold(total),
			globals.YellowBold("MUTATIONS"),
			globals.GreenBold(mut),
			globals.CustomBlue("SAFE"),
			globals.GreenBold(safe),
			globals.RedBold("BUG"),
			globals.RedBold(bug),
		),
	)

	fmt.Print(buf.String())
}
