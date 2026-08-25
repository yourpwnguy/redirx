// Command redirx is the compiled entry point of the RedirX open-redirect
// scanner. It exists solely to hand control to the CLI package — all real
// wiring (flags, config, scanner, output) lives there so this file never
// grows logic and never needs testing.
//
// Usage:
//
//	redirx -u "https://target.com/redirect?to=" [flags]
package main

import (
	"github.com/yourpwnguy/redirx/cmd/cli"
)

// main delegates everything to cli.Execute, which owns flag parsing, the
// scan lifecycle, and process exit codes (0 = scan ran, 1 = bad input).
func main() {
	cli.Execute()
}
