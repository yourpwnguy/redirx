// Package cli implements the RedirX command-line interface.
//
// It handles flag parsing, stdin detection, config assembly, and signal
// handling. The actual scan logic lives in internal/scanner — this package
// is just the ergonomic shell around it.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/yourpwnguy/redirx/internal/config"
	"github.com/yourpwnguy/redirx/internal/output"
	"github.com/yourpwnguy/redirx/internal/payload"
	"github.com/yourpwnguy/redirx/internal/scanner"
)

// version is the CLI release identifier. The default "dev" marks source
// builds; release pipelines override it at link time:
//
//	go build -ldflags "-X github.com/yourpwnguy/redirx/cmd/cli.version=v0.2.0"
//
// Single source of truth for the banner, --version output, and User-Agent.
var version = "dev"

// displayVersion normalizes the raw version string for display:
//   - bare semver from release pipelines ("0.2.0")  → "v0.2.0"
//   - already-prefixed values ("v0.2.0")             → unchanged
//   - dev fallbacks ("dev", "ac1498e-dirty")         → unchanged
//
// A commit hash with a bolted-on "v" looks like a typo, so only actual
// semantic versions earn the prefix.
func displayVersion() string {
	if strings.HasPrefix(version, "v") {
		return version
	}
	if isSemver(version) {
		return "v" + version
	}
	return version
}

// isSemver reports whether s looks like MAJOR.MINOR[.PATCH] with optional
// pre-release/build suffixes. Intentionally loose — this only gates the
// display prefix, not any parsing.
func isSemver(s string) bool {
	core := s
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || !isDigits(p) {
			return false
		}
	}
	return true
}

// isDigits reports whether s consists solely of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Flag storage variables — bound to cobra flags in init() and read in
// RunE when assembling the Config. One variable per flag, package-level
// because cobra's binding API requires stable addresses.
var (
	flagURLs        []string // -u: direct URL inputs (repeatable)
	flagURLList     string   // -l: path to a newline-separated URL file
	flagPayloads    string   // -p: custom payload file; empty = built-in set
	flagConcurrency int      // -c: max parallel probes
	flagTimeout     int      // -t: per-request timeout, seconds
	flagMaxRedirect int      // hop cap per probe
	flagMethod      string   // -X: HTTP verb for probes
	flagProxy       string   // optional proxy URL for traffic inspection
	flagHeaders     []string // -H: raw "Key: Value" headers (repeatable)
	flagVulnOnly    bool     // -v: suppress SAFE/ERR result lines
	flagBaseline    bool     // control requests to filter legit bounces
	flagOutput      string   // -o: output file path (JSON mode)
	flagJSON        bool     // -j: emit JSON lines instead of console output
	flagQuiet       bool     // -q: no banner, no live counter
)

// banner prints the startup header. Suppressed in quiet or JSON mode.
func banner(quiet, jsonOut bool) {
	if quiet || jsonOut {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		color.New(color.FgWhite, color.Bold, color.Italic).Sprint("REDIRX"),
		color.New(color.FgHiBlack).Sprint(displayVersion()+" — open redirect scanner with mutation engine"))
	fmt.Fprintln(os.Stderr)
}

// rootCmd is the single cobra command RedirX exposes. SilenceErrors/
// SilenceUsage are set so Execute() owns error presentation — cobra's
// default usage dump on every failure is noise, not help.
var rootCmd = &cobra.Command{
	Use:     "redirx [flags]",
	Version: displayVersion(),
	Short:   "Open redirect vulnerability scanner with mutation engine",
	Long: `RedirX scans URLs for open-redirect vulnerabilities by mutating query
parameters with a curated payload list, following redirects, and detecting
when the landing domain differs from the target's registrable domain.

Supports baseline control requests to reduce false positives from legitimate
SSO/auth/geo-redirects.`,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		banner(flagQuiet, flagJSON)

		// Assemble the config from CLI flags. This is the single place where
		// flag values get transformed into the Config struct — scanner never
		// touches cobra or flags directly.
		cfg := config.Config{
			URLs:        flagURLs,
			URLList:     flagURLList,
			Concurrency: flagConcurrency,
			Timeout:     time.Duration(flagTimeout) * time.Second,
			MaxRedirect: flagMaxRedirect,
			Method:      flagMethod,
			Proxy:       flagProxy,
			Headers:     parseHeaders(flagHeaders),
			VulnOnly:    flagVulnOnly,
			Baseline:    flagBaseline,
			Output:      flagOutput,
			JSONOutput:  flagJSON,
			Quiet:       flagQuiet,
			UserAgent:   "redirx-scan/" + version,
		}

		if flagPayloads != "" {
			p, err := payload.Load(flagPayloads)
			if err != nil {
				return fmt.Errorf("load payloads: %w", err)
			}
			cfg.Payloads = p
		}

		// Merge stdin URLs — silently returns nil if not piped.
		stdinURLs := ReadFromStdin()
		cfg.URLs = append(cfg.URLs, stdinURLs...)

		if len(cfg.URLs) == 0 && cfg.URLList == "" {
			return fmt.Errorf("no URLs provided (use -u, -l, or pipe via stdin)")
		}

		// Ctrl-C cancels the context, which cancels in-flight HTTP requests,
		// which makes workers exit cleanly. No orphaned goroutines.
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		// Wire up the output backend. Console for humans, JSON for pipelines.
		var writer output.Writer
		if cfg.JSONOutput {
			w, err := output.NewJSONWriter(cfg.Output)
			if err != nil {
				return err
			}
			// Best-effort flush; nothing actionable if the file handle is
			// already failing at this point.
			defer func() { _ = w.Close() }()
			writer = w
		} else {
			writer = output.NewConsoleWriter(cfg.VulnOnly, cfg.Quiet)
		}

		return scanner.Run(ctx, cfg, writer)
	},
}

// parseHeaders converts "Key: Value" strings into a map.
// Uses strings.Cut instead of manual byte scanning — cleaner and idiomatic.
func parseHeaders(raw []string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	headers := make(map[string]string, len(raw))
	for _, h := range raw {
		key, val, ok := strings.Cut(h, ":")
		if !ok {
			continue // skip malformed headers silently
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key != "" {
			headers[key] = val
		}
	}
	return headers
}

// init binds flag variables, orders help output, and installs the custom
// help/usage/version renderers. Flag registration order here defines the
// order groups render in renderHelp — keep them grouped by concern.
func init() {
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false

	f := rootCmd.Flags()

	f.StringSliceVarP(&flagURLs, "url", "u", nil, "URL(s) to scan (repeatable)")
	f.StringVarP(&flagURLList, "url-list", "l", "", "File containing URLs, one per line")
	f.StringVarP(&flagPayloads, "payloads", "p", "", "Custom payload file (one per line, # comments)")
	f.IntVarP(&flagConcurrency, "concurrency", "c", 5, "Max concurrent requests")
	f.IntVarP(&flagTimeout, "timeout", "t", 10, "HTTP request timeout in seconds")
	f.IntVar(&flagMaxRedirect, "max-redirects", 10, "Max redirects to follow")
	f.StringVarP(&flagMethod, "method", "X", "HEAD", "HTTP method (HEAD, GET, ...)")
	f.StringVar(&flagProxy, "proxy", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")
	f.StringSliceVarP(&flagHeaders, "header", "H", nil, "Custom headers (Key: Value, repeatable)")
	f.BoolVarP(&flagVulnOnly, "vuln-only", "v", false, "Show only vulnerable results")
	f.BoolVar(&flagBaseline, "baseline", false, "Control requests to filter legit bounces (fewer false positives)")
	f.StringVarP(&flagOutput, "output", "o", "", "Output file path")
	f.BoolVarP(&flagJSON, "json", "j", false, "Output results as JSON lines")
	f.BoolVarP(&flagQuiet, "quiet", "q", false, "Suppress banner and progress output")

	rootCmd.SetHelpFunc(renderHelp)
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(os.Stderr, "%s\n",
			color.New(color.FgWhite, color.Bold).Sprint("Usage:"))
		fmt.Fprintf(os.Stderr, "  redirx [OPTIONS]\n\nSee --help for full usage and examples.\n")
		return nil
	})
	// displayVersion() (set below on the Command) already carries the "v".
	rootCmd.SetVersionTemplate(color.New(color.FgWhite, color.Bold).Sprint("REDIRX {{.Version}}\n"))
}

// renderHelp prints a cargo-style help screen: short description, usage
// line, flags grouped by purpose, and worked examples. Colors come from
// fatih/color, so they degrade to plain text when piped.
func renderHelp(cmd *cobra.Command, args []string) {
	w := cmd.OutOrStdout()

	header := func(title string) {
		fmt.Fprintf(w, "\n%s\n", color.New(color.FgWhite, color.Bold).Sprint(title))
	}
	dim := color.New(color.FgHiBlack).SprintFunc()
	prompt := color.New(color.FgGreen, color.Bold).SprintFunc()

	title := color.New(color.FgWhite, color.Bold, color.Italic).Sprint("REDIRX")
	fmt.Fprintf(w, "\n%s %s %s\n",
		title,
		color.New(color.FgWhite, color.Bold).Sprint(displayVersion()),
		dim("— open redirect scanner with a mutation engine"))

	fmt.Fprintf(w, "\nMutates every query parameter of the target URL(s) with redirect payloads,\n"+
		"follows each hop, and reports when the landing domain escapes the target's\n"+
		"registrable domain AND traces back to the injected payload.\n")

	header("Usage:")
	fmt.Fprintf(w, "  %s [OPTIONS]\n", color.New(color.FgGreen, color.Bold).Sprint("redirx"))

	type group struct {
		name  string
		flags []string
	}
	groups := []group{
		{"Targeting", []string{"url", "url-list", "payloads"}},
		{"Engine", []string{"concurrency", "baseline", "max-redirects"}},
		{"HTTP", []string{"timeout", "method", "proxy", "header"}},
		{"Output", []string{"vuln-only", "output", "json", "quiet"}},
	}

	header("Options:")
	for _, g := range groups {
		fmt.Fprintf(w, "  %s\n", dim(g.name+":"))
		fs := pflag.NewFlagSet("", pflag.ContinueOnError)
		fs.SortFlags = false
		for _, name := range g.flags {
			if fl := cmd.Flags().Lookup(name); fl != nil {
				fs.AddFlag(fl)
			}
		}
		fmt.Fprint(w, indentUsages(fs.FlagUsages(), "    "))
	}

	header("Examples:")
	examples := []struct{ cmd, note string }{
		{"redirx -u \"https://target.com/redirect?to=\"", "scan one URL"},
		{"cat recon-urls.txt | redirx -c 50 -v", "pipe URLs, 50 workers, vulns only"},
		{"redirx -l targets.txt --baseline", "control requests to cut false positives"},
		{"redirx -u \"$U\" -j -o findings.json", "JSON lines to file for pipelines"},
		{"redirx -u \"$U\" --proxy http://127.0.0.1:8080", "route through Burp/collaborator"},
	}
	for _, ex := range examples {
		fmt.Fprintf(w, "  %s  %s\n", prompt("$ "+ex.cmd), dim("# "+ex.note))
	}

	fmt.Fprintf(w, "\nExit codes: 0 = scan ran, 1 = bad input or config.\n")
	fmt.Fprintf(w, "VULN findings also carry tags for IP redirects (SSRF), userinfo tricks,\nand chain escapes.\n\n")
}

// indentUsages re-indents pflag's aligned flag usage block.
func indentUsages(usages, prefix string) string {
	if usages == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(usages, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}

// Execute runs the root command and terminates the process on failure.
//
// Exit-code contract: 0 = scan completed (findings don't affect it),
// 1 = bad input/config or runtime error. Errors are printed in red to
// stderr — stdout stays reserved for machine-readable output.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31merror:\033[0m %v\n", err)
		os.Exit(1)
	}
}
