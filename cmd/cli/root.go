package cli

import (
	"github.com/spf13/cobra"
	"github.com/yourpwnguy/redirx/pkg/globals"
	"github.com/yourpwnguy/redirx/pkg/scanner"
	"golang.org/x/exp/slices"
)

var cfg = globals.Config{}

var rootCmd = &cobra.Command{
	Use:           "redirx",
	Short:         "The Fastest Open-Redirect Checker",
	Long:          "Scans one or many domains for open‑redirect vulnerabilities.",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		urls := slices.Clone(cfg.URLS)

		if len(urls) == 0 {
			inURLS := readFromStdin()
			urls = append(urls, inURLS...)
		}

		cfg.URLS = urls
		return scanner.RunScan(cfg)
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(
		&cfg.URLS,
		"url",
		"u",
		nil,
		"Url(s) to scan (repeatable)",
	)

	rootCmd.PersistentFlags().StringVarP(
		&cfg.URLSList,
		"url-list",
		"l",
		"",
		"Path to file containing urls (one per line)",
	)

	rootCmd.PersistentFlags().IntSliceVarP(
		&cfg.MatchCodes,
		"mcode",
		"m",
		[]int{},
		"Status Codes to match",
	)
	rootCmd.PersistentFlags().BoolVarP(
		&cfg.VulnOnly,
		"vuln",
		"v",
		false,
		"Show only vulnerable results (BUG) and suppress SAFE lines",
	)

	rootCmd.PersistentFlags().Int64VarP(
		&cfg.Concurrency,
		"rate",
		"r",
		5,
		"Max concurrent requests (rate-limit)",
	)
	rootCmd.PersistentFlags().StringVarP(
		&cfg.PayloadList,
		"payloads",
		"p",
		"",
		"Path to file containing payloads",
	)
}
