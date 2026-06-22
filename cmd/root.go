// Package cmd defines the secaudit CLI surface.
package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "secaudit",
	Short: "Passive domain reconnaissance with a terminal report",
	Long: "secaudit runs passive recon checks (DNS, TLS, RDAP, mail/HTTP security " +
		"policy) against a domain and produces a shareable markdown/JSON report.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }

func init() {
	rootCmd.AddCommand(scanCmd, checkersCmd)
}
