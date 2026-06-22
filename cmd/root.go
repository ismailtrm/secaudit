// Package cmd defines the secaudit CLI surface.
package cmd

import "github.com/spf13/cobra"

var (
	flagOwnership string
	flagMode      string
	flagNoTUI     bool
	flagFormat    string
	flagOutDir    string
)

var rootCmd = &cobra.Command{
	Use:   "secaudit [domain]",
	Short: "Passive domain reconnaissance with a terminal report",
	Long: "secaudit runs passive recon checks (DNS, TLS, RDAP, mail/HTTP security " +
		"policy, CT-log subdomains) against a domain.\n\n" +
		"Run `secaudit` with no arguments for the full-screen launcher, or " +
		"`secaudit <domain>` to jump straight in. Add --no-tui for a headless report.",
	Args:          cobra.MaximumNArgs(1),
	RunE:          runScan,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() error { return rootCmd.Execute() }

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagOwnership, "ownership", "own", "own|authorized|third-party")
	pf.StringVar(&flagMode, "mode", "passive", "passive|active")
	pf.BoolVar(&flagNoTUI, "no-tui", false, "headless: print summary and write report, no interactive UI")
	pf.StringVar(&flagFormat, "format", "both", "report files to write: both|md|json|none")
	pf.StringVar(&flagOutDir, "out", ".", "directory for report files")

	rootCmd.AddCommand(scanCmd, checkersCmd)
}
