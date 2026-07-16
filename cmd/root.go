// Package cmd defines the secaudit CLI surface.
package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ismailtrm/secaudit/internal/checker"
)

var (
	flagOwnership string
	flagMode      string
	flagNoTUI     bool
	flagFormat    string
	flagOutDir    string
	flagFailOn    string
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
	pf.StringVar(&flagFailOn, "fail-on", "none", "headless CI gate: exit 2 if a finding at or above this severity is found: none|info|low|medium|high|critical")

	rootCmd.AddCommand(scanCmd, checkersCmd)
}

// parseFailOn maps a --fail-on flag value to a checker.Severity threshold.
// ok is false when the gate is disabled ("none"), in which case sev is unused.
func parseFailOn(s string) (sev checker.Severity, ok bool, err error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return 0, false, nil
	case "info":
		return checker.SevInfo, true, nil
	case "low":
		return checker.SevLow, true, nil
	case "medium":
		return checker.SevMedium, true, nil
	case "high":
		return checker.SevHigh, true, nil
	case "critical":
		return checker.SevCritical, true, nil
	default:
		return 0, false, fmt.Errorf("invalid --fail-on value %q: must be one of none|info|low|medium|high|critical", s)
	}
}
