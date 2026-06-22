package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/engine"
	"github.com/ismailtrm/secaudit/internal/guard"
	"github.com/ismailtrm/secaudit/internal/report"
)

var (
	flagOwnership string
	flagMode      string
	flagNoTUI     bool
	flagFormat    string
	flagOutDir    string
)

var scanCmd = &cobra.Command{
	Use:   "scan <domain>",
	Short: "Scan a domain and produce a report",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	f := scanCmd.Flags()
	f.StringVar(&flagOwnership, "ownership", "own", "own|authorized|third-party")
	f.StringVar(&flagMode, "mode", "passive", "passive|active")
	f.BoolVar(&flagNoTUI, "no-tui", false, "headless: print summary and write report, no interactive UI")
	f.StringVar(&flagFormat, "format", "both", "report files to write: both|md|json|none")
	f.StringVar(&flagOutDir, "out", ".", "directory for report files")
}

func runScan(cmd *cobra.Command, args []string) error {
	owner, err := guard.ParseOwnership(flagOwnership)
	if err != nil {
		return err
	}
	mode, err := guard.ParseMode(flagMode)
	if err != nil {
		return err
	}
	// Guardrail enforced here too, not only in the (future) wizard.
	if err := guard.Authorize(owner, mode); err != nil {
		return err
	}

	t, err := checker.NewTarget(args[0], owner)
	if err != nil {
		return err
	}

	checkers := checker.ByMode(mode)
	if len(checkers) == 0 {
		return fmt.Errorf("no checkers registered for mode %s", mode)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// TUI is the default once implemented; until then everything is headless.
	return runHeadless(ctx, t, checkers)
}

func runHeadless(ctx context.Context, t checker.Target, checkers []checker.Checker) error {
	started := time.Now()
	var results []checker.Result
	for res := range engine.Run(ctx, t, checkers, engine.Options{}) {
		results = append(results, res)
	}
	rep := report.Build(t, results, started)
	fmt.Println(rep.Text())
	return writeReports(rep, t)
}

func writeReports(rep report.Report, t checker.Target) error {
	if flagFormat == "none" {
		return nil
	}
	ts := rep.StartedAt.Format("20060102-150405")
	base := filepath.Join(flagOutDir, fmt.Sprintf("report-%s-%s", t.Domain, ts))

	if flagFormat == "both" || flagFormat == "md" {
		if err := os.WriteFile(base+".md", []byte(rep.Markdown()), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", base+".md")
	}
	if flagFormat == "both" || flagFormat == "json" {
		j, err := rep.JSON()
		if err != nil {
			return err
		}
		if err := os.WriteFile(base+".json", j, 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", base+".json")
	}
	return nil
}
