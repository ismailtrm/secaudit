package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/engine"
	"github.com/ismailtrm/secaudit/internal/guard"
	"github.com/ismailtrm/secaudit/internal/report"
	"github.com/ismailtrm/secaudit/internal/tui"
)

var (
	flagOwnership string
	flagMode      string
	flagNoTUI     bool
	flagFormat    string
	flagOutDir    string
)

var scanCmd = &cobra.Command{
	Use:   "scan [domain]",
	Short: "Scan a domain and produce a report",
	Long: "Scan a domain with passive recon checks. With no --no-tui flag it opens " +
		"an interactive wizard and live TUI; the domain argument is optional there.",
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
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
	var domain0 string
	if len(args) == 1 {
		domain0 = args[0]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if flagNoTUI {
		return runHeadlessCmd(ctx, domain0)
	}
	return runTUICmd(ctx, domain0)
}

// runHeadlessCmd resolves parameters from flags (no interactive prompt).
func runHeadlessCmd(ctx context.Context, domain0 string) error {
	if strings.TrimSpace(domain0) == "" {
		return fmt.Errorf("a domain argument is required with --no-tui")
	}
	owner, err := guard.ParseOwnership(flagOwnership)
	if err != nil {
		return err
	}
	mode, err := guard.ParseMode(flagMode)
	if err != nil {
		return err
	}
	if err := guard.Authorize(owner, mode); err != nil {
		return err
	}
	t, err := checker.NewTarget(domain0, owner)
	if err != nil {
		return err
	}
	checkers := checker.ByMode(mode)
	if len(checkers) == 0 {
		return fmt.Errorf("no checkers registered for mode %s", mode)
	}

	started := time.Now()
	var results []checker.Result
	for res := range engine.Run(ctx, t, checkers, engine.Options{}) {
		results = append(results, res)
	}
	rep := report.Build(t, results, started)
	fmt.Println(rep.Text())
	paths, err := writeReportFiles(rep, t)
	for _, p := range paths {
		fmt.Println("wrote", p)
	}
	return err
}

// runTUICmd opens the wizard, then the live scan TUI.
func runTUICmd(ctx context.Context, domain0 string) error {
	wiz, err := tui.RunWizard(ctx, domain0, flagOwnership, flagMode)
	if err != nil {
		return err
	}
	t, err := checker.NewTarget(wiz.Domain, wiz.Ownership)
	if err != nil {
		return err
	}
	checkers := checker.ByMode(wiz.Mode)
	if len(checkers) == 0 {
		return fmt.Errorf("no checkers registered for mode %s", wiz.Mode)
	}
	write := func(rep report.Report) (string, error) {
		paths, err := writeReportFiles(rep, t)
		if err != nil {
			return "", err
		}
		if len(paths) == 0 {
			return "nothing written (--format none)", nil
		}
		return "wrote " + strings.Join(paths, ", "), nil
	}
	return tui.RunScan(ctx, t, checkers, write)
}

// writeReportFiles writes the report to disk per --format/--out and returns the
// paths written.
func writeReportFiles(rep report.Report, t checker.Target) ([]string, error) {
	if flagFormat == "none" {
		return nil, nil
	}
	ts := rep.StartedAt.Format("20060102-150405")
	base := filepath.Join(flagOutDir, fmt.Sprintf("report-%s-%s", t.Domain, ts))

	var paths []string
	if flagFormat == "both" || flagFormat == "md" {
		p := base + ".md"
		if err := os.WriteFile(p, []byte(rep.Markdown()), 0o644); err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}
	if flagFormat == "both" || flagFormat == "json" {
		p := base + ".json"
		j, err := rep.JSON()
		if err != nil {
			return paths, err
		}
		if err := os.WriteFile(p, j, 0o644); err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}
