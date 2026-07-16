package cmd

import (
	"context"
	"errors"
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

// ErrThresholdExceeded is returned (wrapped) by runHeadless when --fail-on is
// set and the report contains a finding at or above the threshold severity.
// main.go checks errors.Is against this sentinel to exit 2 without printing
// the "secaudit:" operational-error prefix: a threshold hit is an intended CI
// signal, not a failure of the tool itself.
var ErrThresholdExceeded = errors.New("fail-on threshold exceeded")

// scanCmd is an explicit alias for the bare `secaudit [domain]` form.
var scanCmd = &cobra.Command{
	Use:   "scan [domain]",
	Short: "Scan a domain (same as `secaudit [domain]`)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	var domain0 string
	if len(args) == 1 {
		domain0 = args[0]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if flagNoTUI {
		return runHeadless(ctx, domain0)
	}
	return tui.RunInteractive(ctx, domain0, flagOwnership, flagMode, writeReport)
}

// runHeadless resolves parameters from flags and prints/writes a report with no UI.
func runHeadless(ctx context.Context, domain0 string) error {
	if strings.TrimSpace(domain0) == "" {
		return fmt.Errorf("a domain argument is required with --no-tui")
	}
	failSev, failEnabled, err := parseFailOn(flagFailOn)
	if err != nil {
		return err
	}
	streamToStdout := flagOutDir == "-"
	if streamToStdout && flagFormat != "json" && flagFormat != "md" {
		return fmt.Errorf("--out - requires --format json or --format md, got --format %s", flagFormat)
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
	opts := engine.Options{}
	if mode == checker.Active {
		opts.ActiveTimeout = 15 * time.Minute
	}
	var results []checker.Result
	for ev := range engine.Run(ctx, t, checkers, opts) {
		if ev.Result != nil {
			results = append(results, *ev.Result)
		}
	}
	rep := report.Build(t, results, started)

	if streamToStdout {
		var doc []byte
		if flagFormat == "json" {
			doc, err = rep.JSON()
			if err != nil {
				return fmt.Errorf("failed to render json report: %w", err)
			}
		} else {
			doc = []byte(rep.Markdown())
		}
		fmt.Println(string(doc))
	} else {
		fmt.Println(rep.Text())
		paths, werr := writeReportFiles(rep)
		for _, p := range paths {
			fmt.Println("wrote", p)
		}
		if werr != nil {
			return werr
		}
	}

	if failEnabled && reportMeetsThreshold(rep, failSev) {
		return fmt.Errorf("findings at or above the --fail-on threshold were found: %w", ErrThresholdExceeded)
	}
	return nil
}

// reportMeetsThreshold reports whether rep has at least one finding whose
// severity is at or above sev.
func reportMeetsThreshold(rep report.Report, sev checker.Severity) bool {
	for _, f := range rep.Findings {
		if f.Severity >= sev {
			return true
		}
	}
	return false
}

// writeReport is the tui.WriteFunc: writes the report and returns a status line.
func writeReport(rep report.Report) (string, error) {
	paths, err := writeReportFiles(rep)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "nothing written (--format none)", nil
	}
	return "wrote " + strings.Join(paths, ", "), nil
}

// writeReportFiles writes the report per --format/--out and returns the paths.
func writeReportFiles(rep report.Report) ([]string, error) {
	if flagFormat == "none" {
		return nil, nil
	}
	ts := rep.StartedAt.Format("20060102-150405")
	base := filepath.Join(flagOutDir, fmt.Sprintf("report-%s-%s", rep.Domain, ts))

	var paths []string
	if flagFormat == "both" || flagFormat == "md" {
		p := base + ".md"
		if err := os.WriteFile(p, []byte(rep.Markdown()), 0o600); err != nil {
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
		if err := os.WriteFile(p, j, 0o600); err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}
