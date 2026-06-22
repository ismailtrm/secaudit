package tui

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/engine"
)

// RunScan launches the live scan TUI: it starts the engine, streams Results into
// a bubbletea program (progress → results), and lets the user write the report.
func RunScan(ctx context.Context, t checker.Target, checkers []checker.Checker, write WriteFunc) error {
	started := time.Now()
	ch := engine.Run(ctx, t, checkers, engine.Options{})
	m := newScanModel(t, len(checkers), ch, started, write)
	_, err := tea.NewProgram(m, tea.WithContext(ctx)).Run()
	return err
}
