package tui

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/engine"
)

type screen int

const (
	screenLauncher screen = iota
	screenScan
)

// appModel is the top-level full-screen program: it starts on the launcher and
// transitions into the live scan once a target is submitted. The whole UI runs
// in the alternate screen buffer (set in View) for a btop-style takeover.
type appModel struct {
	screen   screen
	launcher launcherModel
	scan     scanModel

	ctx           context.Context
	write         WriteFunc
	width, height int

	scanGen    int                // increments per scan; tags events to drop stale ones
	scanCancel context.CancelFunc // cancels the in-flight scan
}

// optsFor gives the active checkers in a combined scan a long per-checker budget
// (nuclei/nmap run for minutes); passive checkers keep the engine's short
// default even when active scanning is enabled.
func optsFor(mode checker.Mode) engine.Options {
	if mode == checker.Active {
		return engine.Options{ActiveTimeout: 15 * time.Minute}
	}
	return engine.Options{}
}

func newApp(ctx context.Context, domain0, ownership0, mode0 string, write WriteFunc) appModel {
	return appModel{
		launcher: newLauncher(domain0, ownership0, mode0),
		ctx:      ctx,
		write:    write,
	}
}

func (m appModel) Init() tea.Cmd { return m.launcher.Init() }

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.launcher, _ = m.launcher.Update(msg)
		if m.screen == screenScan {
			sm, _ := m.scan.Update(msg)
			m.scan = sm.(scanModel)
		}
		return m, nil

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case launchMsg:
		if m.scanCancel != nil {
			m.scanCancel() // cancel any prior scan before starting a new one
		}
		m.scanGen++
		sctx, cancel := context.WithCancel(m.ctx)
		m.scanCancel = cancel
		checkers := checker.ByMode(msg.mode)
		ch := engine.Run(sctx, msg.target, checkers, optsFor(msg.mode))
		m.scan = newScanModel(m.scanGen, msg.target, checkers, ch, time.Now(), m.write)
		// Seed the scan model with the current terminal size so its table lays out.
		if m.width > 0 {
			sm, _ := m.scan.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
			m.scan = sm.(scanModel)
		}
		m.screen = screenScan
		return m, m.scan.Init()

	case backToLauncherMsg:
		if m.scanCancel != nil {
			m.scanCancel()
			m.scanCancel = nil
		}
		m.screen = screenLauncher
		m.launcher = m.launcher.prefill(msg.domain)
		return m, m.launcher.Init()
	}

	if m.screen == screenLauncher {
		var cmd tea.Cmd
		m.launcher, cmd = m.launcher.Update(msg)
		return m, cmd
	}
	sm, cmd := m.scan.Update(msg)
	m.scan = sm.(scanModel)
	return m, cmd
}

func (m appModel) View() tea.View {
	content := m.launcher.View()
	if m.screen == screenScan {
		content = m.scan.render()
	}
	v := tea.NewView(content)
	v.AltScreen = true
	return v
}

// RunInteractive launches the full-screen launcher → scan TUI. domain0 prefills
// the search box (empty for a bare `secaudit`); ownership0/mode0 preselect the
// bottom bar from CLI flags.
func RunInteractive(ctx context.Context, domain0, ownership0, mode0 string, write WriteFunc) error {
	m := newApp(ctx, domain0, ownership0, mode0, write)
	_, err := tea.NewProgram(m, tea.WithContext(ctx)).Run()
	return err
}
