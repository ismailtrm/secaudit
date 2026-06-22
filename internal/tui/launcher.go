package tui

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/guard"
)

// launchMsg is emitted when the user submits a valid target from the launcher.
type launchMsg struct {
	target checker.Target
	mode   checker.Mode
}

var (
	ownerships    = []checker.Ownership{checker.Own, checker.Authorized, checker.ThirdParty}
	ownershipName = []string{"own", "authorized", "third-party"}
	scanModes     = []checker.Mode{checker.Passive, checker.Active}
	modeName      = []string{"passive", "active"} // matches --mode flag values
	// modeLabel is the launcher display: "active" means passive + active, since a
	// combined scan always runs the passive checks too.
	modeLabel = []string{"passive only", "passive + active"}
)

// launcherModel is the full-screen home screen: a centered search box plus a
// bottom bar for ownership/mode selection.
type launcherModel struct {
	input         textinput.Model
	ownership     int
	mode          int
	err           string
	width, height int
}

func newLauncher(domain0, ownership0, mode0 string) launcherModel {
	ti := textinput.New()
	ti.Placeholder = "enter a domain to scan"
	ti.Prompt = "› "
	ti.CharLimit = 253
	ti.SetWidth(36)
	ti.SetVirtualCursor(true)
	ti.SetValue(domain0)
	ti.Focus() // focus here so the state persists on the stored model

	return launcherModel{
		input:     ti,
		ownership: indexOf(ownershipName, ownership0),
		mode:      indexOf(modeName, mode0),
	}
}

func (l launcherModel) Init() tea.Cmd { return l.input.Focus() }

// prefill returns to the launcher with the input set to domain and any prior
// error cleared, for the "new scan" / cancel flow.
func (l launcherModel) prefill(domain string) launcherModel {
	l.input.SetValue(domain)
	l.err = ""
	return l
}

func (l launcherModel) Update(msg tea.Msg) (launcherModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		l.width, l.height = msg.Width, msg.Height
		return l, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			return l, tea.Quit
		case "tab":
			l.ownership = (l.ownership + 1) % len(ownerships)
			l.err = ""
			return l, nil
		case "shift+tab":
			l.ownership = (l.ownership - 1 + len(ownerships)) % len(ownerships)
			l.err = ""
			return l, nil
		case "up", "down":
			l.mode = 1 - l.mode // toggle passive/active
			l.err = ""
			return l, nil
		case "enter":
			return l.submit()
		}
	}

	var cmd tea.Cmd
	l.input, cmd = l.input.Update(msg)
	return l, cmd
}

// submit validates the current selection and emits a launchMsg, or sets l.err.
func (l launcherModel) submit() (launcherModel, tea.Cmd) {
	domain := strings.TrimSpace(l.input.Value())
	if domain == "" {
		l.err = "enter a domain to scan"
		return l, nil
	}
	owner := ownerships[l.ownership]
	mode := scanModes[l.mode]
	if err := guard.Authorize(owner, mode); err != nil {
		l.err = "third-party + active is not allowed. Switch to passive (↑/↓)"
		return l, nil
	}
	t, err := checker.NewTarget(domain, owner)
	if err != nil {
		l.err = err.Error()
		return l, nil
	}
	return l, func() tea.Msg { return launchMsg{target: t, mode: mode} }
}

func (l launcherModel) View() string {
	logo := logoStyle.Render("S E C A U D I T")
	subtitle := faintStyle.Render("terminal domain recon")
	box := searchBox.Render(l.input.View())

	stack := []string{logo, subtitle, "", box}
	if l.err != "" {
		stack = append(stack, "", errStyle.Render("! "+l.err))
	}
	center := lipgloss.JoinVertical(lipgloss.Center, stack...)

	bodyH := l.height - 1
	if bodyH < 1 {
		bodyH = 1
	}
	body := lipgloss.Place(l.width, bodyH, lipgloss.Center, lipgloss.Center, center)
	return lipgloss.JoinVertical(lipgloss.Left, body, l.footer())
}

func (l launcherModel) footer() string {
	own := "ownership " + chip(ownershipName[l.ownership], true)
	mode := "mode " + chip(modeLabel[l.mode], true)
	keys := footerBar.Render("tab ownership · ↑↓ mode · ↵ scan · esc quit")
	left := own + "   " + mode
	gap := l.width - lipgloss.Width(left) - lipgloss.Width(keys) - 2
	if gap < 1 {
		gap = 1
	}
	return " " + left + strings.Repeat(" ", gap) + keys
}

func indexOf(ss []string, v string) int {
	for i, s := range ss {
		if s == v {
			return i
		}
	}
	return 0
}
