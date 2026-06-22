package tui

import (
	"sort"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/engine"
	"github.com/ismailtrm/secaudit/internal/report"
)

// WriteFunc persists a finished report and returns a one-line status (or error).
type WriteFunc func(report.Report) (string, error)

// Scan events carry the generation of the scan that produced them so a cancelled
// or restarted scan's in-flight events can't be applied to a newer scan.
type resultMsg struct {
	gen int
	r   checker.Result
}
type findingMsg struct {
	gen int
	f   checker.Finding
}
type scanDoneMsg struct{ gen int }

// backToLauncherMsg returns to the launcher, prefilled with domain, cancelling
// any in-flight scan.
type backToLauncherMsg struct{ domain string }

// feedItem is one entry in the live scanning feed.
type feedItem struct {
	elapsed time.Duration
	cat     checker.Category
	sev     checker.Severity
	title   string
}

// pane indices into scanModel.panes.
const (
	panePassive = 0
	paneActive  = 1
)

// findingPane is one scrollable list of findings (passive or active) on the
// results screen, each with its own cursor and scroll offset.
type findingPane struct {
	findings []checker.Finding
	cursor   int
	scroll   int
}

// waitForEvent blocks on one engine Event and re-arms itself until the channel
// closes: a streamed finding, a completed checker, or end-of-scan. gen tags each
// event so a stale scan's events are dropped by the model.
func waitForEvent(gen int, ch <-chan engine.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return scanDoneMsg{gen}
		}
		if ev.Finding != nil {
			return findingMsg{gen, *ev.Finding}
		}
		return resultMsg{gen, *ev.Result}
	}
}

type scanModel struct {
	gen      int // generation; events from other generations are ignored
	target   checker.Target
	checkers []checker.Checker
	ch       <-chan engine.Event
	started  time.Time
	write    WriteFunc

	spinner spinner.Model
	results []checker.Result

	// scanning screen
	totalCat    map[checker.Category]int
	receivedCat map[checker.Category]int
	catOrder    []checker.Category
	pending     map[string]string // checkerID → name, still running
	feed        []feedItem
	liveSev     map[checker.Severity]int // running tally, incl. streamed findings

	// results screen
	done         bool
	rep          report.Report
	panes        [2]findingPane          // panePassive, paneActive
	focus        int                     // pane holding the cursor
	activeRan    bool                    // active checkers ran -> two-column layout
	detailScroll int                     // scroll offset of the bottom detail pane
	minSev       checker.Severity        // filter floor, applied to both panes
	sortByCat    bool                    // sort by category vs severity
	modeByID     map[string]checker.Mode // CheckerID -> Mode, classifies findings into panes

	width, height int
	status        string
	showHelp      bool
}

func newScanModel(gen int, t checker.Target, checkers []checker.Checker, ch <-chan engine.Event, started time.Time, write WriteFunc) scanModel {
	totalCat := map[checker.Category]int{}
	pending := map[string]string{}
	modeByID := map[string]checker.Mode{}
	for _, c := range checkers {
		totalCat[c.Category()]++
		pending[c.ID()] = c.Name()
		modeByID[c.ID()] = c.Mode()
	}
	pref := []checker.Category{checker.CatDNS, checker.CatEmail, checker.CatTLS,
		checker.CatHTTP, checker.CatWhois, checker.CatOSINT, checker.CatPort, checker.CatVuln}
	var catOrder []checker.Category
	for _, cat := range pref {
		if totalCat[cat] > 0 {
			catOrder = append(catOrder, cat)
		}
	}
	return scanModel{
		gen:    gen,
		target: t, checkers: checkers, ch: ch, started: started, write: write,
		spinner:     spinner.New(),
		totalCat:    totalCat,
		receivedCat: map[checker.Category]int{},
		catOrder:    catOrder,
		pending:     pending,
		liveSev:     map[checker.Severity]int{},
		modeByID:    modeByID,
	}
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForEvent(m.gen, m.ch))
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case spinner.TickMsg:
		if m.done {
			return m, nil // results screen shows no spinner; stop re-arming the tick
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case findingMsg:
		if msg.gen != m.gen {
			return m, nil // stale scan
		}
		f := msg.f
		m.feed = append(m.feed, feedItem{elapsed: time.Since(m.started), cat: f.Category, sev: f.Severity, title: f.Title})
		m.liveSev[f.Severity]++
		return m, waitForEvent(m.gen, m.ch)

	case resultMsg:
		if msg.gen != m.gen {
			return m, nil // stale scan
		}
		r := msg.r
		m.results = append(m.results, r)
		m.receivedCat[r.Category]++
		delete(m.pending, r.CheckerID)
		now := time.Since(m.started)
		// Streaming checkers already pushed their findings live via findingMsg.
		if !r.Streamed {
			for _, f := range r.Findings {
				m.feed = append(m.feed, feedItem{elapsed: now, cat: f.Category, sev: f.Severity, title: f.Title})
				m.liveSev[f.Severity]++
			}
		}
		if r.Skipped {
			m.feed = append(m.feed, feedItem{elapsed: now, cat: r.Category, sev: checker.SevInfo,
				title: r.Name + " skipped: " + r.Reason})
		}
		return m, waitForEvent(m.gen, m.ch)

	case scanDoneMsg:
		if msg.gen != m.gen {
			return m, nil // stale scan
		}
		m.done = true
		m.rep = report.Build(m.target, m.results, m.started)
		m.applyFilterSort()
		return m, nil

	case tea.KeyPressMsg:
		if m.showHelp {
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			m.showHelp = false // any key dismisses help
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "?":
			m.showHelp = true
			return m, nil
		case "esc":
			// During a scan: cancel and go back. On results: same as a new scan.
			return m, backToLauncher(m.target.Domain)
		case "n":
			if m.done {
				return m, backToLauncher(m.target.Domain)
			}
		}
		if m.done {
			return m.handleResultsKey(msg.String()), nil
		}
	}
	return m, nil
}

// backToLauncher emits the message that returns to the launcher; appModel cancels
// the running scan when it receives it.
func backToLauncher(domain string) tea.Cmd {
	return func() tea.Msg { return backToLauncherMsg{domain: domain} }
}

func (m scanModel) handleResultsKey(key string) scanModel {
	switch key {
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "left", "h", "right", "l", "tab":
		m.switchPane()
	case "g", "home":
		m.panes[m.focus].cursor, m.panes[m.focus].scroll, m.detailScroll = 0, 0, 0
	case "pgdown", " ":
		if m.detailScroll < m.maxDetailScroll() {
			m.detailScroll++
		}
	case "pgup", "b":
		if m.detailScroll > 0 {
			m.detailScroll--
		}
	case "f":
		m.minSev = (m.minSev + 1) % 5 // info -> low -> medium -> high -> critical -> info
		m.applyFilterSort()
	case "s":
		m.sortByCat = !m.sortByCat
		m.applyFilterSort()
	case "w":
		if m.write != nil {
			if s, err := m.write(m.rep); err != nil {
				m.status = "write error: " + err.Error()
			} else {
				m.status = s
			}
		}
	}
	return m
}

// switchPane moves focus to the other pane, but only when active findings give
// us two columns to move between.
func (m *scanModel) switchPane() {
	if !m.activeRan {
		return
	}
	m.focus = 1 - m.focus
	m.detailScroll = 0
}

func (m *scanModel) moveCursor(d int) {
	p := &m.panes[m.focus]
	h := m.listViewH()
	p.cursor = clampi(p.cursor+d, 0, max(len(p.findings)-1, 0))
	if p.cursor < p.scroll {
		p.scroll = p.cursor
	}
	if h > 0 && p.cursor >= p.scroll+h {
		p.scroll = p.cursor - h + 1
	}
	m.detailScroll = 0
}

// applyFilterSort rebuilds both panes' visible findings from the report,
// classifying each finding as passive or active by its source checker's mode.
func (m *scanModel) applyFilterSort() {
	var passive, active []checker.Finding
	var activeTotal int
	for _, f := range m.rep.Findings {
		isActive := m.modeByID[f.CheckerID] == checker.Active
		if isActive {
			activeTotal++
		}
		if f.Severity < m.minSev {
			continue
		}
		if isActive {
			active = append(active, f)
		} else {
			passive = append(passive, f)
		}
	}
	// activeRan is computed before filtering so the active column doesn't vanish
	// when a severity filter empties it — it just shows "no findings match".
	m.activeRan = activeTotal > 0
	m.panes[panePassive].findings = m.sortFindings(passive)
	m.panes[paneActive].findings = m.sortFindings(active)
	if !m.activeRan {
		m.focus = panePassive
	}
	for i := range m.panes {
		m.clampPane(&m.panes[i])
	}
	m.detailScroll = 0 // the selected finding may have changed under the filter
}

func (m *scanModel) sortFindings(fs []checker.Finding) []checker.Finding {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if m.sortByCat {
			if a.Category != b.Category {
				return a.Category < b.Category
			}
			return a.Severity > b.Severity
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Category < b.Category
	})
	return fs
}

func (m *scanModel) clampPane(p *findingPane) {
	h := m.listViewH()
	p.cursor = clampi(p.cursor, 0, max(len(p.findings)-1, 0))
	if p.cursor < p.scroll {
		p.scroll = p.cursor
	}
	if h > 0 && p.cursor >= p.scroll+h {
		p.scroll = p.cursor - h + 1
	}
}

// liveCounts returns the running severity tally, including findings streamed by
// active checkers that haven't completed yet.
func (m scanModel) liveCounts() map[checker.Severity]int {
	return m.liveSev
}

func (m scanModel) render() string {
	if m.showHelp {
		return m.helpView()
	}
	if m.done {
		return m.resultsView()
	}
	return m.runningView()
}

func (m scanModel) View() tea.View { return tea.NewView(m.render()) }
