package tui

import (
	"sort"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/report"
)

// WriteFunc persists a finished report and returns a one-line status (or error).
type WriteFunc func(report.Report) (string, error)

type resultMsg checker.Result
type scanDoneMsg struct{}

// feedItem is one entry in the live scanning feed.
type feedItem struct {
	elapsed time.Duration
	cat     checker.Category
	sev     checker.Severity
	title   string
}

// waitForResult blocks on one Result and re-arms itself until the channel closes.
func waitForResult(ch <-chan checker.Result) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return scanDoneMsg{}
		}
		return resultMsg(r)
	}
}

type scanModel struct {
	target   checker.Target
	checkers []checker.Checker
	ch       <-chan checker.Result
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

	// results screen
	done      bool
	rep       report.Report
	findings  []checker.Finding // filtered + sorted view
	cursor    int
	scroll    int
	minSev    checker.Severity
	sortByCat bool
	listH     int

	width, height int
	status        string
}

func newScanModel(t checker.Target, checkers []checker.Checker, ch <-chan checker.Result, started time.Time, write WriteFunc) scanModel {
	totalCat := map[checker.Category]int{}
	pending := map[string]string{}
	for _, c := range checkers {
		totalCat[c.Category()]++
		pending[c.ID()] = c.Name()
	}
	pref := []checker.Category{checker.CatDNS, checker.CatEmail, checker.CatTLS,
		checker.CatHTTP, checker.CatWhois, checker.CatOSINT, checker.CatPort}
	var catOrder []checker.Category
	for _, cat := range pref {
		if totalCat[cat] > 0 {
			catOrder = append(catOrder, cat)
		}
	}
	return scanModel{
		target: t, checkers: checkers, ch: ch, started: started, write: write,
		spinner:     spinner.New(),
		totalCat:    totalCat,
		receivedCat: map[checker.Category]int{},
		catOrder:    catOrder,
		pending:     pending,
	}
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForResult(m.ch))
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.listH = m.height - 7 // header(4) + footer(1) + box borders(2)
		if m.listH < 1 {
			m.listH = 1
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case resultMsg:
		r := checker.Result(msg)
		m.results = append(m.results, r)
		m.receivedCat[r.Category]++
		delete(m.pending, r.CheckerID)
		now := time.Since(m.started)
		for _, f := range r.Findings {
			m.feed = append(m.feed, feedItem{elapsed: now, cat: f.Category, sev: f.Severity, title: f.Title})
		}
		if r.Skipped {
			m.feed = append(m.feed, feedItem{elapsed: now, cat: r.Category, sev: checker.SevInfo,
				title: r.Name + " skipped — " + r.Reason})
		}
		return m, waitForResult(m.ch)

	case scanDoneMsg:
		m.done = true
		m.rep = report.Build(m.target, m.results, m.started)
		m.applyFilterSort()
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
		if m.done {
			return m.handleResultsKey(msg.String()), nil
		}
	}
	return m, nil
}

func (m scanModel) handleResultsKey(key string) scanModel {
	switch key {
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "g", "home":
		m.cursor, m.scroll = 0, 0
	case "f":
		m.minSev = (m.minSev + 1) % 4 // info → low → medium → high → info
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

func (m *scanModel) moveCursor(d int) {
	m.cursor = clampi(m.cursor+d, 0, max(len(m.findings)-1, 0))
	if m.cursor < m.scroll {
		m.scroll = m.cursor
	}
	if m.listH > 0 && m.cursor >= m.scroll+m.listH {
		m.scroll = m.cursor - m.listH + 1
	}
}

// applyFilterSort rebuilds the visible findings slice from the report.
func (m *scanModel) applyFilterSort() {
	var fs []checker.Finding
	for _, f := range m.rep.Findings {
		if f.Severity >= m.minSev {
			fs = append(fs, f)
		}
	}
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
	m.findings = fs
	m.cursor = clampi(m.cursor, 0, max(len(fs)-1, 0))
	if m.cursor < m.scroll {
		m.scroll = m.cursor
	}
	if m.listH > 0 && m.cursor >= m.scroll+m.listH {
		m.scroll = m.cursor - m.listH + 1
	}
}

// liveCounts tallies severities seen so far during scanning.
func (m scanModel) liveCounts() map[checker.Severity]int {
	c := map[checker.Severity]int{}
	for _, r := range m.results {
		for _, f := range r.Findings {
			c[f.Severity]++
		}
	}
	return c
}

func (m scanModel) render() string {
	if m.done {
		return m.resultsView()
	}
	return m.runningView()
}

func (m scanModel) View() tea.View { return tea.NewView(m.render()) }
