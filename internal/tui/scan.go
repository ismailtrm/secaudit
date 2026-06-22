package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/report"
)

// WriteFunc persists a finished report and returns a one-line description of
// what was written (or an error). Supplied by the caller so tui needn't know
// about output paths/flags.
type WriteFunc func(report.Report) (string, error)

type resultMsg checker.Result
type scanDoneMsg struct{}

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
	target  checker.Target
	total   int
	ch      <-chan checker.Result
	started time.Time
	write   WriteFunc

	spinner spinner.Model
	results []checker.Result
	done    bool
	rep     report.Report
	table   table.Model
	status  string

	width, height int
}

func newScanModel(t checker.Target, total int, ch <-chan checker.Result, started time.Time, write WriteFunc) scanModel {
	return scanModel{target: t, total: total, ch: ch, started: started, write: write, spinner: spinner.New()}
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForResult(m.ch))
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.done {
			m.table.UpdateViewport()
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case resultMsg:
		m.results = append(m.results, checker.Result(msg))
		return m, waitForResult(m.ch)

	case scanDoneMsg:
		m.done = true
		m.rep = report.Build(m.target, m.results, m.started)
		m.table = m.buildTable()
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
		if m.done {
			if msg.String() == "w" {
				if m.write != nil {
					s, err := m.write(m.rep)
					if err != nil {
						m.status = "write error: " + err.Error()
					} else {
						m.status = s
					}
				}
				return m, nil
			}
			var cmd tea.Cmd
			m.table, cmd = m.table.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m scanModel) View() tea.View {
	if m.done {
		return tea.NewView(m.resultsView())
	}
	return tea.NewView(m.runningView())
}

func (m scanModel) buildTable() table.Model {
	cols := []table.Column{
		{Title: "SEV", Width: 9},
		{Title: "CATEGORY", Width: 10},
		{Title: "TITLE", Width: 44},
	}
	rows := make([]table.Row, 0, len(m.rep.Findings))
	for _, f := range m.rep.Findings {
		rows = append(rows, table.Row{f.Severity.String(), string(f.Category), f.Title})
	}
	t := table.New(table.WithColumns(cols), table.WithRows(rows))
	t.Focus()
	t.SetWidth(9 + 10 + 46 + 6) // sum of column widths + cell padding
	h := len(rows) + 1
	if h > 15 {
		h = 15
	}
	t.SetHeight(h)
	t.UpdateViewport() // commit rows into the table's internal viewport
	return t
}

func (m scanModel) runningView() string {
	var b strings.Builder
	b.WriteString(header(m.target) + "\n\n")
	fmt.Fprintf(&b, "%s scanning… %d/%d checks complete\n\n", m.spinner.View(), len(m.results), m.total)
	for _, r := range m.results {
		var icon, detail string
		switch {
		case r.Skipped:
			icon = faintStyle.Render("⊘")
			detail = faintStyle.Render("skipped: " + r.Reason)
		case r.Err != "":
			icon = sevStyle(checker.SevHigh).Render("✗")
			detail = sevStyle(checker.SevHigh).Render(r.Err)
		default:
			icon = okStyle.Render("✓")
			detail = faintStyle.Render(fmt.Sprintf("%d findings · %s", len(r.Findings), r.Elapsed.Round(time.Millisecond)))
		}
		fmt.Fprintf(&b, "  %s %-24s %s\n", icon, r.Name, detail)
	}
	b.WriteString("\n" + hintStyle.Render("[q] quit"))
	return b.String()
}

func (m scanModel) resultsView() string {
	var b strings.Builder
	score := scoreStyles.Foreground(scoreColor(m.rep.Score)).Render(fmt.Sprintf("%d/100", m.rep.Score))
	b.WriteString(header(m.target) + "   score " + score + "   " +
		faintStyle.Render(severityLine(m.rep.Counts)+"   "+m.rep.Duration.Round(time.Millisecond).String()) + "\n\n")
	b.WriteString(m.table.View() + "\n")

	if len(m.rep.Findings) > 0 {
		i := m.table.Cursor()
		if i < 0 || i >= len(m.rep.Findings) {
			i = 0
		}
		f := m.rep.Findings[i]
		head := sevStyle(f.Severity).Render("["+f.Severity.String()+"] ") +
			lipgloss.NewStyle().Bold(true).Render(f.Title)
		body := f.Summary
		if f.Detail != "" {
			body += "\n" + f.Detail
		}
		if f.Err != "" {
			body += "\n! " + f.Err
		}
		b.WriteString("\n" + boxStyle.Width(boxWidth(m.width)).Render(head+"\n"+body) + "\n")
	}

	hint := "[↑/↓] navigate   [w] write report   [q] quit"
	if m.status != "" {
		hint = okStyle.Render(m.status) + "    " + hintStyle.Render(hint)
	} else {
		hint = hintStyle.Render(hint)
	}
	b.WriteString("\n" + hint)
	return b.String()
}

func header(t checker.Target) string {
	return titleStyle.Render("secaudit") +
		faintStyle.Render(" — "+t.Domain+" ("+t.Ownership.String()+")")
}

// severityLine renders the counts map in severity order.
func severityLine(counts map[string]int) string {
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, " · ")
}

func boxWidth(w int) int {
	if w <= 0 {
		return 76
	}
	if w > 100 {
		w = 100
	}
	return w - 4
}
