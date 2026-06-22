package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
)

// ─── shared widgets ─────────────────────────────────────────────────────────

// titledBox draws a rounded box with the title embedded in the top border,
// fixed to the given outer width and body height (in content lines).
func titledBox(title, body string, width, height int) string {
	if width < 6 {
		width = 6
	}
	contentW := width - 4
	used := 3 + lipgloss.Width(title) + 1 // "╭─ " + title + " "
	fill := width - used - 1
	if fill < 0 {
		fill = 0
	}
	var b strings.Builder
	b.WriteString(borderStyle.Render("╭─ ") + title + borderStyle.Render(" "+strings.Repeat("─", fill)+"╮") + "\n")
	lines := strings.Split(body, "\n")
	for i := 0; i < height; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		b.WriteString(borderStyle.Render("│ ") + fitLine(line, contentW) + borderStyle.Render(" │") + "\n")
	}
	b.WriteString(borderStyle.Render("╰" + strings.Repeat("─", width-2) + "╯"))
	return b.String()
}

// gauge renders an n-cell score meter colored by health.
func gauge(score, n int) string {
	filled := score * n / 100
	if filled > n {
		filled = n
	}
	col := scoreColor(score)
	return lipgloss.NewStyle().Foreground(col).Render(strings.Repeat("▰", filled)) +
		barEmpty.Render(strings.Repeat("▱", n-filled))
}

// meterBar renders an n-cell progress meter for done/total.
func meterBar(done, total, n int) string {
	filled := 0
	if total > 0 {
		filled = done * n / total
	}
	if filled > n {
		filled = n
	}
	return barFull.Render(strings.Repeat("▰", filled)) + barEmpty.Render(strings.Repeat("▱", n-filled))
}

func shortSev(s checker.Severity) string {
	switch s {
	case checker.SevCritical:
		return "CRIT"
	case checker.SevHigh:
		return "HIGH"
	case checker.SevMedium:
		return "MED"
	case checker.SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// severityChips renders a colored ●/○ tally line from a severity→count map.
func severityChips(counts map[checker.Severity]int) string {
	order := []checker.Severity{checker.SevCritical, checker.SevHigh, checker.SevMedium, checker.SevLow, checker.SevInfo}
	var parts []string
	for _, s := range order {
		n := counts[s]
		if n == 0 {
			continue
		}
		dot := "●"
		if s == checker.SevInfo {
			dot = "○"
		}
		parts = append(parts, sevStyle(s).Render(fmt.Sprintf("%s%d %s", dot, n, shortSev(s))))
	}
	if len(parts) == 0 {
		return faintStyle.Render("no findings yet")
	}
	return strings.Join(parts, "  ")
}

func sevCounts(fs []checker.Finding) map[checker.Severity]int {
	m := map[checker.Severity]int{}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// ─── text fitting ───────────────────────────────────────────────────────────

func clipPlain(s string, n int) string {
	r := []rune(s)
	if n < 1 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func fitPlain(s string, n int) string {
	s = clipPlain(s, n)
	if d := n - len([]rune(s)); d > 0 {
		s += strings.Repeat(" ", d)
	}
	return s
}

// fitLine pads (or, rarely, truncates) a possibly-styled line to visible width w.
func fitLine(s string, w int) string {
	vis := lipgloss.Width(s)
	switch {
	case vis == w:
		return s
	case vis < w:
		return s + strings.Repeat(" ", w-vis)
	case !strings.Contains(s, "\x1b"):
		return clipPlain(s, w)
	default:
		return s // styled overflow is rare; callers pre-fit plain text
	}
}

func wrapPlain(s string, w int) []string {
	if w < 1 {
		return nil
	}
	var out []string
	for _, para := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line := ""
		for _, word := range words {
			switch {
			case line == "":
				line = word
			case len([]rune(line))+1+len([]rune(word)) <= w:
				line += " " + word
			default:
				out = append(out, line)
				line = word
			}
			for len([]rune(line)) > w {
				out = append(out, string([]rune(line)[:w]))
				line = string([]rune(line)[w:])
			}
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (m scanModel) elapsed() string {
	d := m.rep.Duration
	if d == 0 {
		d = time.Since(m.started)
	}
	return d.Round(10 * time.Millisecond).String()
}

// ─── results view (master-detail) ───────────────────────────────────────────

func (m scanModel) resultsView() string {
	W, H := max(m.width, 24), max(m.height, 12)
	header := m.headerBox(W)
	panelH := H - lipgloss.Height(header) - 1 - 2 // header, footer, box borders
	if panelH < 1 {
		panelH = 1
	}
	leftW := W * 44 / 100
	if leftW < 28 {
		leftW = 28
	}
	rightW := W - leftW

	left := titledBox(faintStyle.Render("findings ")+m.filterLabel(), m.listBody(leftW-4, panelH), leftW, panelH)
	right := titledBox(faintStyle.Render("detail"), m.detailBody(rightW-4, panelH), rightW, panelH)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	keys := keyhint("↑↓", "move") + "  " + keyhint("f", "filter") + "  " +
		keyhint("s", "sort") + "  " + keyhint("w", "write") + "  " + keyhint("q", "quit")
	footer := keys
	if m.status != "" {
		footer = okStyle.Render(m.status) + "   " + keys
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, body, fitLine(" "+footer, W))
}

func (m scanModel) headerBox(W int) string {
	score := m.rep.Score
	l1 := gauge(score, 14) + "  " + scoreStyles.Foreground(scoreColor(score)).Render(fmt.Sprintf("%d/100", score))
	l2 := severityChips(sevCounts(m.rep.Findings)) + "   " +
		faintStyle.Render(m.target.Ownership.String()+" · "+m.elapsed())
	title := titleStyle2.Render("secaudit") + faintStyle.Render(" · "+m.target.Domain)
	return titledBox(title, l1+"\n"+l2, W, 2)
}

func (m scanModel) filterLabel() string {
	if m.minSev == checker.SevInfo {
		return faintStyle.Render("(all)")
	}
	return sevStyle(m.minSev).Render("(≥" + shortSev(m.minSev) + ")")
}

func (m scanModel) listBody(w, h int) string {
	if len(m.findings) == 0 {
		return faintStyle.Render("no findings match filter")
	}
	end := min(m.scroll+h, len(m.findings))
	var lines []string
	for i := m.scroll; i < end; i++ {
		f := m.findings[i]
		row := fitPlain(fmt.Sprintf("%-4s %-6s %s", shortSev(f.Severity), f.Category, f.Title), w)
		st := sevStyle(f.Severity)
		if i == m.cursor {
			st = st.Background(selectedBg).Bold(true)
		}
		lines = append(lines, st.Render(row))
	}
	return strings.Join(lines, "\n")
}

func (m scanModel) detailBody(w, h int) string {
	if len(m.findings) == 0 {
		return ""
	}
	i := clampi(m.cursor, 0, len(m.findings)-1)
	f := m.findings[i]

	var lines []string
	lines = append(lines, lipgloss.NewStyle().Bold(true).Render(clipPlain(f.Title, w)))
	lines = append(lines, faintStyle.Render(string(f.Category))+"  "+sevStyle(f.Severity).Render(shortSev(f.Severity)))
	lines = append(lines, "")
	lines = append(lines, wrapPlain(f.Summary, w)...)
	if f.Detail != "" {
		lines = append(lines, "")
		lines = append(lines, wrapPlain(f.Detail, w)...)
	}
	if len(f.Evidence) > 0 {
		lines = append(lines, "", faintStyle.Render("evidence"))
		for _, k := range sortedKeys(f.Evidence) {
			lines = append(lines, "  "+clipPlain(fmt.Sprintf("%s = %v", k, f.Evidence[k]), w-2))
		}
	}
	if f.Err != "" {
		lines = append(lines, "", errStyle.Render("! "+clipPlain(f.Err, w-2)))
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n")
}

// ─── scanning view (meters + live feed) ──────────────────────────────────────

func (m scanModel) runningView() string {
	W, H := max(m.width, 24), max(m.height, 12)
	header := m.scanHeaderBox(W)
	meters := titledBox(faintStyle.Render("checks"), m.metersLine(W-4), W, 1)
	footer := fitLine(" "+severityChips(m.liveCounts()), W)

	feedH := H - lipgloss.Height(header) - lipgloss.Height(meters) - 1 - 2
	if feedH < 1 {
		feedH = 1
	}
	feed := titledBox(faintStyle.Render("live findings"), m.feedBody(W-4, feedH), W, feedH)
	return lipgloss.JoinVertical(lipgloss.Left, header, meters, feed, footer)
}

func (m scanModel) scanHeaderBox(W int) string {
	body := m.spinner.View() + " " + fmt.Sprintf("%d/%d checks", len(m.results), len(m.checkers)) +
		faintStyle.Render(" · "+m.elapsed())
	title := titleStyle2.Render("secaudit") + faintStyle.Render(" · scanning "+m.target.Domain)
	return titledBox(title, body, W, 1)
}

func (m scanModel) metersLine(w int) string {
	var parts []string
	for _, cat := range m.catOrder {
		done, total := m.receivedCat[cat], m.totalCat[cat]
		status := okStyle.Render("✓")
		if done < total {
			status = m.spinner.View()
		}
		parts = append(parts, faintStyle.Render(string(cat))+meterBar(done, total, 4)+status)
	}
	return strings.Join(parts, "  ")
}

func (m scanModel) feedBody(w, h int) string {
	var lines []string
	rows := h
	if !m.done && len(m.pending) > 0 {
		rows = h - 1 // reserve a line for the pending spinner
	}
	start := 0
	if len(m.feed) > rows {
		start = len(m.feed) - rows
	}
	for _, it := range m.feed[start:] {
		t := faintStyle.Render(fmt.Sprintf("%5s", it.elapsed.Round(100*time.Millisecond)))
		cat := faintStyle.Render(fmt.Sprintf("%-6s", clipPlain(string(it.cat), 6)))
		sev := sevStyle(it.sev).Render(fmt.Sprintf("%-4s", shortSev(it.sev)))
		lines = append(lines, fmt.Sprintf("%s %s %s %s", t, cat, sev, clipPlain(it.title, w-22)))
	}
	if !m.done && len(m.pending) > 0 {
		lines = append(lines, m.spinner.View()+" "+faintStyle.Render(clipPlain("scanning "+m.pendingNames(), w-2)))
	}
	return strings.Join(lines, "\n")
}

func (m scanModel) pendingNames() string {
	names := make([]string, 0, len(m.pending))
	for _, n := range m.pending {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// keyhint renders a "key action" pair with the key emphasized.
func keyhint(key, action string) string {
	return keyStyle.Render(key) + " " + hintStyle.Render(action)
}

func clampi(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
