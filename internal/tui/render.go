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
	return titledBoxC(title, body, width, height, borderStyle)
}

// titledBoxC is titledBox with a caller-chosen border color, used to give the
// passive and active panes their cool/warm accents.
func titledBoxC(title, body string, width, height int, border lipgloss.Style) string {
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
	b.WriteString(border.Render("╭─ ") + title + border.Render(" "+strings.Repeat("─", fill)+"╮") + "\n")
	lines := strings.Split(body, "\n")
	for i := 0; i < height; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		b.WriteString(border.Render("│ ") + fitLine(line, contentW) + border.Render(" │") + "\n")
	}
	b.WriteString(border.Render("╰" + strings.Repeat("─", width-2) + "╯"))
	return b.String()
}

// grade maps a 0-100 score to a letter, shown next to the gauge.
func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
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

// ─── results view (split panes + bottom detail) ──────────────────────────────

// resultLayout splits the results screen height between the list panes (top) and
// the detail pane (bottom), and reports whether to draw two columns. The math:
// header box (4) + footer (1) + mid borders (2) + detail borders (2) = 9 lines
// of chrome, leaving `avail` content lines shared ~3:2 between mid and detail.
func (m scanModel) resultLayout() (midH, detailH int, twoCol bool) {
	H := max(m.height, 12)
	// chrome = header box (headerBodyH+2) + footer (1) + mid borders (2) + detail
	// borders (2); the rest is shared ~3:2 between the list panes and the detail.
	avail := H - (m.headerBodyH() + 7)
	if avail < 4 {
		avail = 4
	}
	detailH = avail * 2 / 5
	if detailH < 3 {
		detailH = 3
	}
	if detailH > avail-1 {
		detailH = avail - 1
	}
	midH = avail - detailH
	if midH < 1 {
		midH = 1
	}
	return midH, detailH, m.activeRan
}

// listViewH is the content height of a list pane, used to clamp cursor scrolling.
func (m scanModel) listViewH() int {
	h, _, _ := m.resultLayout()
	return h
}

func (m scanModel) resultsView() string {
	W := max(m.width, 24)
	header := m.headerBox(W)
	midH, detailH, twoCol := m.resultLayout()

	var mid string
	if twoCol {
		leftW := W / 2
		rightW := W - leftW
		left := m.paneBox("passive", m.panes[panePassive], leftW, midH, m.focus == panePassive, accentPassive)
		right := m.paneBox("active", m.panes[paneActive], rightW, midH, m.focus == paneActive, accentActive)
		mid = lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	} else {
		mid = m.paneBox("findings", m.panes[panePassive], W, midH, true, borderStyle)
	}

	detailBody, more := m.detailContent(W-4, detailH)
	dtitle := faintStyle.Render("detail")
	if more > 0 {
		dtitle += faintStyle.Render(fmt.Sprintf("  ↓ %d more", more))
	}
	detail := titledBox(dtitle, detailBody, W, detailH)

	keys := keyhint("↑↓", "move") + "  "
	if twoCol {
		keys += keyhint("←→", "pane") + "  "
	}
	keys += keyhint("f", "filter") + "  " + keyhint("s", "sort") + "  " +
		keyhint("w", "write") + "  " + keyhint("n", "new") + "  " +
		keyhint("?", "keys") + "  " + keyhint("q", "quit")
	footer := keys
	if m.status != "" {
		footer = okStyle.Render(m.status) + "   " + keys
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, mid, detail, fitLine(" "+footer, W))
}

func (m scanModel) headerBox(W int) string {
	score := m.rep.Score
	sc := scoreStyles.Foreground(scoreColor(score))
	l1 := gauge(score, 14) + "  " + sc.Render(fmt.Sprintf("%d/100", score)) + "  " + sc.Render(grade(score))
	l2 := severityChips(sevCounts(m.rep.Findings)) + "   " +
		faintStyle.Render(m.target.Ownership.String()+" · "+m.elapsed())
	title := titleStyle2.Render("secaudit") + faintStyle.Render(" · "+m.target.Domain)
	body := l1 + "\n" + l2
	if line, ok := m.skippedLine(W - 4); ok {
		body += "\n" + line
	}
	return titledBox(title, body, W, m.headerBodyH())
}

// headerBodyH is the header's content-line count: 3 when checkers were skipped
// (the extra line lists them), otherwise 2.
func (m scanModel) headerBodyH() int {
	if _, ok := m.skippedLine(max(m.width-4, 1)); ok {
		return 3
	}
	return 2
}

// skippedLine summarizes the checkers that did not run, so a finished scan still
// shows what was not covered (e.g. an unavailable scanner or no network).
func (m scanModel) skippedLine(w int) (string, bool) {
	sk := m.rep.SkippedResults()
	if len(sk) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(sk))
	for _, r := range sk {
		parts = append(parts, fmt.Sprintf("%s (%s)", r.Name, r.Reason))
	}
	raw := fmt.Sprintf("skipped %d: %s", len(sk), strings.Join(parts, " · "))
	return faintStyle.Render(clipPlain(raw, w)), true
}

func (m scanModel) filterLabel() string {
	if m.minSev == checker.SevInfo {
		return faintStyle.Render("(all)")
	}
	return sevStyle(m.minSev).Render("(≥" + shortSev(m.minSev) + ")")
}

// paneBox renders one findings list as a titled box; the focused pane gets the
// accent border and a highlighted title, the other stays dim.
func (m scanModel) paneBox(label string, p findingPane, w, h int, focused bool, accent lipgloss.Style) string {
	border := borderStyle
	if focused {
		border = accent
	}
	return titledBoxC(m.paneTitle(label, p, focused), m.listBody(p, w-4, h, focused), w, h, border)
}

func (m scanModel) paneTitle(label string, p findingPane, focused bool) string {
	style := faintStyle
	if focused {
		style = titleStyle2
	}
	t := style.Render(label) + faintStyle.Render(fmt.Sprintf(" (%d)", len(p.findings)))
	if focused {
		if m.minSev != checker.SevInfo {
			t += " " + m.filterLabel()
		}
		t += faintStyle.Render(" · " + m.sortLabel())
	}
	return t
}

// sortLabel names the current ordering, shown in the focused pane's title.
func (m scanModel) sortLabel() string {
	if m.sortByCat {
		return "by cat"
	}
	return "by sev"
}

func (m scanModel) listBody(p findingPane, w, h int, focused bool) string {
	if len(p.findings) == 0 {
		return faintStyle.Render("no findings match filter")
	}
	end := min(p.scroll+h, len(p.findings))
	var lines []string
	for i := p.scroll; i < end; i++ {
		f := p.findings[i]
		selected := i == p.cursor
		// The focused selection takes a uniform highlight; other rows get the
		// per-category color on the category column so it reads as a color band.
		if selected && focused {
			st := sevStyle(f.Severity).Background(selectedBg).Bold(true)
			row := fitPlain(fmt.Sprintf("%-4s %-6s %s", shortSev(f.Severity), f.Category, f.Title), w-1)
			lines = append(lines, st.Render("▌"+row))
			continue
		}
		gutter := " "
		if selected {
			gutter = "▌"
		}
		titleW := max(w-13, 1) // gutter(1) + sev(4) + sp + cat(6) + sp
		sev := sevStyle(f.Severity)
		sevTok := sev.Render(fmt.Sprintf("%-4s", shortSev(f.Severity)))
		catTok := catStyle(f.Category).Render(fmt.Sprintf("%-6s", clipPlain(string(f.Category), 6)))
		title := sev.Render(fitPlain(f.Title, titleW))
		lines = append(lines, faintStyle.Render(gutter)+sevTok+" "+catTok+" "+title)
	}
	return strings.Join(lines, "\n")
}

// detailContent renders the focused finding's detail, windowed to the scroll
// offset, and returns how many lines remain below the window.
func (m scanModel) detailContent(w, h int) (string, int) {
	p := m.panes[m.focus]
	if len(p.findings) == 0 {
		return faintStyle.Render("no finding selected"), 0
	}
	i := clampi(p.cursor, 0, len(p.findings)-1)
	lines := m.detailLines(p.findings[i], w)
	maxScroll := max(len(lines)-h, 0)
	s := clampi(m.detailScroll, 0, maxScroll)
	end := min(s+h, len(lines))
	return strings.Join(lines[s:end], "\n"), maxScroll - s
}

// detailLines builds the full (unwindowed) detail body for one finding.
func (m scanModel) detailLines(f checker.Finding, w int) []string {
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
	return lines
}

// maxDetailScroll caps PgDn so the detail pane stops at its last line.
func (m scanModel) maxDetailScroll() int {
	_, detailH, _ := m.resultLayout()
	p := m.panes[m.focus]
	if len(p.findings) == 0 {
		return 0
	}
	i := clampi(p.cursor, 0, len(p.findings)-1)
	// Width must match detailContent (max(m.width,24)-4) or PgDn over-increments.
	return max(len(m.detailLines(p.findings[i], max(m.width, 24)-4))-detailH, 0)
}

// ─── help overlay ────────────────────────────────────────────────────────────

func (m scanModel) helpView() string {
	W, H := max(m.width, 24), max(m.height, 12)
	rows := [][2]string{
		{"↑ ↓ / j k", "move selection"},
		{"← → / tab", "switch passive/active pane"},
		{"PgDn / PgUp", "scroll detail"},
		{"f", "cycle severity filter"},
		{"s", "toggle sort (severity/category)"},
		{"w", "write report (md + json)"},
		{"n", "new scan"},
		{"esc", "cancel scan, back to launcher"},
		{"?", "toggle this help"},
		{"q / ctrl+c", "quit"},
	}
	lines := []string{titleStyle2.Render("secaudit keys"), ""}
	for _, r := range rows {
		lines = append(lines, keyStyle.Render(fmt.Sprintf("%-12s", r[0]))+"  "+hintStyle.Render(r[1]))
	}
	box := titledBox(faintStyle.Render("help"), strings.Join(lines, "\n"), min(W-4, 52), len(lines))
	return lipgloss.Place(W, H, lipgloss.Center, lipgloss.Center, box)
}

// ─── scanning view (meters + live feed) ──────────────────────────────────────

func (m scanModel) runningView() string {
	W, H := max(m.width, 24), max(m.height, 12)
	header := m.scanHeaderBox(W)
	meters := titledBox(faintStyle.Render("checks"), m.metersLine(W-4), W, 1)
	hint := keyhint("esc", "cancel") + "  " + keyhint("?", "keys") + "  " + keyhint("ctrl+c", "quit")
	footer := fitLine(" "+severityChips(m.liveCounts())+"   "+hint, W)

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
