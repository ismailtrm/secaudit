package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ismailtrm/secaudit/internal/checker"
)

// Markdown renders the report as a shareable markdown document.
func (r Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# secaudit report — %s\n\n", r.Domain)
	fmt.Fprintf(&b, "- **Host scanned:** %s\n", r.Host)
	fmt.Fprintf(&b, "- **Ownership:** %s\n", r.Ownership)
	fmt.Fprintf(&b, "- **Started:** %s\n", r.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "- **Duration:** %s\n", r.Duration.Round(1e6))
	fmt.Fprintf(&b, "- **Health score:** %d/100\n\n", r.Score)

	if len(r.Counts) > 0 {
		b.WriteString("**Findings:** ")
		b.WriteString(severitySummary(r.Counts))
		b.WriteString("\n\n")
	}

	// Group findings by category.
	byCat := map[checker.Category][]checker.Finding{}
	var cats []checker.Category
	for _, f := range r.Findings {
		if _, seen := byCat[f.Category]; !seen {
			cats = append(cats, f.Category)
		}
		byCat[f.Category] = append(byCat[f.Category], f)
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i] < cats[j] })

	for _, cat := range cats {
		fmt.Fprintf(&b, "## %s\n\n", cat)
		for _, f := range byCat[cat] {
			fmt.Fprintf(&b, "### [%s] %s\n\n", f.Severity, f.Title)
			if f.Summary != "" {
				fmt.Fprintf(&b, "%s\n\n", f.Summary)
			}
			if f.Detail != "" {
				fmt.Fprintf(&b, "%s\n\n", f.Detail)
			}
			if f.Err != "" {
				fmt.Fprintf(&b, "> error: %s\n\n", f.Err)
			}
			for _, ref := range f.Refs {
				fmt.Fprintf(&b, "- %s\n", ref)
			}
			if len(f.Refs) > 0 {
				b.WriteString("\n")
			}
		}
	}

	if skipped := r.SkippedResults(); len(skipped) > 0 {
		b.WriteString("## Skipped checks\n\n")
		for _, s := range skipped {
			fmt.Fprintf(&b, "- **%s** — %s\n", s.Name, s.Reason)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func severitySummary(counts map[string]int) string {
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " · ")
}
