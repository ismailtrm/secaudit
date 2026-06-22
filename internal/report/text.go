package report

import (
	"fmt"
	"strings"
)

// Text renders a compact plain-text summary for the --no-tui terminal path.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "secaudit — %s (%s)\n", r.Domain, r.Ownership)
	fmt.Fprintf(&b, "score %d/100 · %s · %s\n",
		r.Score, severitySummary(r.Counts), r.Duration.Round(1e6))
	b.WriteString(strings.Repeat("-", 60) + "\n")

	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%-8s] %-9s %s\n", f.Severity, f.Category, f.Title)
		if f.Summary != "" {
			fmt.Fprintf(&b, "             %s\n", f.Summary)
		}
		if f.Err != "" {
			fmt.Fprintf(&b, "             ! %s\n", f.Err)
		}
	}

	if skipped := r.SkippedResults(); len(skipped) > 0 {
		b.WriteString(strings.Repeat("-", 60) + "\n")
		for _, s := range skipped {
			fmt.Fprintf(&b, "[SKIPPED ] %-9s %s — %s\n", s.Category, s.Name, s.Reason)
		}
	}
	return b.String()
}
