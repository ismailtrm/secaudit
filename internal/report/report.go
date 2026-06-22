// Package report aggregates checker Results into a scored Report and renders it
// as terminal text, markdown, or JSON.
package report

import (
	"sort"
	"time"

	"github.com/ismailtrm/secaudit/internal/checker"
)

// Report is the aggregate output of one scan.
type Report struct {
	Domain    string                    `json:"domain"`
	Host      string                    `json:"host"`
	Ownership string                    `json:"ownership"`
	Mode      string                    `json:"mode"`
	StartedAt time.Time                 `json:"started_at"`
	Duration  time.Duration             `json:"duration_ns"`
	Score     int                       `json:"score"` // 0-100, higher is healthier
	Counts    map[string]int            `json:"counts"`
	Findings  []checker.Finding         `json:"findings"` // flattened, severity-sorted
	Results   []checker.Result          `json:"results"`  // per-checker, incl. skipped
}

// severityPenalty is subtracted from a starting score of 100 per finding.
var severityPenalty = map[checker.Severity]int{
	checker.SevCritical: 25,
	checker.SevHigh:     15,
	checker.SevMedium:   7,
	checker.SevLow:      3,
	checker.SevInfo:     0,
}

// Build aggregates results into a Report. started is the scan start time.
func Build(t checker.Target, results []checker.Result, started time.Time) Report {
	r := Report{
		Domain:    t.Domain,
		Host:      t.Host,
		Ownership: t.Ownership.String(),
		StartedAt: started,
		Duration:  time.Since(started),
		Counts:    map[string]int{},
		Results:   results,
	}

	score := 100
	for _, res := range results {
		for _, f := range res.Findings {
			r.Findings = append(r.Findings, f)
			r.Counts[f.Severity.String()]++
			score -= severityPenalty[f.Severity]
		}
	}
	if score < 0 {
		score = 0
	}
	r.Score = score

	// Sort findings by severity descending, then category, then title.
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Title < b.Title
	})
	return r
}

// SkippedResults returns the checkers that did not run.
func (r Report) SkippedResults() []checker.Result {
	var out []checker.Result
	for _, res := range r.Results {
		if res.Skipped {
			out = append(out, res)
		}
	}
	return out
}
