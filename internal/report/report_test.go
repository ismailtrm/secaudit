package report

import (
	"testing"
	"time"

	"github.com/ismailtrm/secaudit/internal/checker"
)

func TestBuildScoreAndSort(t *testing.T) {
	tgt, err := checker.NewTarget("example.com", checker.Own)
	if err != nil {
		t.Fatal(err)
	}
	results := []checker.Result{
		{CheckerID: "a", Findings: []checker.Finding{
			{Severity: checker.SevInfo, Category: checker.CatDNS, Title: "info"},
			{Severity: checker.SevHigh, Category: checker.CatTLS, Title: "high"},
		}},
		{CheckerID: "b", Findings: []checker.Finding{
			{Severity: checker.SevMedium, Category: checker.CatHTTP, Title: "med"},
		}},
		{CheckerID: "c", Name: "C", Skipped: true, Reason: "not installed"},
	}

	rep := Build(tgt, results, time.Now())

	// 100 - high(15) - med(7) - info(0)
	if rep.Score != 78 {
		t.Errorf("score = %d, want 78", rep.Score)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(rep.Findings))
	}
	if rep.Findings[0].Severity != checker.SevHigh {
		t.Errorf("first finding sev = %v, want HIGH (severity-desc sort)", rep.Findings[0].Severity)
	}
	if rep.Counts["HIGH"] != 1 || rep.Counts["MEDIUM"] != 1 || rep.Counts["INFO"] != 1 {
		t.Errorf("counts = %v, want HIGH/MEDIUM/INFO = 1 each", rep.Counts)
	}
	if got := rep.SkippedResults(); len(got) != 1 {
		t.Errorf("skipped = %d, want 1", len(got))
	}

	// Markdown/JSON should render without error and mention the domain.
	if md := rep.Markdown(); len(md) == 0 {
		t.Error("empty markdown")
	}
	if _, err := rep.JSON(); err != nil {
		t.Errorf("JSON: %v", err)
	}
}

func TestBuildScoreFloor(t *testing.T) {
	tgt, _ := checker.NewTarget("example.com", checker.Own)
	var fs []checker.Finding
	for i := 0; i < 10; i++ {
		fs = append(fs, checker.Finding{Severity: checker.SevCritical, Title: "x"})
	}
	rep := Build(tgt, []checker.Result{{Findings: fs}}, time.Now())
	if rep.Score != 0 {
		t.Errorf("score = %d, want clamped to 0", rep.Score)
	}
}
