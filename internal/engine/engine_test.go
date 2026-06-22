package engine

import (
	"context"
	"testing"

	"github.com/ismailtrm/secaudit/internal/checker"
)

// fakeChecker records whether it ran, for guardrail assertions.
type fakeChecker struct {
	id   string
	mode checker.Mode
	cat  checker.Category
	ran  *bool
}

func (f fakeChecker) ID() string                               { return f.id }
func (f fakeChecker) Name() string                             { return f.id }
func (f fakeChecker) Category() checker.Category               { return f.cat }
func (f fakeChecker) Mode() checker.Mode                       { return f.mode }
func (f fakeChecker) Available(context.Context) (bool, string) { return true, "" }
func (f fakeChecker) Run(context.Context, checker.Target) ([]checker.Finding, error) {
	*f.ran = true
	return []checker.Finding{{CheckerID: f.id, Severity: checker.SevInfo, Title: "ok"}}, nil
}

func collectResults(ch <-chan Event) []checker.Result {
	var rs []checker.Result
	for ev := range ch {
		if ev.Result != nil {
			rs = append(rs, *ev.Result)
		}
	}
	return rs
}

func TestEngineBlocksActiveOnThirdParty(t *testing.T) {
	passiveRan, activeRan := false, false
	checkers := []checker.Checker{
		fakeChecker{id: "p", mode: checker.Passive, cat: checker.CatDNS, ran: &passiveRan},
		fakeChecker{id: "active.x", mode: checker.Active, cat: checker.CatPort, ran: &activeRan},
	}
	target := checker.Target{Domain: "example.com", Host: "example.com", Ownership: checker.ThirdParty}

	results := collectResults(Run(context.Background(), target, checkers, Options{}))

	if activeRan {
		t.Error("active checker ran against a third-party target — guardrail bypassed")
	}
	if !passiveRan {
		t.Error("passive checker should still run against a third-party target")
	}
	var active *checker.Result
	for i := range results {
		if results[i].CheckerID == "active.x" {
			active = &results[i]
		}
	}
	if active == nil || !active.Skipped {
		t.Errorf("active result = %+v, want Skipped=true", active)
	}
}

func TestEngineAllowsActiveOnOwn(t *testing.T) {
	activeRan := false
	checkers := []checker.Checker{
		fakeChecker{id: "active.x", mode: checker.Active, cat: checker.CatPort, ran: &activeRan},
	}
	target := checker.Target{Domain: "example.com", Host: "example.com", Ownership: checker.Own}

	collectResults(Run(context.Background(), target, checkers, Options{}))

	if !activeRan {
		t.Error("active checker should run against an own target")
	}
}
