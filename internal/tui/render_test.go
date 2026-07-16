package tui

import (
	"testing"

	"github.com/ismailtrm/secaudit/internal/checker"
)

func TestGradeBoundaries(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {80, "B"}, {79, "C"},
		{70, "C"}, {69, "D"}, {60, "D"}, {59, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		if got := grade(tt.score); got != tt.want {
			t.Errorf("grade(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestShortSev(t *testing.T) {
	tests := []struct {
		sev  checker.Severity
		want string
	}{
		{checker.SevCritical, "CRIT"},
		{checker.SevHigh, "HIGH"},
		{checker.SevMedium, "MED"},
		{checker.SevLow, "LOW"},
		{checker.SevInfo, "INFO"},
	}
	for _, tt := range tests {
		if got := shortSev(tt.sev); got != tt.want {
			t.Errorf("shortSev(%v) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSevCounts(t *testing.T) {
	fs := []checker.Finding{
		{Severity: checker.SevHigh},
		{Severity: checker.SevHigh},
		{Severity: checker.SevInfo},
	}
	got := sevCounts(fs)
	if got[checker.SevHigh] != 2 {
		t.Errorf("SevHigh count = %d, want 2", got[checker.SevHigh])
	}
	if got[checker.SevInfo] != 1 {
		t.Errorf("SevInfo count = %d, want 1", got[checker.SevInfo])
	}
	if got[checker.SevCritical] != 0 {
		t.Errorf("SevCritical count = %d, want 0", got[checker.SevCritical])
	}
	if len(sevCounts(nil)) != 0 {
		t.Errorf("sevCounts(nil) should be empty")
	}
}
