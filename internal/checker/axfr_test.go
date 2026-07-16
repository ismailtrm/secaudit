package checker

import (
	"errors"
	"testing"
)

func TestAxfrSummarize(t *testing.T) {
	tests := []struct {
		name      string
		results   []axfrResult
		wantSev   []Severity
		wantTitle []string
	}{
		{
			name: "all nameservers refuse",
			results: []axfrResult{
				{ns: "ns1.example.com", err: errors.New("connection refused")},
				{ns: "ns2.example.com", err: errors.New("i/o timeout")},
			},
			wantSev:   []Severity{SevInfo},
			wantTitle: []string{"AXFR refused"},
		},
		{
			name: "one nameserver allows transfer",
			results: []axfrResult{
				{ns: "ns1.example.com", err: errors.New("connection refused")},
				{ns: "ns2.example.com", count: 42, err: nil},
			},
			wantSev:   []Severity{SevHigh},
			wantTitle: []string{"Zone transfer allowed"},
		},
		{
			name: "all nameservers allow transfer",
			results: []axfrResult{
				{ns: "ns1.example.com", count: 10, err: nil},
				{ns: "ns2.example.com", count: 12, err: nil},
			},
			wantSev:   []Severity{SevHigh, SevHigh},
			wantTitle: []string{"Zone transfer allowed", "Zone transfer allowed"},
		},
		{
			name:      "no results",
			results:   nil,
			wantSev:   nil,
			wantTitle: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := summarizeAXFR(tc.results)
			if len(findings) != len(tc.wantSev) {
				t.Fatalf("summarizeAXFR() = %d findings, want %d", len(findings), len(tc.wantSev))
			}
			for i, f := range findings {
				if f.Severity != tc.wantSev[i] {
					t.Errorf("finding %d severity = %v, want %v", i, f.Severity, tc.wantSev[i])
				}
				if f.Title != tc.wantTitle[i] {
					t.Errorf("finding %d title = %q, want %q", i, f.Title, tc.wantTitle[i])
				}
			}
		})
	}
}

func TestAxfrNormalizeNS(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ns1.example.com.", "ns1.example.com"},
		{"NS1.Example.COM.", "ns1.example.com"},
		{"ns1.example.com", "ns1.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeNS(tc.in); got != tc.want {
				t.Errorf("normalizeNS(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
