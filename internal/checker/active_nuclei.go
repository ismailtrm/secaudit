package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ismailtrm/secaudit/internal/tool"
)

func init() { Register(nucleiScan{}) }

// nucleiScan runs ProjectDiscovery's nuclei template scanner and streams each
// finding live (nuclei emits JSONL line-by-line as it matches). Active: gated
// by guard. Defaults to low+ severity to skip the very noisy info templates.
type nucleiScan struct{}

func (nucleiScan) ID() string                               { return "active.nuclei" }
func (nucleiScan) Name() string                             { return "nuclei Templates" }
func (nucleiScan) Category() Category                       { return CatVuln }
func (nucleiScan) Mode() Mode                               { return Active }
func (nucleiScan) Available(context.Context) (bool, string) { return tool.Available("nuclei") }

func (c nucleiScan) Run(ctx context.Context, t Target) ([]Finding, error) {
	return c.RunStream(ctx, t, func(Finding) {})
}

func (nucleiScan) RunStream(ctx context.Context, t Target, emit Emitter) ([]Finding, error) {
	var findings []Finding
	err := tool.Stream(ctx, "", func(line string) {
		if !strings.HasPrefix(strings.TrimSpace(line), "{") {
			return // skip banner / non-JSON noise
		}
		var r nucleiResult
		if json.Unmarshal([]byte(line), &r) != nil || r.TemplateID == "" {
			return
		}
		f := nucleiFinding(r)
		findings = append(findings, f)
		emit(f)
	},
		"nuclei", "-u", t.URL.String(),
		"-jsonl", "-silent", "-no-color", "-duc", // duc: disable update check
		"-severity", "low,medium,high,critical",
	)
	// Surface the error even when some findings streamed: a cut-short scan must
	// not read as "clean". The partial findings are still returned.
	if err != nil {
		return findings, fmt.Errorf("nuclei: %w", err)
	}
	if len(findings) == 0 {
		f := Finding{CheckerID: "active.nuclei", Category: CatVuln, Severity: SevInfo,
			Title: "No template matches", Summary: "nuclei found no low+ severity issues"}
		emit(f)
		findings = append(findings, f)
	}
	return findings, nil
}

// nucleiResult is the subset of nuclei's JSONL schema we consume.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Type       string `json:"type"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
}

func nucleiFinding(r nucleiResult) Finding {
	name := r.Info.Name
	if name == "" {
		name = r.TemplateID
	}
	summary := r.TemplateID
	if r.MatchedAt != "" {
		summary += " @ " + r.MatchedAt
	}
	return Finding{
		CheckerID: "active.nuclei", Category: CatVuln, Severity: nucleiSev(r.Info.Severity),
		Title: name, Summary: summary, Detail: r.Info.Description,
		Evidence: map[string]any{"template": r.TemplateID, "matched_at": r.MatchedAt, "type": r.Type},
	}
}

func nucleiSev(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low":
		return SevLow
	default:
		return SevInfo
	}
}
