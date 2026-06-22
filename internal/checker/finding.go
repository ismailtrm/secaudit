package checker

import "time"

// Severity ranks a finding. Higher is worse; report scores weight by severity.
type Severity uint8

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Finding is one observation from a checker. The same struct drives the TUI
// table, the detail viewport, and the markdown/JSON report.
type Finding struct {
	CheckerID string         `json:"checker_id"`
	Category  Category       `json:"category"`
	Severity  Severity       `json:"severity"`
	Title     string         `json:"title"`             // "HSTS header missing"
	Summary   string         `json:"summary,omitempty"` // one line for the table
	Detail    string         `json:"detail,omitempty"`  // markdown body for the viewport
	Evidence  map[string]any `json:"evidence,omitempty"`
	Refs      []string       `json:"refs,omitempty"`
	// Err holds a soft failure (e.g. a single record lookup failed) surfaced as
	// a "could not check" row. A checker-wide failure is returned from Run instead.
	Err string `json:"error,omitempty"`
}

// Result is the unit the engine streams to the TUI: one per checker, carrying
// its findings plus timing and skip status for the progress display.
type Result struct {
	CheckerID string        `json:"checker_id"`
	Name      string        `json:"name"`
	Category  Category      `json:"category"`
	Findings  []Finding     `json:"findings"`
	Skipped   bool          `json:"skipped"`
	Reason    string        `json:"reason,omitempty"` // why skipped ("nmap not installed")
	Err       string        `json:"error,omitempty"`  // checker-wide failure
	Elapsed   time.Duration `json:"elapsed_ns"`
	Streamed  bool          `json:"-"` // findings were emitted live (don't re-add to feed)
}
