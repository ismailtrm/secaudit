// Package checker defines the plugin contract for secaudit recon checks.
//
// Every check (DNS, TLS, RDAP, ...) implements Checker and self-registers in an
// init() via Register. The engine discovers checkers through the registry and
// the TUI iterates results — neither names a concrete checker, so adding a new
// check is a single new file.
package checker

import "context"

// userAgent identifies secaudit's outbound HTTP requests (crt.sh, Wayback,
// InternetDB, security.txt, takeover probes). Single source for the version.
const userAgent = "secaudit/1.0 (+passive recon)"

// Mode classifies a checker by how intrusive it is against the target.
type Mode uint8

const (
	// Passive checks only read public data (DNS, CT logs, TLS handshakes that
	// any client makes). Always safe to run against any target.
	Passive Mode = iota
	// Active checks probe the target directly (port scans, vuln templates) and
	// require ownership or written authorization. Gated by package guard.
	Active
)

func (m Mode) String() string {
	if m == Active {
		return "active"
	}
	return "passive"
}

// Ownership records the caller's relationship to the target. It drives the
// legal guardrail in package guard: third-party + active is a hard fail.
type Ownership uint8

const (
	Own        Ownership = iota // infrastructure the user controls
	Authorized                  // written authorization (pentest contract, bug bounty)
	ThirdParty                  // someone else's system — passive only
)

func (o Ownership) String() string {
	switch o {
	case Own:
		return "own"
	case Authorized:
		return "authorized"
	default:
		return "third-party"
	}
}

// Category groups findings in the report and TUI.
type Category string

const (
	CatDNS   Category = "DNS"
	CatEmail Category = "EMAIL"
	CatTLS   Category = "TLS"
	CatHTTP  Category = "HTTP"
	CatWhois Category = "WHOIS"
	CatOSINT Category = "OSINT"
	CatPort  Category = "PORT"
	CatVuln  Category = "VULN"
)

// Checker is the plugin contract. Implementations must be safe for concurrent
// use: the engine runs every checker against the same read-only Target.
type Checker interface {
	// ID is a stable slug ("dns.records") used for cache keys and report grouping.
	ID() string
	// Name is a human label shown in the TUI.
	Name() string
	Category() Category
	Mode() Mode
	// Available reports whether the checker can run (binary present, network
	// reachable). A false result becomes a "Skipped" row rather than an error.
	Available(ctx context.Context) (ok bool, reason string)
	// Run executes the check. It returns multiple findings (one DNS check yields
	// many: missing DMARC, weak SPF, ...). A returned error is a hard failure;
	// per-finding soft failures go in Finding.Err.
	Run(ctx context.Context, t Target) ([]Finding, error)
}

// Emitter receives a finding the moment a checker discovers it.
type Emitter func(Finding)

// StreamingChecker is an optional capability: long-running checkers (active
// scanners) call emit() for each finding as it is found, so the UI can show
// results live instead of waiting for the whole scan. The engine prefers
// RunStream when a checker implements it; the returned slice still feeds the
// final report. Implementations typically have Run delegate to RunStream with a
// no-op emit.
type StreamingChecker interface {
	Checker
	RunStream(ctx context.Context, t Target, emit Emitter) ([]Finding, error)
}
