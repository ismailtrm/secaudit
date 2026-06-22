// Package guard enforces the legal guardrail: active probing requires ownership
// or written authorization. The check lives here, separate from the UI, and is
// called from both the engine and the TUI wizard so it cannot be bypassed by
// scripting around the interactive prompt.
package guard

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ismailtrm/secaudit/internal/checker"
)

// ErrUnauthorized is returned when the requested mode is not permitted for the
// declared ownership.
var ErrUnauthorized = errors.New("unauthorized: active scanning of a third-party target")

// Authorize reports whether running checks up to maxMode is permitted for a
// target with the given ownership. Passive is always allowed. Active is allowed
// only for own or authorized targets.
func Authorize(o checker.Ownership, maxMode checker.Mode) error {
	if maxMode == checker.Passive {
		return nil
	}
	if o == checker.ThirdParty {
		return fmt.Errorf("%w: active scanning of a system you neither own nor "+
			"are authorized to test is illegal (e.g. TR TCK 243 / CFAA). "+
			"Provide written authorization or restrict to --mode passive", ErrUnauthorized)
	}
	return nil
}

// ParseOwnership maps a string flag to an Ownership.
func ParseOwnership(s string) (checker.Ownership, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "own", "self":
		return checker.Own, nil
	case "authorized", "auth":
		return checker.Authorized, nil
	case "third-party", "thirdparty", "3rd-party", "third":
		return checker.ThirdParty, nil
	default:
		return 0, fmt.Errorf("unknown ownership %q (want own|authorized|third-party)", s)
	}
}

// ParseMode maps a string flag to a Mode.
func ParseMode(s string) (checker.Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "passive", "":
		return checker.Passive, nil
	case "active":
		return checker.Active, nil
	default:
		return 0, fmt.Errorf("unknown mode %q (want passive|active)", s)
	}
}
