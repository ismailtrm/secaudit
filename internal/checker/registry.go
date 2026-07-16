package checker

import (
	"fmt"
	"sort"
	"strings"
)

// registry holds every checker, keyed by ID. Checkers self-register in init().
var registry = map[string]Checker{}

// Register adds a checker to the global registry. It panics on a duplicate ID,
// which can only happen at init time and indicates a programming error.
func Register(c Checker) {
	if _, dup := registry[c.ID()]; dup {
		panic("checker: duplicate ID " + c.ID())
	}
	registry[c.ID()] = c
}

// All returns every registered checker, sorted by ID for stable ordering.
func All() []Checker {
	out := make([]Checker, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// ByMode returns the checkers whose Mode is allowed by maxMode: Passive returns
// only passive checkers; Active returns both.
func ByMode(maxMode Mode) []Checker {
	var out []Checker
	for _, c := range All() {
		if c.Mode() <= maxMode {
			out = append(out, c)
		}
	}
	return out
}

// Filter narrows checkers to an --only allowlist and/or an --skip denylist,
// matched exactly against Checker.ID(). An empty only keeps every checker;
// a non-empty only keeps just those IDs. skip is then applied on top of
// whatever only produced. Unknown IDs in either list are reported by name
// rather than silently ignored, so a typo fails loudly instead of quietly
// running (or skipping) nothing.
func Filter(checkers []Checker, only, skip []string) ([]Checker, error) {
	known := make(map[string]bool, len(checkers))
	for _, c := range checkers {
		known[c.ID()] = true
	}
	if err := unknownIDs(known, only); err != nil {
		return nil, err
	}
	if err := unknownIDs(known, skip); err != nil {
		return nil, err
	}

	onlySet := toSet(only)
	skipSet := toSet(skip)

	out := make([]Checker, 0, len(checkers))
	for _, c := range checkers {
		if len(onlySet) > 0 && !onlySet[c.ID()] {
			continue
		}
		if skipSet[c.ID()] {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// unknownIDs reports an error naming every id not present in known.
func unknownIDs(known map[string]bool, ids []string) error {
	var bad []string
	for _, id := range ids {
		if !known[id] {
			bad = append(bad, id)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("unknown checker ID(s): %s", strings.Join(bad, ", "))
	}
	return nil
}

func toSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}
