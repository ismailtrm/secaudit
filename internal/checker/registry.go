package checker

import "sort"

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
