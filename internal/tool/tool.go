// Package tool wraps discovery of external binaries (nmap, nuclei, httpx) so a
// missing tool becomes a graceful "Skipped: not installed" instead of a crash.
package tool

import (
	"os/exec"
)

// Lookup reports the absolute path of an external binary and whether it exists.
func Lookup(name string) (path string, ok bool) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}

// Available is a helper for a checker's Available() method: it returns ok=false
// with a human reason when the binary is missing.
func Available(name string) (ok bool, reason string) {
	if _, found := Lookup(name); !found {
		return false, name + " not installed"
	}
	return true, ""
}
