// Package tool wraps discovery and execution of external binaries (nmap, nuclei,
// httpx) so a missing tool becomes a graceful "Skipped: not installed" instead
// of a crash.
package tool

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
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

// Output runs name with args and returns combined stdout. The context kills the
// process when cancelled (scan timeout / Ctrl-C).
func Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// Stream runs name with args and calls onLine for each stdout line as it is
// produced (for tools that emit JSONL incrementally, e.g. nuclei/httpx). stdin,
// if non-empty, is written to the process. It blocks until the process exits.
func Stream(ctx context.Context, stdin string, onLine func(string), name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // tolerate long JSON lines
	for sc.Scan() {
		onLine(sc.Text())
	}
	return cmd.Wait()
}
