// Package engine fans checkers out concurrently and streams their Results.
//
// One Result is emitted per checker on a buffered channel (capacity = number of
// checkers, so a slow or absent consumer never blocks a checker). The channel
// closes when every checker finishes. Cancelling the context stops in-flight
// checkers. Per-checker errors and panics are captured into the Result — one
// failing checker never sinks the whole scan.
package engine

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ismailtrm/secaudit/internal/checker"
)

const (
	defaultConcurrency    = 8
	defaultCheckerTimeout = 30 * time.Second
)

// Options tunes a run. Zero values fall back to defaults.
type Options struct {
	Concurrency    int           // max checkers running at once
	CheckerTimeout time.Duration // hard cap per checker
}

// Run executes each checker against t concurrently and returns a channel that
// emits one Result per checker, closed when all finish.
func Run(ctx context.Context, t checker.Target, checkers []checker.Checker, opts Options) <-chan checker.Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.CheckerTimeout <= 0 {
		opts.CheckerTimeout = defaultCheckerTimeout
	}

	out := make(chan checker.Result, len(checkers))
	go func() {
		defer close(out)
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(opts.Concurrency)
		for _, c := range checkers {
			g.Go(func() error {
				out <- runOne(gctx, c, t, opts.CheckerTimeout)
				return nil // never fail the group; errors live in the Result
			})
		}
		_ = g.Wait()
	}()
	return out
}

// runOne executes a single checker, capturing timing, skip status, errors, and
// panics into the Result.
func runOne(ctx context.Context, c checker.Checker, t checker.Target, timeout time.Duration) (res checker.Result) {
	start := time.Now()
	res = checker.Result{CheckerID: c.ID(), Name: c.Name(), Category: c.Category()}
	defer func() {
		res.Elapsed = time.Since(start)
		if r := recover(); r != nil {
			res.Err = fmt.Sprintf("panic: %v", r)
		}
	}()

	if ok, reason := c.Available(ctx); !ok {
		res.Skipped = true
		res.Reason = reason
		return res
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	findings, err := c.Run(cctx, t)
	if err != nil {
		res.Err = err.Error()
	}
	res.Findings = findings
	return res
}
