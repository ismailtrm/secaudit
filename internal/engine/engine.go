// Package engine fans checkers out concurrently and streams their events.
//
// Each checker produces a stream of Events: zero or more Finding events (for
// streaming checkers, emitted live as results are discovered) followed by one
// Result event when it completes. The channel closes when every checker
// finishes. Cancelling the context stops in-flight checkers. Per-checker errors
// and panics are captured into the Result — one failing checker never sinks the
// whole scan.
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

// Event is one item on the engine's output stream: exactly one of Finding or
// Result is non-nil.
type Event struct {
	Finding *checker.Finding // a finding discovered mid-scan (streaming)
	Result  *checker.Result  // a checker completed
}

// Run executes each checker against t concurrently and returns a channel of
// Events, closed when all checkers finish.
func Run(ctx context.Context, t checker.Target, checkers []checker.Checker, opts Options) <-chan Event {
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.CheckerTimeout <= 0 {
		opts.CheckerTimeout = defaultCheckerTimeout
	}

	out := make(chan Event, 256)
	go func() {
		defer close(out)
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(opts.Concurrency)
		for _, c := range checkers {
			g.Go(func() error {
				send := func(e Event) {
					select {
					case out <- e:
					case <-gctx.Done():
					}
				}
				res := runOne(gctx, c, t, opts.CheckerTimeout, func(f checker.Finding) {
					send(Event{Finding: &f})
				})
				send(Event{Result: &res})
				return nil
			})
		}
		_ = g.Wait()
	}()
	return out
}

// runOne executes a single checker, streaming findings through emit when the
// checker supports it, and capturing timing, skip status, errors, and panics.
func runOne(ctx context.Context, c checker.Checker, t checker.Target, timeout time.Duration, emit checker.Emitter) (res checker.Result) {
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

	var findings []checker.Finding
	var err error
	if sc, ok := c.(checker.StreamingChecker); ok {
		res.Streamed = true
		findings, err = sc.RunStream(cctx, t, emit)
	} else {
		findings, err = c.Run(cctx, t)
	}
	if err != nil {
		res.Err = err.Error()
	}
	res.Findings = findings
	return res
}
