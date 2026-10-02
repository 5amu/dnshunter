// Package scanner runs checks concurrently against a target.
package scanner

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/5amu/dnshunter/pkg/core"
)

// Run executes checks with at most concurrency checks in flight. onResult (if
// not nil) is called in check order as soon as each result and all the
// previous ones are available, which allows streaming output. The returned
// results are in check order.
func Run(ctx context.Context, env *core.Env, checks []*core.Check, concurrency int, timeout time.Duration, onResult func(*core.Result)) []*core.Result {
	if concurrency <= 0 {
		concurrency = 4
	}
	results := make([]*core.Result, len(checks))
	done := make([]chan struct{}, len(checks))
	for i := range done {
		done[i] = make(chan struct{})
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func(i int, c *core.Check) {
			defer wg.Done()
			defer close(done[i])
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = runOne(ctx, env, c, timeout)
		}(i, c)
	}

	for i := range checks {
		<-done[i]
		if onResult != nil {
			onResult(results[i])
		}
	}
	wg.Wait()
	return results
}

func runOne(ctx context.Context, env *core.Env, c *core.Check, timeout time.Duration) (r *core.Result) {
	r = core.NewResult(c)
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			r.Error = fmt.Sprintf("internal error: %v\n%s", p, debug.Stack())
		}
		r.DurationMS = time.Since(start).Milliseconds()
		r.Finalize()
	}()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := c.Run(ctx, env, r); err != nil {
		r.Error = err.Error()
	}
	return r
}
