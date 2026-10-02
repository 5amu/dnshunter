package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/5amu/dnshunter/pkg/core"
)

func TestRunOrderPanicAndTimeout(t *testing.T) {
	mk := func(id string, fn func(ctx context.Context, r *core.Result) error) *core.Check {
		return &core.Check{ID: id, Name: id, Run: func(ctx context.Context, _ *core.Env, r *core.Result) error { return fn(ctx, r) }}
	}
	checks := []*core.Check{
		mk("slow", func(ctx context.Context, r *core.Result) error {
			time.Sleep(50 * time.Millisecond)
			r.Add(core.Fail(core.SeverityHigh, "x", "bad"), core.Fail(core.SeverityLow, "x", "meh"))
			return nil
		}),
		mk("panic", func(context.Context, *core.Result) error { panic("boom") }),
		mk("timeout", func(ctx context.Context, r *core.Result) error {
			<-ctx.Done()
			return ctx.Err()
		}),
		mk("error", func(context.Context, *core.Result) error { return errors.New("no data") }),
		mk("pass", func(_ context.Context, r *core.Result) error {
			r.Add(core.Pass("x", "ok"), core.Errorf("y", "partial"))
			return nil
		}),
	}
	var order []string
	res := Run(context.Background(), &core.Env{}, checks, 4, 200*time.Millisecond, func(r *core.Result) { order = append(order, r.ID) })
	if strings.Join(order, ",") != "slow,panic,timeout,error,pass" {
		t.Fatalf("streaming order = %v", order)
	}
	if res[0].Status != core.StatusFail || res[0].Severity != core.SeverityHigh {
		t.Errorf("slow = %s/%s", res[0].Status, res[0].Severity)
	}
	if res[1].Status != core.StatusError || !strings.Contains(res[1].Error, "boom") {
		t.Errorf("panic = %s %q", res[1].Status, res[1].Error)
	}
	if res[2].Status != core.StatusError || !strings.Contains(res[2].Error, "deadline") {
		t.Errorf("timeout = %s %q", res[2].Status, res[2].Error)
	}
	if res[3].Status != core.StatusError {
		t.Errorf("error = %s", res[3].Status)
	}
	if res[4].Status != core.StatusPass {
		t.Errorf("pass = %s", res[4].Status)
	}
}
