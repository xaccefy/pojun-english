package server

import (
	"context"
	"testing"
	"time"
)

// When a planning round wedges, the planner loop must keep responding.
//
// Regression background (production incident 2026-10-21): the planner went mute for 1h05m
// — service running, task still 'running', zero planner logs. A goroutine dump showed it
// stuck on a self-deadlock in agent/compaction.go (tryStart held c.mu then called a
// locking
// cooldownFor).
//
// Key: **a deadlocked goroutine never returns — ctx cancellation can't reach it**. So a
// ctx-based 'wall-clock cap on the planning round' is useless against deadlock — calling
// Plan directly wedges runRound forever, and every later wake-up (edge + heartbeat) piles
// up behind it.
//
// Fix: Plan runs on its own goroutine while the main side selects on ctx; when ctx
// fires, **abandon this round** and let the planner loop continue (the wedged goroutine
// leaks, but the planner stops being mute).
func TestRunPlannerRoundAbandonsStuckPlan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	release := make(chan struct{})
	defer close(release)

	start := time.Now()
	out := runPlannerRound(ctx, func(context.Context) (bool, string, error) {
		// simulate deadlock: neither returns nor honors ctx.
		<-release
		return true, "should never be seen", nil
	})
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("runPlannerRound waited %v for a stuck plan — it must give up when ctx ends", elapsed)
	}
	if out.err == nil {
		t.Fatal("an abandoned round must report an error")
	}
	if out.met {
		t.Error("an abandoned round must not claim the goal was met")
	}
}

// A normally-returning planning round must surface its result untouched — not swallowed
// by the timeout logic.
func TestRunPlannerRoundPassesThroughResult(t *testing.T) {
	out := runPlannerRound(context.Background(), func(context.Context) (bool, string, error) {
		return true, "goal reached", nil
	})
	if !out.met {
		t.Error("met must be preserved")
	}
	if out.reason != "goal reached" {
		t.Errorf("reason = %q, want %q", out.reason, "goal reached")
	}
	if out.err != nil {
		t.Errorf("err = %v, want nil", out.err)
	}
}

// A failing planning round must surface its error untouched (not turn into a timeout).
func TestRunPlannerRoundPassesThroughError(t *testing.T) {
	want := context.Canceled
	out := runPlannerRound(context.Background(), func(context.Context) (bool, string, error) {
		return false, "", want
	})
	if out.err != want {
		t.Errorf("err = %v, want %v", out.err, want)
	}
	if out.met {
		t.Error("met must be false on error")
	}
}

// The wall-clock cap must be injectable, else 'wedged but doesn't drag the loop down'
// can't be verified in tests (production value is 15 minutes).
func TestPlannerRoundLimitOverride(t *testing.T) {
	if plannerRoundLimit() != plannerRoundTimeout {
		t.Errorf("default limit = %v, want %v", plannerRoundLimit(), plannerRoundTimeout)
	}
	old := plannerRoundTimeoutOverride
	plannerRoundTimeoutOverride = 3 * time.Second
	t.Cleanup(func() { plannerRoundTimeoutOverride = old })
	if plannerRoundLimit() != 3*time.Second {
		t.Errorf("overridden limit = %v, want 3s", plannerRoundLimit())
	}
}
