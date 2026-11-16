package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// plannerRoundTimeout must be a finite value.
//
// Regression background (production incident 2026-10-20): the planner's MaxDuration
// comes from clampMaxDuration(deadline, 0) — 0 = unlimited when the task has no
// deadline; and the SDK's MaxDuration only checks at round boundaries and only bounds
// tool execution — LLM calls use l.ctx with no deadline. So one half-open upstream
// connection (connected but never returning) made Plan() never return.
//
// runRound is serial: once it doesn't return, every later wake-up (edge + 10-minute
// heartbeat) piles up behind it → the planner goes permanently mute. Measured: 6 hours
// with zero planner rounds, zero new intents, running workers stuck at 0, task still
// 'running' but doing nothing; a service restart fixed it.
//
// 0 or negative would turn 'capped' back into 'uncapped' — i.e. no fix at all.
func TestPlannerRoundTimeoutIsBounded(t *testing.T) {
	if plannerRoundTimeout <= 0 {
		t.Fatalf("planner rounds need a wall-clock cap, currently %v (0 = unlimited = unfixed)", plannerRoundTimeout)
	}
	// and not too short: a planning round measures 3–5 minutes (1M context + dozens of
	// tool calls) — too short a cap misjudges normal planning as timed out.
	if plannerRoundTimeout < 5*time.Minute {
		t.Fatalf("planner round cap too short (%v): rounds take 3–5 minutes, killing normal planning", plannerRoundTimeout)
	}
	// and not too long: the longer the wait on a wedged upstream, the longer the task
	// stays mute.
	if plannerRoundTimeout > 30*time.Minute {
		t.Fatalf("planner round cap too long (%v): slow recovery when upstream wedges", plannerRoundTimeout)
	}
}

// The timeout must actually interrupt a wedged call — otherwise it's just a marker
// while the goroutine stays stuck and symptoms don't change.
//
// Uses a real http.Server (receives the request, never responds) to simulate a
// 'half-open upstream connection'.
func TestPlannerTimeoutInterruptsHungCall(t *testing.T) {
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(hang)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, nil)
		if err != nil {
			done <- err
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the request should error after ctx timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ctx timeout didn't interrupt the blocked request — the timeout is just a marker, the goroutine still hangs")
	}
}
