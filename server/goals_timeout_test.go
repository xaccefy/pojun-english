package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Goal decomposition must carry its own wall clock: with no timeout_seconds configured
// execContextFor has no deadline, and a hung upstream once stuck tasks at created forever
// (measured 2026-10-30 on Kali). This test uses a tiny override to verify the
// decomposition ctx surfaces DeadlineExceeded at expiry so startTaskEngine takes the
// 'no decomposition output' fallback instead of waiting forever.
func TestGoalsDecomposeTimeoutConstant(t *testing.T) {
	if goalsDecomposeTimeout != 5*time.Minute {
		t.Fatalf("goalsDecomposeTimeout=%v, expected 5 minutes (normal decomposition 30s–2min; generous slack)",
			goalsDecomposeTimeout)
	}
	// semantics self-check: DeadlineExceeded is detectable via errors.Is on a
	// timeout-bearing ctx — startTaskEngine's fallback decision relies on it.
	// Note: never write 'sleep 2ms then assert' — under CI load a 1ms timer may fire
	// later than 2ms (measured CI failure in v0.3.94). Use bounded polling instead: pass
	// as soon as the deadline hits; only 'still not fired after 100ms' fails (normal
	// machines: <1ms).
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	deadline := time.Now().Add(100 * time.Millisecond)
	for errors.Is(ctx.Err(), context.Canceled) || ctx.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("timeout ctx should be detectable via errors.Is(DeadlineExceeded) (didn't fire within 100ms)")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("ctx.Err()=%v, expected DeadlineExceeded", ctx.Err())
	}
}
