package agent

import (
	"testing"
	"time"
)

// Repeatedly failing compactions must back off — else they become a 'burn 5 minutes every minute' futile loop.
//
// Background: one failed compaction burns hundreds of seconds of LLM time (measured: thinking models
// think 300+s on long input before giving up), while the base cooldown is only 60s. Compaction failure
// doesn't block the main flow (planner reads raw nodes without a digest) — the backoff just saves resources.
func TestCompactionBackoffOnRepeatedFailure(t *testing.T) {
	c := NewCompactor(&fakeProvider{}, "m")
	base := c.cooldown

	if got := c.cooldownFor(1); got != base {
		t.Fatalf("initial cooldown should be %v, got %v", base, got)
	}

	// consecutive failures: cooldown grows exponentially
	want := []time.Duration{base * 2, base * 4, base * 8}
	for i, w := range want {
		c.recordResult(1, false)
		if got := c.cooldownFor(1); got != w {
			t.Errorf("after failure %d cooldown should be %v, got %v", i+1, w, got)
		}
	}

	// one success resets
	c.recordResult(1, true)
	if got := c.cooldownFor(1); got != base {
		t.Errorf("after success cooldown should return to %v, got %v", base, got)
	}
}

// Backoff has a cap (30 min) — doesn't grow without bound.
func TestCompactionBackoffIsCapped(t *testing.T) {
	c := NewCompactor(&fakeProvider{}, "m")
	for i := 0; i < 20; i++ {
		c.recordResult(7, false)
	}
	if got := c.cooldownFor(7); got > 30*time.Minute {
		t.Errorf("backoff should cap at 30 min, got %v", got)
	}
}

// Explorations don't affect each other.
func TestCompactionBackoffIsPerExploration(t *testing.T) {
	c := NewCompactor(&fakeProvider{}, "m")
	base := c.cooldown
	c.recordResult(1, false)
	c.recordResult(1, false)
	if got := c.cooldownFor(2); got != base {
		t.Errorf("exploration 2's cooldown shouldn't be affected by exploration 1, got %v", got)
	}
}
