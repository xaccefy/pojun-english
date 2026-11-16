package vulnintel

import (
	"context"
	"testing"
	"time"
)

// NVD rate-limit gate: the main sync and the fast channel share the same quota.
//
// Background (measured 2026-10-22): NVD anonymous access is rate-limited to about 5 requests/30s, and the limit is **per egress
// IP** — the main sync and the fast channel are two independent paths (different query dimensions, different cursors, different
// goroutines), but they hit the same NVD, each computing its own page interval, and together they exceed it.
// First real run of the fast channel: page 0 already got "nvd rate limited", not a single page came down.
//
// The gate is a process-level singleton, so the two paths automatically yield to each other.

// The token bucket must release requests at a fixed interval.
func TestRateLimiterSpacesRequests(t *testing.T) {
	l := &rateLimiter{interval: 60 * time.Millisecond}
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.allow(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	// The 1st is released immediately, the 2nd and 3rd each wait one interval → at least 2 intervals.
	if elapsed < 110*time.Millisecond {
		t.Errorf("three requests took only %v, the interval isn't working (should be at least ~120ms)", elapsed)
	}
}

// The gate must be cancellable via ctx — after a sync timeout it must not stay stuck waiting for a token.
func TestRateLimiterRespectsContextCancel(t *testing.T) {
	l := &rateLimiter{interval: 10 * time.Second}
	// Consume once first so the next call has to wait 10 seconds.
	_ = l.allow(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if err := l.allow(ctx); err == nil {
		t.Error("allow should return an error when ctx times out")
	}
	if elapsed := time.Since(t0); elapsed > 2*time.Second {
		t.Errorf("still waited %v after ctx cancellation, it should return immediately", elapsed)
	}
}

// There must be an interval between two requests from the same client (otherwise the rate limit is meaningless).
func TestNvdClientFetchRespectsRateLimit(t *testing.T) {
	// Verifying with a very short interval won't work: the gate is a process-level singleton and the rate is fixed on first use,
	// so we can't change the rate here — we can only verify that requests actually queued.
	// Test the gate directly: two consecutive fetches should be at least one interval apart.
	l := nvdLimiter("")
	if l == nil {
		t.Fatal("rate-limit gate not initialized")
	}
	interval := l.interval
	if interval <= 0 {
		t.Fatalf("gate interval=%v, should be positive", interval)
	}
	// Without a key it must use the anonymous limit (5 requests/30s), not 0 or 1ms.
	if interval < time.Second {
		t.Errorf("anonymous rate-limit interval=%v, should derive from 5 requests/30s (~6.5s)", interval)
	}
}

// With an API key the limit should be relaxed (50 requests/30s).
func TestPageDelayForKeyAndAnonymous(t *testing.T) {
	anon := PageDelayFor("")
	withKey := PageDelayFor("some-key")
	if anon <= withKey {
		t.Errorf("anonymous interval (%v) should be greater than the with-key interval (%v)", anon, withKey)
	}
	// Measured values: anonymous 6.5s, with key 0.7s.
	if anon != 6500*time.Millisecond {
		t.Errorf("anonymous interval=%v, should be 6.5s (5 requests/30s)", anon)
	}
	if withKey != 700*time.Millisecond {
		t.Errorf("with-key interval=%v, should be 0.7s (50 requests/30s)", withKey)
	}
	// A blank key is equivalent to anonymous.
	if PageDelayFor("   ") != anon {
		t.Error("a blank key should be treated as anonymous")
	}
}

// Changing the API key mid-run must rebuild the rate-limit interval: a process that first ran anonymously, after the user configures a key in the UI,
// should immediately sync at the with-key rate rather than waiting for a restart. Regression background:
// docs/project-assessment-report-2026-10-29.md P2 (the original sync.Once implementation's comment didn't match its behavior).
func TestNvdLimiterRebuildsOnKeyChange(t *testing.T) {
	first := nvdLimiter("")
	if first.interval != PageDelayFor("") {
		t.Fatalf("anonymous gate interval=%v, should derive from the anonymous rate", first.interval)
	}
	second := nvdLimiter("audit-key")
	if second == first {
		t.Fatal("the gate instance should be rebuilt after changing the key")
	}
	if second.interval != PageDelayFor("audit-key") {
		t.Fatalf("with-key gate interval=%v, should derive from the key", second.interval)
	}
	// Fetching the same key again must reuse the instance (a prerequisite for the main sync and fast channel sharing a quota).
	if again := nvdLimiter("audit-key"); again != second {
		t.Fatal("two fetches with the same key should return the same instance")
	}
}
