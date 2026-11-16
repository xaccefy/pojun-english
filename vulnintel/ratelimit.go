package vulnintel

import (
	"context"
	"sync"
	"time"
)

// NVD rate-limit gate: the main sync and the fast lane **share** one budget.
//
// ## Why it is needed
//
// NVD rate limits are counted **per egress IP**, not per client: about 5 requests/30s
// anonymously and about 50 requests/30s with a key. The main sync and the fast lane are two
// independent paths (different query dimensions, different cursors, different goroutines),
// but they hit **the same NVD** — each computing its own page interval, and together they overrun.
//
// Measured (2026-10-22, the fast lane's first real run): the main sync started at 90s and the
// fast lane at 120s, only 30 seconds apart → the fast lane hit "nvd rate limited" on page 0 and
// did not fetch a single page. Staggering start times only mitigates, never cures (the main sync
// runs 30 minutes per round and the fast lane likewise, so they collide again sooner or later).
// What really needs solving is "the two paths share one budget".
//
// ## Mechanism
//
// One process-level token bucket: one token is released every PageDelay milliseconds and taken
// before a request. The rate is derived from the API key (50/30s with a key, 5/30s without).
//
// Because both paths share one bucket instance they yield to each other automatically — no
// coordination logic is needed.

// rateLimiter is a simple token bucket (releasing at a fixed interval).
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// allow blocks until one request may proceed.
func (l *rateLimiter) allow(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.IsZero() || l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// nvdLimiter is the process-level NVD rate-limit gate.
//
// The rate is derived from the **currently effective API key**: on every request the main sync
// and the fast lane bring the same key from their clients (one configuration), so with an
// unchanged key the same gate instance is reused and the two paths yield to each other
// naturally. When the key changes (e.g. an anonymous run first, then a key configured in the
// UI) it is rebuilt for the new key, equivalent to the state after a process restart.
//
// The rebuild only swaps the interval: requests still waiting on the old instance finish on the
// old timer and are not interrupted.
var (
	nvdLimiterMu   sync.Mutex
	nvdLimiterKey  string
	nvdLimiterInst *rateLimiter
)

// nvdLimiter returns the process-wide NVD rate limiter, rebuilding it when
// the configured API key changes.
func nvdLimiter(apiKey string) *rateLimiter {
	nvdLimiterMu.Lock()
	defer nvdLimiterMu.Unlock()
	if nvdLimiterInst == nil || nvdLimiterKey != apiKey {
		nvdLimiterKey = apiKey
		nvdLimiterInst = &rateLimiter{interval: PageDelayFor(apiKey)}
	}
	return nvdLimiterInst
}

// waitNvdSlot blocks until this request may proceed under the shared NVD
// rate limit.
//
// The wait happens **before every request**, so the main sync and the fast lane naturally yield
// to each other.
func (c *NvdClient) waitNvdSlot(ctx context.Context) error {
	return nvdLimiter(c.APIKey).allow(ctx)
}
