package agent

import "testing"

// With no context window set, it must default to 1M — not 200K.
//
// Regression background: the platform's common minimax-m3.1-flash-free natively has a 1M context (model
// self-reports 1000000), but when the profile's context_window_k was empty the code used 200K (Claude's
// default) for compaction thresholds — compaction fired far below the real cap, costing an extra LLM call
// (plus 32768 output budget) each time: wasted budget, slower flow.
//
// The threshold math is safe at 1M: effectiveWindow = 1M − 20K = 980K, buffer 50K,
// auto-compaction threshold 930K (norma's buffer tiers support >= 800000).
func TestDefaultContextWindowIs1Million(t *testing.T) {
	if defaultWindowK != 1000 {
		t.Errorf("default context window %dK, want 1000K(1M)", defaultWindowK)
	}
	c := Config{}
	got := c.CompactionWindow()
	if got != 1_000_000 {
		t.Errorf("unset should give CompactionWindow=%d, want 1000000", got)
	}
}

// Explicit values win and get clamped into [32K, 1M].
func TestCompactionWindowClamps(t *testing.T) {
	if got := (Config{ContextWindowK: 500}).CompactionWindow(); got != 500_000 {
		t.Errorf("explicit 500K should apply, got %d", got)
	}
	if got := (Config{ContextWindowK: 5}).CompactionWindow(); got != 32_000 {
		t.Errorf("below floor should clamp to 32K, got %d", got)
	}
	if got := (Config{ContextWindowK: 5000}).CompactionWindow(); got != 1_000_000 {
		t.Errorf("above cap should clamp to 1M, got %d", got)
	}
}
