package server

import (
	"testing"
)

// agentRunSeconds' fallback when the DB/row is unreadable must be 1200 (= seed default),
// never 3600.
//
// Regression background (2026-10-21): the fallback used to be 3600. On a DB read
// failure every agent's per-run budget jumped to 1 hour — and 3600s measured exactly
// '4 intents ran a full hour, 4.1 machine-hours, zero facts produced'. The fallback's
// job is precisely 'don't make things worse when the DB misbehaves', so it must follow
// the seed default, not 'whatever value someone once changed it to'.
func TestAgentRunSecondsFallbackMatchesSeedDefault(t *testing.T) {
	// a Server without a DB: no config readable → falls back.
	s := &Server{}
	got := s.agentRunSeconds("worker")
	if got != 1200 {
		t.Errorf("agentRunSeconds fallback = %d, want 1200 (must match the seed default)", got)
	}
	// the fallback also can't be 'unlimited' — that would disable the budget entirely.
	if got == 0 {
		t.Error("fallback must not be 0 (unlimited)")
	}
}
