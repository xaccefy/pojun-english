package server

import (
	"testing"
	"time"
)

// The task-level timeout wrap-up window must give **every** worker time to finish its
// settlement.
//
// Regression background (measured in production 2026-10-21): task 3's 12 workers were all
// running when the timeout hit at 13:42:23; at 13:43:53 (90s later) the drain timed out
// and hard-cancelled — each worker only managed 1–3 facts, and in-flight results were
// lost outright.
//
// Workers settle **in parallel**, so the window doesn't scale with worker count; but
// each worker's settlement needs at least 1 LLM round (write results + wrap-up summary),
// and a thinking model (minimax-m3.1) takes 30–60s per round — 90s fit only '1 LLM round
// + a little slack', and anything slower got cut.
//
// 300s budgets '2 LLM rounds (write-back + summary) + slack' — enough for 12 workers
// writing back in parallel.
func TestSettleDrainGraceCoversOneSettlementRound(t *testing.T) {
	// worst-case settlement: 1 round writing results + 1 round summary, 60s each.
	const perSettlement = 120 * time.Second
	if settleDrainGrace < perSettlement {
		t.Errorf("settleDrainGrace = %v, must at least fit one full settlement (%v)",
			settleDrainGrace, perSettlement)
	}
	// and not too long: the drain window caps total wrap-up time; too long makes users
	// wait pointlessly (task is due but state won't change). 10 minutes is the ceiling.
	const maxGrace = 10 * time.Minute
	if settleDrainGrace > maxGrace {
		t.Errorf("settleDrainGrace = %v is too long — wrap-up shouldn't wait this long (cap %v)",
			settleDrainGrace, maxGrace)
	}
}
