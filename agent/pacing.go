package agent

import "fmt"

// Dispatch pacing (v0.6 backpressure; v0.10 soft-advised; v0.9.6 changed to 'per-round cap'): a code tail,
// permanently in the planner prompt.
//
// Background: live task #4 piled up 12 open intents in 24 min with only 3 workers;
// task #20 (2026-11-13 audit) backlogged to 71 open, production:consumption ≈ 2.5:1, oldest queued 6h.
// v0.8's full release (soft advice only) couldn't constrain; v0.6's total-count hard reject stalled adaptive
// dispatch — so it became 'this-round add cap': the higher the backlog, the fewer this round may add, while plan rounds keep running.
func pacingPlannerGuidance(limit, workers, active int) string {
	if limit <= 0 {
		return fmt.Sprintf(`
[Dispatch pacing (advisory, not a hard cap)]
- Current unfinished intents (open+running): %d, workers: %d; the platform doesn't reject new intents.
- With intents running or a backlog, add at most 1-2 this round; only when frontier is empty AND nothing runs may you dispatch 3-5 at once.
- Before dispatching a new direction, check recent completed intents' output: continue/deep-dive when possible rather than starting fresh — re-dispatching the same direction dilutes worker attention.
- When a conclusion already refutes a queued intent's premise, retire it via retire_intent (with reason) — don't let workers run it for nothing.
- Retirement guardrail: at most 6 per round; dedupe-retirement must give superseded_by (pointing at an open/running/done replacement), never at already-retired ones;
  claiming 'premise invalidated' requires citing the fact/finding node ID that refutes it in reason.`, active, workers)
	}
	return fmt.Sprintf(`
[Dispatch pacing (hard constraint for this task)]
- Current unfinished intents (open+running): %d, threshold %d, workers: %d.
- At threshold, this round's add_intent gets platform-rejected (new adds only — planning isn't frozen): you can still read results, prove_goal, write facts, retire_intent.
- With intents running or a backlog, add at most 1-2 this round; only when frontier is empty AND nothing runs may you dispatch 3-5 at once.
- Before dispatching a new direction, check recent completed intents' output: continue/deep-dive when possible rather than starting fresh.
- When a conclusion already refutes a queued intent's premise, retire it via retire_intent (with reason) — the oldest few in the backlog, if invalidated, should be cleaned proactively.
- Retirement guardrail: at most 6 per round; dedupe-retirement must give superseded_by (pointing at an open/running/done replacement), never at already-retired ones;
  claiming 'premise invalidated' requires citing the fact/finding node ID that refutes it in reason.`, active, limit, workers)
}
