package agent

import (
	"context"

	"github.com/chu0119/pojun/intercept"
)

// The prompt tail for autonomous progression (Autopilot).
//
// Same mechanism as the kb/domain tails: **code-concatenated, always present** — immune to UI prompt edits.
// Only appended when the task has autopilot on (see ctx-resolver calls in planner.go / worker.go);
// normal tasks never see these constraints — behavior unchanged.
//
// Writing rules:
//   - Express only 'must keep progressing; unfinished goals don't count as done' — don't repeat what kb/
//     grey-market tails already cover;
//   - Must yield to endgame wrap-up orders: when the task truly hits deadline/budget cap, wrap-up wins —
//     else the model keeps pushing through wrap-up rounds and fights wrapup.
const autopilotPlannerGuidance = `
[Autopilot mode (ON for this task — these constraints take priority over normal wrap-up habits)]
- Completion first: while no goal is judged achieved, you **may not** wrap up citing 'explored enough /
  insufficient info / low marginal yield'. Every round must produce at least one advancing action: dispatch
  a new intent, retry from another direction, add evidence verification, or write a fact explaining why this
  direction is infeasible before switching.
- With no running intents and goals still unmet, dispatch an intent **immediately** (hard floor, not advice).
- On stagnation, query the knowledge base (kb_search) before switching vectors; never re-dispatch the exact
  intent that just failed. Task may end only when: ① all goals proven via prove_goal/goal_met; or
  ② an explicit endgame wrap-up order arrives (task timeout/budget cap). Otherwise don't self-wrap.
`
const autopilotWorkerGuidance = `
[Autopilot mode (ON for this task)]
- This intent's hypothesis must be proven or disproven to count as done: write back supporting facts
  (fact/asset/finding/evidence) before stopping — no idle wrap-up without write-back.
- On blockers switch vectors first (encoding/path/param position/request method/source IP/time window), and
  kb_search the knowledge base; if still stuck, write 'what was tried, why it failed' as a fact — not just a verdict.
- Never run actions that wait for human input/approval: approvals need human response and stall progression;
  take an equivalent approval-free path (smaller verification / read-only proof) and leave evidence.
- Endgame wrap-up orders win: on a 'task timeout/budget cap' wrap-up message, follow it — open no new fronts.
`
// autopilotTail returns the prompt tail when the task has autopilot on, else empty.
// Wired via ctx resolver (intercept.WithAutopilot injection), sharing one switch with approval bypass:
// flipping the switch mid-run returns next plan/exec round to normal mode.
func autopilotTail(ctx context.Context, tail string) string {
	if ap := intercept.AutopilotFromContext(ctx); ap != nil && ap() {
		return tail
	}
	return ""
}
