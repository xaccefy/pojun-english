package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Autumn-27/norma/harness"
)

// Wrap-up prompt (settlement prompt): when an agent gets terminated for [step exhaustion (MaxTurns)] or
// [timeout (run_seconds/MaxDuration)], the SDK's settlement phase injects this prompt,
// letting the agent persist identified-but-unwritten content first, then output a one-line summary — no dead ends.
//
// Each agent's wrap-up prompt can be overridden in the backend (agents.wrapup_prompt); empty = the built-in
// default here. Only the [prompt body] is editable; which tools are disabled and the wrap-up's own round budget are fixed code policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, keyed by agent. worker reuses the historically hardcoded settleWrapUpPrompt
// (defined in worker.go); planner/mainagent each get one; unmatched (custom agents) get the generic fallback.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: each agent's wrap-up-phase [own] round-budget default (backend can override with >0).
// All get 10 rounds — enough steps for the wrap-up to persist things. Unmatched → genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    10,
	"planner":   10,
	"mainagent": 10,
}

const genericWrapupTurns = 10

const plannerWrapUpDefault = "Your planning steps for this round are almost exhausted — note only [this round] is ending; the system will wake you again as the posture changes — this is NOT task termination, no need to close out the whole plan. Land the conclusions you've already reached this round so it isn't wasted, but [don't force intents just to wrap up] (0 intents this round is a perfectly normal result): (1) for exploration directions you've judged [should be dispatched now], submit them in one batch via add_intent (don't sit on decided intents); (2) for goals proven achieved by some finding/fact, mark met via prove_goal (don't miss judgments); (3) for identified serial exploit chains needing steps, note them in TodoWrite so the next wake-up continues. Then just end the round — no summary text needed."

const mainAgentWrapUpDefault = "Your steps are almost exhausted — this interaction is ending. Start no new explorations/operations. Summarize current progress, key conclusions and suggested next steps to the user in **a single plain-text sentence**."

const genericWrapUpDefault = "You're about to be terminated for budget exhaustion. First write back completed-but-unpersisted results, then summarize what you did and key conclusions in **a single plain-text sentence** (shown as this run's result)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
// settlementDisabledTools returns tools to hide during wrap-up: hiding only Bash isn't enough — job_start,
// http_request, session_login, listener_*, payment_* etc. can all bypass Bash to keep executing/hitting the target,
// the wrap-up budget gets eaten by new probes and the real record_fact/report_finding never finishes.
func settlementDisabledTools() []string {
	out := make([]string, 0, len(localExecToolNames)+12)
	for name := range localExecToolNames {
		out = append(out, name)
	}
	out = append(out,
		"Monitor", // SDK background task: can run shell
		"shell_open", "shell_exec", "shell_input", "shell_close", "shell_list", "shell_write",
		// Execute/target-touching tools that bypass Bash (every one named in the comment must really be hidden):
		"job_start", "job_stop", "job_status", "job_output",
		"http_request", "session_login", "session_request",
		"listener_start", "listener_stop", "listener_sessions",
		"payment_probe", "payment_verify",
		"run_script", "poc_scaffold", "http_probe", "diff_responses",
	)
	sort.Strings(out)
	return out
}

func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// ---------- Task-level timeout wrap-up prompts (see docs/task-timeout-and-wrapup design) ----------
//
// These are [two different sets] from per-run prompts: per-run = 'this run's budget is spent'; task timeout =
// 'the whole task is at its deadline, about to end'. Semantics are often opposite (esp. planner: per-run says
// 'don't stop, keep planning'; task timeout says 'stop planning, make the final judgment'). Only worker/planner get them.

// WrapupTaskTimeoutOverride / …TurnsOverride: DB overrides for task-timeout prompt and rounds
// (wired to agents.task_timeout_wrapup_prompt / _max_turns, worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The whole task has hit its timeout cap and is about to end** (not this run's budget — the entire engagement is at deadline). Last chance: (1) persist [everything] you've identified but not yet written back — new assets via insert_assets, exploration conclusions/facts via record_fact, confirmed vulns via report_finding; (2) start no new commands/probes; (3) **finish with a single plain-text sentence** summarizing your key conclusions for this intent."

const plannerTaskTimeoutDefault = "**The whole task has hit its timeout cap and is about to end** (not this round — the whole task terminates). Based on [all] current facts and findings, make a final goal judgment: mark met via prove_goal for goals proven by evidence (don't miss judgments). **Generate no new intents** (any dispatched now won't run anyway). Close after judging — no summary text needed."

const plannerAutoFinishDefault = "**The whole task has ended per the auto-finish policy** (reason: %s) — not a timeout, not this round's budget. Based on [all] current facts and findings make a final goal judgment: mark met via prove_goal for goals proven by evidence (don't miss judgments); **generate no new intents** (dispatched ones won't run anyway). Finish with a one-sentence summary of the task's main outputs and uncovered scope."

func autoFinishReasonText(reason string) string {
	switch reason {
	case "auto_idle":
		return "no new facts/findings/tested-assets for many consecutive rounds — marginal yield hit zero"
	case "auto_coverage":
		return "asset coverage reached the configured threshold"
	case "auto_rounds":
		return "hit the maximum planning-round cap"
	default:
		return reason
	}
}

// AutoFinishWrapup returns the auto-finish planner endgame prompt (built-in — not overridable on the Agent page).
func AutoFinishWrapup(agentKey, reason string) string {
	if agentKey != "planner" {
		return ""
	}
	return fmt.Sprintf(plannerAutoFinishDefault, autoFinishReasonText(reason))
}

// TaskTimeoutWrapupDefault returns an agent's built-in task-timeout prompt (backend placeholder/restore-default).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // unconfigured (mainagent/chat) returns ""
}

// resolveTaskTimeoutWrapup: DB override (non-empty) > built-in default. Empty means this agent has no
// task-timeout prompt (non worker/planner) — the caller should fall back to the per-run prompt.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // default follows per-run rounds
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  → this run is squeezed by the task deadline: Timeout wrap-up = task deadline → task-timeout prompt;
//     MaxTurns wrap-up = steps ran out inside the squeeze window while the task still has minutes → fall back to per-run prompt.
//   - clamped=false → the task has plenty of time: both reasons use the per-run prompt (degrades to wrapupSettlement).
//
// The PromptByReason handed to harness picks by the [actual] reason at wrap-up time — no build-time mismatch.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // fallback (and the value for both reasons when not clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // task at deadline
				harness.ReasonMaxTurns: perRun, // steps ran out first, task still has time
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
