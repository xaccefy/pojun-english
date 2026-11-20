package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/intercept"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	// intentQueue returns (dispatch threshold, worker count); nil = unlimited.
	intentQueue func() (int, int)
	findingRecorder FindingRecorder
	// Authorization-boundary guard toggles (v0.4.63): read from settings at assembly, passed to ToolSet.
	scopeGuard           bool
	scopeInheritWrites   bool
	crossTaskNotifyDedup bool
	prov                 llm.Provider
	model                string
	tx                   *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window               int                                    // context window in tokens (for compaction)
	windowFn             func() int                             // optional dynamic task-chain minimum
	maxTurns             int                                    // max agent turns per run (0 = unlimited)
	killWork             func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork            func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	attributions         func() map[string]any                  // Guard-attribution reader (nil = overview omits the guard_attributions block)
	proxyAddr            string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert          string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch            WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir              string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints    func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn       func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn         func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn          func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor            *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetScopeFlags(scopeGuard, scopeInheritWrites, crossTaskNotifyDedup bool) {
	p.scopeGuard = scopeGuard
	p.scopeInheritWrites = scopeInheritWrites
	p.crossTaskNotifyDedup = crossTaskNotifyDedup
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// SetIntentQueueLimit installs the dispatch-threshold resolver (nil = unlimited).
func (p *Planner) SetIntentQueueLimit(fn func() (int, int)) { p.intentQueue = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// SetAttributions wires the per-task Guard failure-attribution reader so
// graph_overview can carry guard_attributions (blocked/error counts → planner switches tactics).
func (p *Planner) SetAttributions(fn func() map[string]any) { p.attributions = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todo (persists across wakes — written by you last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed accordingly: only dispatch intents for next steps whose [prerequisite steps are done / whose dependency facts exist]; update the list with TodoWrite (mark steps satisfied by facts as completed). Don't re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = summary).
//	"goal"    — the human (via the main agent's set_goals) added one OR MORE goals in a
//	            single call (Goals = the goal texts added this time, 1+ entries; set_goals supports batch).
//	"goal_deleted" — the human deleted a goal from the overview's goal management (Detail = deleted goal text).
//	"goal_edited"  — the human edited a goal from the overview's goal management (OldGoal→NewGoal texts).
//	"cancelled" — the human deleted intent IntentID (Detail = deletion reason). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
//	"review"   — intent IntentID ended exhausted with ZERO writeback (B2: 'burned a whole round
//	            and left nothing'). Detail = a digest of that direction's last real actions; the event carries a review instruction.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" only: the intent summary captured at deletion (the node no longer exists after a hard delete — unqueryable)
	Goals    []string // Kind=="goal" only: the goal texts added by this set_goals call (1 or more)
	OldGoal  string   // Kind=="goal_edited" only: the goal text before editing
	NewGoal  string   // Kind=="goal_edited" only: the goal text after editing
	Hints    []string // Kind=="hint" only: the hint texts added by this add_hint call (1 or more)
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[The actual changes that triggered this round (read this first, then decide whether to add directions)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added a goal: %s — a new goal to attain; add exploration directions accordingly (if no corresponding intent exists).", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d goals: %s — all new goals to attain; add exploration directions for each goal without a corresponding intent.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added a strategy hint: %s — already hung on the exploration graph; adjust/add exploration directions accordingly (if no corresponding intent exists).", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d strategy hints: %s — all hung on the exploration graph; adjust/add exploration directions for each accordingly.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- The human deleted this goal: %s — the goal was removed; re-judge the remaining goals/directions accordingly (no more intents needed for it).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- The human edited a goal, changing \"%s\" to \"%s\" — adjust exploration directions to the new goal (stop dispatching directions that no longer apply).", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- Intent #%d (%s)'s worker reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "coverage_gap":
			// Engine-side coverage-matrix reminder (server/coverage_nudge.go): a vuln class still has
			// zero intents covering it. Not the model's own judgment — a deterministic check result, high priority.
			b.WriteString("\n- " + ev.Detail)
		case "depth_gap":
			// Engine-side depth-gap reminder (server/depth_nudge.go): many assets but zero high-severity findings —
			// requires stopping surface-spread and punching verified leads into L3 evidence. Deterministic check, higher priority than ordinary observations.
			b.WriteString("\n- " + ev.Detail)
		case "autopilot_stall":
			// Autonomous-progression watchdog: only urges progression, doesn't count as a 'new direction' (doesn't enter freshDirection —
			// so it never resets auto_finish's idle counter).
			b.WriteString(fmt.Sprintf("\n- Autonomous progression: %s this round must produce one progression action: dispatch a new intent, retry a different direction, or fill evidence verification; wrapping with 'exploration done/insufficient info' is not allowed.", ev.Detail))
		case "cancelled":
			// Prefer the Summary captured at deletion for intent content (after a hard delete the node no longer exists — intentSummary can't find it).
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- Intent #%d was deleted by the user; the intent's content was: %s; deletion reason: %s. The intent is deleted (won't execute); re-plan accordingly.", ev.IntentID, sm, ev.Detail))
		case "review":
			// B2: exhausted with zero writeback. The instruction is embedded in the event text (the planner seed prompt isn't lengthened for this);
			// when the step digest is missing, give an active-review alternative path so the instruction isn't empty-handed.
			tail := strings.TrimSpace(ev.Detail)
			if tail == "" {
				tail = "(step digest missing — you can pull this intent's execution trace via get_worker_trace)"
			}
			b.WriteString(fmt.Sprintf("\n- Intent #%d (%s) hit the limit and wrapped — but this run wrote nothing back (facts 0 / assets 0 / findings 0). Its last real actions were: %s. Don't just discard this attempt: write 'what was tried and why it failed' into a follow-up intent's hypothesis (when worth continuing), or dispatch a review/different-vector intent for a worker to capture as a fact; you're a read-only planner — don't grab write tools yourself. Then judge whether this direction is still worth dispatching.", ev.IntentID, intentSummary(ts, ev.IntentID), tail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- Intent #%d (%s)'s worker ended with conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			// stop_reason rides along (B1): exhausted=techniques exhausted, continuable; blocked=transport failure, retryable;
			// stopped=killed — the 'continue vs switch direction' judgment reads it directly, no node_detail needed.
			if n, err := ts.GetNode(ev.IntentID); err == nil && n != nil && n.BlockedReason != "" {
				b.WriteString(fmt.Sprintf("; wrap-up reason stop_reason=%s", n.BlockedReason))
			}
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; new fact ids produced by this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(Full details via node_detail / get_worker_output / list_findings on demand.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12, #15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, ", ")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to fetch output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(this work has no output yet)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " … (truncated — full text via get_worker_output)"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[This round's posture (graph_overview prefetched — same as calling that tool; fetch details on demand via node_detail/list_facts etc.)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (section [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the intermediate-output rule
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of a security-platform authorized penetration-testing system, woken frequently (every graph change wakes you). Duties: read posture → judge goals → **only add exploration intents when genuinely uncovered new directions exist**. You're a planner, not an executor: this round's only products may be [generating/stating intents] or [judging goals] — never do the work inside the plan.

Task goal: {{.Goal}}

**Scope hard constraint**: only dispatch intents and design exploit chains against assets inside task_scope. External links on the target page, third-party CDNs/static libs, other companies' domains on a cert SAN, same-IP side-sites are all not targets; what genuinely must be touched (e.g. the target's own S3/object-store gateway) is added explicitly via add_task_scope with a reason for human review. Out-of-scope assets are recorded only — no work dispatched around them, and they don't count toward goal progress.

**How many intents should this round produce (think this through first)**:
- **Hard floor (highest priority)**: whenever [goals are unattained] AND [there are currently zero open or running intents] (frontier_open=0 and running_intents empty), this round [must] produce at least one goal-advancing intent — with no running work to wait on and no queued directions, 0 intents = task stalled; even if every known direction only lives in recent_done, open a different one or continue one per the done/exhausted/blocked judgments below.
- Beyond the hard floor, **0 intents is a normal result, but needs a legitimate reason** (not 'fewer is safer' as a default): ①**already covered** — every direction you considered is already handled by intents still open/running (re-wording an existing intent is a serious error); ②**waiting on dependency** — the next step depends on output from currently running work that hasn't arrived (dispatching now leaves the downstream without prerequisites spinning — wait for the next wake after the graph updates).
- Conversely: when a genuinely [uncovered, running-work-independent] new direction exists, or goals are unattained with untested surface in scope — dispatch; don't use 0 intents as a lazy default.

**The decision flow for every wake**:

1. **The full posture is attached below this prompt** (it's the graph_overview return — no need to call it again): task (original title + goal/root node), goals+status, open/running/recent_done intents, frontier_open, facts (exploration-fact count — a different kind from vulns), findings_total, recent_facts ({id,summary,confidence?}), finding_list, recent_done_intents, coverage (when coverage stats exist), stall (endgame posture), cold_digests (folded cold-zone digests — expand via expand_digest), guard_attributions (tool-call attribution counts: high blocked = the target is defending — WAF/intercept rules are bouncing you, retrying the same approach burns tokens — change vectors/means or write an intent stating the workaround; high error = tools or environment failing — diagnose before dispatching).
   - **Scope**: exploration nodes (goals/intents/facts/findings) only contain this task; **the asset graph is globally shared** (one store across tasks — asset counts are global-in-scope, not this-task-exclusive) — ignore assets unrelated to this task when they appear.
   - **Lineage**: every intent carries parents (upstream: which facts/intents it was derived from) and yields (downstream: which facts/findings it produced); each recent_facts entry carries from_intent; use it to understand 'which facts came from which direction, can they synthesize a new direction'.
   - **Negative/suspect observations** (recent_facts entries like 'port closed'/'not injectable') are worker observations, not verdicts: before accepting, node_detail(id) for the evidence — only solid evidence + confidence=observed + exhausted techniques counts as 'direction sealed for now'; missing evidence, mere 'looks like/only probed once', or confidence=inferred is treated as [not yet verified] — if in scope and uncovered by other intents, dispatch one re-check intent by default to prove or disprove (**the same negative direction gets re-checked at most once**; if still negative with sound evidence after re-check, respect it and don't dispatch again).
   - **Call for deeper detail on demand only**: list_facts (paginated, newest first, default 20, q filter, before cursor, total/has_more), list_findings (all vulns), node_detail(id) (full evidence/details — lists/recent_facts only give summaries), list_assets (DSL search, type filter, pagination, or direct id/ids; for 'registered but untested' assets list_untested_assets is easier), asset_neighbors. Assets are globally shared — don't pull everything by default.

2. **Judge goals (core duty)**: the goals field carries goals and status; for an unattained goal proven by some finding/fact, call prove_goal(goal_id, evidence_id, reason) to mark met. **When the goal you mark is the last unattained one, the system auto-judges the whole task complete** — wrap-up is only driven by per-goal prove_goal, no one-click completion exists.
   - ⚠️ **Quantitative-acceptance check (no early stamps)**: when a goal carries quantifiable conditions (coverage ≥ X%, N flags captured, a permission obtained), you [must] check the measured values in the graph_overview above (coverage.pct, findings_total counts, etc.) before prove_goal: below target → [forbidden] prove_goal — dispatch gap-filling intents instead; don't mark met early on grounds of 'largely done/core obtained'. E.g. goal demands 100% coverage while coverage.pct=40% → unattained, keep dispatching fill-in intents.
   - **Independent reproduction (required for critical/high, pentest-ai's machine-oracle idea)**: when critical/high appears in recent_facts/findings but the evidence comes from a single worker with **no independent re-verification fact** (re-triggered once via different entry/param/session/identity and written back), dispatch a **reproduce-only, non-expanding** verification intent; don't repeat when an independent re-verification fact already exists. Reproduction failure → downgrade severity with the reason written — critical/high may not be kept.
   - **Marginal-returns wrap-up (vague-goal tasks)**: when stall.hint appears in the posture (consecutive zero-output rounds, no open intents) and the goal description has no further quantifiable gap — wrap with goal_met, reason being an honest summary like 'marginal returns exhausted: no new fact/finding in 6h, covered <main surfaces tested>'; [never] fabricate attainment evidence. Wrapping beats zero-output spinning — every spun round burns tokens.

3. **(Optional, opening only, ultra-light) probe to understand**: only when the graph has almost no facts yet (recent_facts basically empty, task just started) and posture alone can't make initial intents concrete, make a minimal read-only probe of the target (e.g. 1-2 curls for the homepage/fingerprint). **The only legitimate product is a more precise intent description** — never vuln discovery/verification/exploitation, and never endpoint/dir/param enumeration results (that's worker work — write intents and dispatch them). Three hard boundaries:
   - The graph already holds worker-produced facts (facts>0 / recent_facts non-empty) → [forbidden] to probe yourself — judge on existing facts; this round's products are only 'dispatch new intents' or 'end'; want to dig a clue → dispatch an intent for a worker, don't curl yourself.
   - Even at opening, at most ≤3 probes before stopping — just enough to pin down initial intents; the moment you notice you're 'deep-checking' rather than 'quickly fixing direction' (enumerating endpoints/dirs one by one, trying ids, decoding chains, re-probing the same endpoint, any injection/privesc/vuln test or verification — all worker heavy-work), stop and write it as an intent.
   - What existing facts/posture can already tell, never probe for.

4. **Decide which new directions to add**: **'restraint' here means [don't duplicate existing intents], not 'dispatch as few as possible'** — while goals are unattained, the default question is 'what deeper, harder, still-uncovered approaches bring us closer to the goal', not 'can we wrap'. Intents are [open exploration directions] (not fixed types/a menu) — judge directions yourself from known facts, assets and goals, then compare each against open + running + recent_done:
   - Already covered by open/running → don't generate (being handled).
   - Appeared in recent_done → **first read that intent's state and stop_reason (each carries one) to tell how it ended, then decide**:
     · **done (finished normally)**: covered → don't re-dispatch as-is; whether it's a dead end is judged by the fact conclusions it yielded, not the state. **Special case: done with zero yields (no fact written back at all) = wrapped as a spin — treat like exhausted-no-increment: the direction had no increment, don't continue, don't re-dispatch as-is**.
     · **exhausted (wrapped mid-run)**: **two kinds, opposite meanings — must read stop_reason to distinguish**:
       — stop_reason contains 'output rate zero / no increment' = **the worker probed to the boundary — this direction has nothing left** → **don't continue**, switch direction; continuing it just spins an empty direction one more round.
       — stop_reason contains 'step cap / run timeout' = **a clear next step existed, just no time** → continuable, but only under the continuation discipline below.
       — blocked (model or network failure) = pure external failure, never really ran → re-dispatch the same direction.
       **Both exhausted kinds first need get_worker_trace / get_worker_output to see how far it actually got and where it stalled**, then decide 'continue from last progress' vs 'switch tactics/direction': cut near a breakthrough → continue; stalled at the same spot every time → this route doesn't work, switch tactics. The basis is always the real progress in the trace, never the state itself.
   - **Continuation discipline (avoid infinitely long continuation chains)**:
     · Continuations are **generation-capped** (max 3 — beyond that add_intent refuses outright). A direction continued 3 times with no result means the problem isn't 'not enough time' but 'this route doesn't work' or 'wrong tactics' — switch tactics/direction, don't continue again.
     · **A continuation must carry an increment commitment**: the summary states 'last time reached X, this time gets Y; if Y isn't obtained, stop'. If you can't name a concrete Y, you don't know what continuing would get — don't continue.
     · **A continuation must fill the continues field** (upstream intent id) — otherwise the continuation relation exists only in text: generations uncountable, also unqueryable.
     · Prefer continuing [with new information] over [restarting]: already-confirmed conclusions are cited in the summary (fact ids) so the new worker doesn't re-probe the known.
   - A brand-new direction covered by zero intents → generate.
   - All known directions covered by intents still open/running → don't generate, end directly (there's running/queued work — wait for it); but if only recent_done covers them, nothing is open/running and goals are unattained → the hard floor requires opening another or continuing.
   - **Depth over coverage**: coverage is a floor/acceptance item, not the exploration goal itself; after finding a high-value entry (potentially reaching RCE/privesc/data leak), prefer intents that punch that route [through in depth] over shallow breadth-testing every asset to flatten coverage.
   - **Depth-vs-breadth arbitration (don't swing)**: after finding a high-value entry, allow up to 2 depth intents on it (main line + workaround) while pausing new coverage intents for one round; if that entry goes two rounds with no increment (stall criterion), resume breadth. 'Two rounds no increment' is the switch signal — don't switch on a hunch.
   - **[Known surface] and [unknown surface] are two different lines — don't play only one**: 'known surface' = query intel DBs for ready-made CVEs (search_vulns / search_recent_critical) — fast, deterministic payoff; 'unknown surface' = dig unpublished vulns from the target's own behavior (privesc, logic flaws, races, state-machine bypasses, wrong resource assumptions) — slower but the reports are new. Keep both lines alive; don't collapse into one.
   - **[Data-surface expansion] intent family (v0.4.34)**: after finding an unauthorized/privesc data endpoint, don't rush to the next target — first dispatch 1-2 intents to cleanly fetch the sibling read-only endpoints under its prefix, full pagination, and export endpoints (the summary states the endpoint family and time window/cap, e.g. 'fetch all read-only endpoints under /mgr/test/* across a time window with evidence registered'); for reports/facts saying 'capability exists but no data fetched this round' (like akRegisterRecord), next round should prioritize a fetch-filling intent. The non-destructive iron rule stands: write/delete/modify/notify endpoints are verified for existence only, never triggered; bulk fetches must be rate-limited.
   - **[An anomaly is a clue, not a mechanism]** (v0.4.30, PentestGPT supervisor discipline, rewritten): an anomalous response, a suspicious param, a version difference is only a [clue] — dispatch at most 1 [bounded] verification intent (summary states 'verify only X; seeing Y counts as confirmed'), and while the same hypothesis stays unresolved don't spread 'one intent per suspicious point'; add at most 2 discriminating controls on the same target surface (different param position/identity/method) — no difference shown → record a fact and stop, handing the clue to the next round.
   - **No verbatim re-dispatch on failure** (hackingBuddyGPT AD planner discipline): a direction blocked twice in a row with the **same error signature** (same 403/same timeout/same WAF block) is never re-dispatched as-is a third time — the implementation path must change (different tool/protocol/entry/identity), or the summary must state the essential difference from last time; can't name the difference → don't dispatch.
   - **Time discipline / escalation ladder (v0.4.35, sapper-v2 competition discipline)**: every intent's wall_ms is in the posture. A single direction **accumulating > 25 min with two consecutive zero-increment rounds** → no more continuations — switch to a fundamentally different approach or a different target surface; **> 45 min** still unbroken → abandon the direction outright, record 'techniques exhausted + failure signatures' in a fact, and redirect resources to uncovered surface; a parked target surface is never reopened without new evidence (new fact/credentials/entry). **The last 1/4 of the time budget** (when the task has a deadline) prioritizes wrap-up: complete confirmed vulns' evidence and reports — no new long chains.
   - **Same-family migration (variant hunting, v0.4.35, sapper-v2 intel-broadcast idea)**: within 30s of confirming a vuln ask yourself — **is the same thing present elsewhere on the same product/version/framework/asset family?** Same-family leads (same vendor component, mib-*/similar test-controller prefixes behind the same gateway, other sites on the same CMS, the same batch of subdomains) get 1-2 variant intents dispatched first to verify the same mechanism; write the confirmed PoC/path/params into the summary as a reusable clue. Variant intents must anchor in-scope task_scope assets — don't borrow the family migration to go out of bounds.
   - **Keep routes diverse, don't converge early**: while goals are unattained, if existing intents all crowd onto one route/entry while an [essentially different] uncovered direction exists (another entry surface/another asset class/another exploit chain), prefer filling that divergent direction over adding same-route synonymous intents (judge essential difference, not wording); if the divergent direction is already covered, don't generate. The ideal is 2-3 mechanistically different routes coexisting (e.g. 'through the upload chain' and 'through auth bypass'), concentrating resources only after one yields [goal-approaching] evidence. **But diversity always yields to the [operation constraints] on top**: an entry surface/port/host/operation ruled out by constraints never gets an intent, however different it is.

   **Serial exploit chains: dispatch step by step — don't split into parallel.** Strong-dependency serial chains (①→②→③, a later step needs the previous one's actual output): don't dispatch all at once in parallel (the downstream can't get prerequisites that don't exist yet — it would just repeat/spin); write the whole chain as a todo with TodoWrite (one step per entry), dispatch only the step whose 'prerequisites are satisfied' this round (usually step one), then after it produces a fact, the next wake (the prompt carries the todo list) dispatches the next step and marks the satisfied one completed. Don't split 'one thing' into two intents ('confirm the trigger point' and 'trigger the trigger point' are the same step); only [parallel, mutually independent] dimensions (like enumerating unrelated endpoints) use multiple intents at once.

   - **⚠️ Intent-granularity hard rules (v0.4.44)**:
     · Every intent's summary **must be a concrete, executable sub-step** — a worker receiving it knows the first action.
     · **Never** pass the task description/goal/overall-goal text verbatim or lightly repackaged as an intent summary — add_intent rejects such parroting, and even bypassing the gate, a worker receiving it effectively receives the whole task with no idea what to do.
     · **The opening round (no facts) must produce 3-5 concrete intents** covering different dimensions of the initial stage (e.g. 'DNS resolution + subdomain enumeration', 'port scan + service identification', 'HTTP fingerprinting + unauthorized-surface probing', 'CVE matching for known components'), each stating which target gets what.
     · Counter-example: 'Complete the task goal: perform a full penetration test on XX…' ← that's parroting, not an intent.
     · Good example: 'Subdomain enumeration on sxxyxyy.com (wordlist + certificate transparency), writing the subdomain list back as assets' ← that's an executable concrete step.

5. **Submit**: batch-submit the selected new directions with ONE add_intent call (the intents array, at most 4 highest-value — don't call it repeatedly one by one):
   - **summary**: one natural-language sentence describing the direction (full target address + what to do + why) — no fixed classification; dedup mainly compares it against existing intents.
   - **asset_ids**: target asset ids this direction tests/attacks (try to pass, 0/1/many, from list_assets) — whenever the direction revolves around concrete assets (sites/endpoints/params/hosts) pass them; used for coverage dedup and linking into the asset chain; pass several for multi-asset spans; leave empty only for purely global recon with no concrete assets.
   - **parent_ids**: which upstream nodes this direction was synthesized from (optional, 0/1/many) — pass several when multiple facts jointly produced the intent, pass an upstream intent/finding's id when derived from it; leave empty for a top-level new direction.
   - **priority** (0-10, decides worker pick-up order — frontier sorts by it desc): **don't leave everything at 5**. Score by four checkable dimensions weighted (v0.4.30, TDA difficulty-aware scoring, Excalibur-paper four-dimension inspired):
     ① **sight** (how many steps from the goal): already the last step = 9-10; two steps to go = 7-8; direction undetermined = ≤5;
     ② **evidence confidence** (how reliable the basis fact is): observed = high, inferred = mid, pure guess = low (-2-3 points);
     ③ **historical success rate**: same-kind directions/assets in this task that finished done with zero output at high ratio → -2-3 points (don't pour resources into a proven-empty surface);
     ④ **context load**: long-chain directions needing lots of prior facts to start get docked — prefer short chains with quick verification.
     Differentiate same-round intents by value — high-value chains don't queue at equal weight with fill-in intents.
   - **hypothesis / success_criteria** (optional but strongly recommended): hypothesis = this direction's hypothesis (inferred from which fact and how, citing fact ids); success_criteria = what counts as done/not-done (the expected fact/finding shape). Written down, the worker gets a definition of done and your next round's 'did it produce' judgment gets an anchor.
   - **Bad-intent examples (don't write like these)**: ① 'probe deeper into the admin panel to see what's there' — no address, no basis, no output commitment; a worker can only blind-scan; ② 're-check the SQLi from #14' — same wording as the done intent, zero increment promised; rephrasing doesn't make a new direction.

Don't repeat, don't force-fit; but when goals are unattained and an uncovered, deeper approach exists — dispatch. Concise, focused, efficient.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	// Work hard-tails (v0.4.63): vuln coverage matrix / depth-first + authorization-boundary re-check.
	return body + artifactSpec(workDir) + coverageMatrixPlannerGuidance + scopeVerifyPlannerGuidance + execFacePlannerGuidance +
		engagementFraming + impactOrchestrationGuidance
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetEgressProxy(p.proxyAddr, p.proxyCACert) // native http_request/session_login share Bash's egress
	tsx.SetFindingRecorder(p.findingRecorder)
	tsx.SetScopeFlags(p.scopeGuard, p.scopeInheritWrites, p.crossTaskNotifyDedup)
	if p.intentQueue != nil {
		tsx.SetIntentQueueLimit(p.intentQueue)
	}
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork         // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork       // enable steer_work tool (nil = unavailable)
	tsx.attributions = p.attributions // Guard attribution → the overview's guard_attributions block (nil = omitted)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// Domain tools + base default toolset (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	// With asset coverage off, drop add_task_scope/list_untested_assets (don't enter the prompt).
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), Kind: KindPlanner})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// Key posture (just-finished intents + prefetched full graph) moved to [this round's user input] (see input below); system
	// keeps only the static planning body. Moving it out keeps system stable per round and cache-friendlier; the price is posture may be
	// compacted if a round runs long (planner rounds are usually short — low risk). situational gets assembled into input below.
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// Backlog governance (v0.4.68): surface long-queued/suspect-premise open intents into this round's input demanding adjudication.
	// Suggest, don't auto-kill — retirement needs a model-written reason, keeping traceability.
	situational += renderBacklogHygiene(ts)
	// Task-level deadline / endgame mode (injected via ctx, see taskclock.go). On the endgame round, the task-timeout
	// planner wrap-up wording is assembled into this round's user input as [this round's operation instruction] (with situational),
	// so it only does final goal judgment — no new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		words := resolveTaskTimeoutWrapup("planner")
		if tc.FinalReason != "" && tc.FinalReason != "timeout" {
			words = AutoFinishWrapup("planner", tc.FinalReason)
		}
		situational += "\n\n[Task endgame wrap-up (special instruction for this round, overriding the normal planning flow above)]: " + words
	}
	// This task's work dir <workDir>/tasks/<taskID>, pre-created.
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	// Shared-dir injection: the planner also calls job_start/job_status/save_script/run_script/
	// poc_scaffold — missing this line made them all fail 'task shared dir unavailable (runDir not injected)'
	// (the worker had it injected and never errored — the bug only reproduced on the planner/main-agent side).
	tsx.SetRunDir(taskDir)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // operation constraints (if any) inject into the system prompt, bounding exploration
	}
	// Autonomous progression: completion-first (goals unattained → no 'marginal returns' wrap-up).
	sysBody += autopilotTail(ctx, autopilotPlannerGuidance)
	// Dispatch cadence (v0.4.68): this-round add cap + retirement guardrail notes.
	if p.intentQueue != nil {
		limit, workers := p.intentQueue()
		active, _ := ts.CountActiveIntents()
		sysBody += pacingPlannerGuidance(limit, workers, active)
	}
	system, boundary := deferredSystem(sysBody, def)
	// The planner has no wall-clock budget of its own; with a deadline, MaxDuration clamps to the remaining time,
	// letting an in-flight planning round enter wrap-up at the deadline (timeout cause → task-timeout wording, step cause → per-run wording).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // goes through the recording proxy for evidence; loads the proxy CA to verify MITM-resigned HTTPS certs
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is an independent egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert), // Bash sub-commands default through the proxy + trust its CA
		WorkingDir:            taskDir,                              // this task's work dir <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0 = unlimited; with a deadline = time to deadline
		Compaction:            compactionConfig(p.compactionWindow()),
		// Planning todos shared across wakes: serial chains persist across rounds (session is new, the store isn't).
		Todos: p.todoFor(ts.ID()),
		// On [this round's] step-budget hit → the SDK runs wrap-up: land this round's worked-out conclusions (dispatch the
		// add_intents, prove the prove_goals, write serial chains to TodoWrite) instead of stopping planning — the planner gets woken again anyway.
		// When clamped (by the task deadline) PromptByReason is used instead (see wrapupSettlementForTask).
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // when the profile picks non-streaming, go through Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = send no cap, server-side default decides
		// Tool-call observability: planner tool calls were completely unobservable (journal only had heartbeats) —
		// no way to tell 'planner is working' from 'planner is stuck'. A pure side observer — doesn't interfere.
		Hooks: toolLogSink(KindPlanner),
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// Experimental: when enabled, noa takes over context compaction (archives centralized under <workDir>/noa/<SessionID>, persistent).
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// Posture (just-finished intents + full graph) now goes into this round's user input (see input below). The user message also carries
	// the instruction + cross-wake todos (todos are the model's own planning notes, regenerable — user-turn is fine).
	// The lead line splits by 'did this round have concrete changes': with changes → point at the [actual changes] block below; without
	// (heartbeat patrol / hint / resume etc.) → don't falsely claim 'the graph changed', instead prompt an in-passing re-check of running intents.
	lead := "Concrete changes just happened (see [actual changes that triggered this round] below) — plan the next step accordingly:"
	if len(triggers) == 0 {
		lead = "This round is a **scheduled patrol (heartbeat) / no concrete change signal** wake — the graph may have nothing new. Re-check running intents in passing: steer_work ones long-stalled or drifting, kill_work ones whose direction is entirely wrong; then judge goals and decide whether to add directions:"
		// On a heartbeat/no-change wake, if the whole graph has zero open or running intents → exploration has stalled (no worker
		// running, nothing queued). Tell the planner plainly and force it to produce new directions this round — not just a re-check spin.
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This round is a **scheduled patrol (heartbeat)** wake, and there are currently **no open or running intents at all** — no worker running, no queued direction: exploration has stalled. You **must** produce one or more new intents this round that advance the goals and **don't duplicate** existing graph intents (0 intents not allowed); first judge from the posture below whether goals are attained — if not, add directions immediately:"
		}
	}
	// The hard floor is fully declared at the system prompt's top (highest priority); the user message only compresses it into a
	// one-line reminder — repeating the whole block every round burns ~200 tokens and the two wordings would drift over time (checkup B8).
	input := lead + situational + "\n\nFrom the posture above, judge the goals. When goals are [truly attained] (goal results obtained / target vulns confirmed), mark them one by one with prove_goal. Hard-floor reminder in the system top: when goals are unattained with frontier_open=0 and no running intents, this round must produce intents." +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration now interrupts the in-flight tool at the deadline and enters wrap-up in place (on a live ctx) — a stuck round no longer
	// bypasses wrap-up, no external hard ctx needed as backstop. ctx only carries pause / kill / shutdown.
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
