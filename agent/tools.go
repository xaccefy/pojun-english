package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/hosttools"
)

// compactIntents distills intents to {id, summary, state, asset_ids, parents,
// yields} so the planner sees both the direction and its LINEAGE — parents (the
// upstream nodes it derived from: facts/intents/findings) and yields (the facts/
// findings it produced) — without pulling full payloads. parentsOf/yieldsOf are
// built from the exploration edges in graph_overview. tokens (B7, optional) maps
// intent id → llm_usage total tokens — marks each intent with "how much this direction burned"; nil = don't mark.
func compactIntents(ns []*db.Node, parentsOf, yieldsOf map[int64][]int64, tokens map[int64]int64) []map[string]any {
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		m := map[string]any{"id": n.ID, "summary": p["summary"], "state": n.State}
		if len(tokens) > 0 {
			if tok, ok := tokens[n.ID]; ok && tok > 0 {
				m["tokens"] = tok
			}
		}
		// stop_reason (B1): why a terminal intent stopped. The planner prompt requires it to tell
		// "continue vs switch direction" apart (exhausted=techniques exhausted, continuable / blocked=transport failure, retryable /
		// stopped=killed). The field existed in the DB column but the posture never carried it — the planner
		// either guessed or spent 1-3 node_detail reads per intent each round.
		if n.BlockedReason != "" {
			m["stop_reason"] = n.BlockedReason
		}
		// wall_ms (v0.4.27): intent wall clock (settled into payload at runIntent settlement) — the planner sees
		// "how long this direction burned", combined with tokens to judge whether to continue it.
		if wm, ok := p["wall_ms"].(float64); ok && wm > 0 {
			m["wall_ms"] = int64(wm)
		}
		if n.Inherited {
			m["source_task_id"] = n.SourceTaskID
			m["inherited"] = true
		}
		// asset_ids is the structured "which assets this direction covers" signal for
		// dedup; fall back to legacy payload keys (target_ids plural, then target_id
		// single) so intents stored before the rename still surface their anchors.
		if tg, ok := p["asset_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_id"]; ok && tg != nil && tg != "" {
			m["asset_ids"] = []any{tg}
		}
		if ps := parentsOf[n.ID]; len(ps) > 0 {
			m["parents"] = ps // upstream: which nodes this intent was derived from (multiple facts can jointly produce one intent)
		}
		if ys := yieldsOf[n.ID]; len(ys) > 0 {
			m["yields"] = ys // downstream: which facts/findings this intent produced
		}
		out = append(out, m)
	}
	return out
}

// ToolSet exposes the PG-backed dual graph (asset + exploration) to an LLM agent.
// One ToolSet is created per planner/worker run; per-run signals live here.
type ToolSet struct {
	findingRecorder FindingRecorder
	// artifactRecorder is injected by the host (v0.5.0 evidence attachments); nil = archiving unsupported in this env.
	artifactRecorder ArtifactRecorder
	// ── Authorization-boundary guards (v0.4.63) ──
	// Three toggles read from settings by server at assembly (scope_write_guard / scope_inherit_writes /
	// notify_cross_task_dedup); changes take effect on the next intent. All off = old soft-constraint behavior.
	ScopeWriteGuard      bool // writeback-anchor guard: fact/finding can only anchor own-scope assets (default on)
	ScopeInheritWrites   bool // inherited/source-task scope assets are also writable (default off; root-cause switch for asset bleed)
	CrossTaskNotifyDedup bool // same-fingerprint vulns across tasks are not pushed again (default on)
	// egressProxy / egressCA are the egress of the native HTTP executors (http_request/session_login):
	// same source as Bash's HTTP_PROXY (recording MITM or global proxy), keeping traffic evidence consistent.
	egressProxy string
	egressCA    string
	// lastScopeWarnings holds the source/foreign asset notices from the last record_fact —
	// returned to the caller only, writes are not blocked.
	lastScopeWarnings []string
	// lastLowNovelty is the count of "low-novelty" entries in this round's record_fact (highly similar to
	// recent facts or carrying no evidence). Such writebacks still persist, but don't reset the intent lease's zero-writeback timer.
	lastLowNovelty int
	// runDir is this run's dedicated work dir (where the worker produces screenshots/samples),
	// the relative-path base for save_evidence; injected by Worker.Execute.
	runDir string
	as     *db.AssetStore   // asset store (optional; nil = asset tools not available)
	cs     *db.CompanyStore // company store (optional)
	ts     *db.ExplorationStore
	worker string
	taskID int64 // PG tasks.id; 0 when unknown (tests / orchestrator cross-task reads)
	// coverageDisabled mirrors tasks.coverage_enabled=false. Stored inverted so the
	// zero value (all existing ToolSet constructions) means ENABLED — matching the
	// DB default (true). When true: graphOverviewData drops the coverage block, the
	// auto-scope hook (insertAssets) is skipped, and add_task_scope/list_untested_assets
	// are filtered out of the agent's tool list. The scope field stays regardless.
	coverageDisabled bool
	// ownerNode is the exploration node that writes attach to: assets this run
	// touches get anchored to it as lineage/provenance (NOT visibility — the asset
	// graph is global and shared). Worker = its claimed intent; planner = begin root.
	ownerNode int64
	GoalMet   bool
	Reason    string
	writes    WriteCounts
	// lastMissingAssets holds the asset ids referenced by the most recent
	// record_fact call that do NOT exist in the asset table. The tool result
	// reports them back so the model stops reusing a fabricated id.
	lastMissingAssets []int64
	// ── Dispatch throttling (v0.4.68) ──
	// intentQueue returns (threshold, worker count); nil = unlimited (test/main-agent scenarios).
	intentQueue func() (int, int)
	// intentAdded is the number of intents added within this ToolSet's lifetime (one ToolSet per planning round).
	intentAdded int
	// retiredThisRun is the number of intents retired this planning round (guardrail: 6 per round).
	retiredThisRun int
	// intentRequiresGate controls whether the requires_intents serial gate takes effect (default off).
	intentRequiresGate bool
	// killWork, if set, terminates a running work by intent id (engine callback,
	// wired by the planner). nil = the kill_work tool reports unavailable.
	killWork func(intentID int64) error
	// steerWork, if set, queues a mid-run course-correction for the work running an
	// intent id (engine callback, wired by the planner): the worker injects it before
	// its next tool call and re-plans, without being killed. nil = tool unavailable.
	steerWork func(intentID int64, msg string) error
	// enrich, if set, receives async auto-completion triggers (DNS resolve for a
	// domain, HTTP probe for a site). nil = no engine enrichment.
	enrich EnrichTrigger
	// notify, if set, wakes the task's planner after a graph change that should be
	// re-planned promptly (currently: a new hint). nil = no wake (the hint is still
	// stored and read on the next round triggered by other events). debounced.
	notify func()
	// notifyFinding, if set, wakes the task's planner when this run reports a finding,
	// carrying (intentID, summary) so the round can spell out which intent found what.
	// Wired for workers; nil elsewhere → falls back to notify (bare wake).
	notifyFinding func(intentID int64, summary string)
	// resumeTask, if set, revives the task after a graph change that should make a
	// stopped task run again (currently: set_goals adds a goal). It flips a terminal/
	// paused task back to running and (re)starts the engine loops — a plain notify()
	// can't, because the planner's terminal gate swallows wakes. Wired ONLY for the
	// main agent (human steering); nil for the goals decomposer and workers.
	resumeTask func()
	// notifyGoal, if set, wakes the planner AND records ONE "human added N goals: …" trigger
	// for a whole set_goals call (batch-aware — one call, one trigger, not one per goal)
	// so the next round spells out the added goals (instead of the planner having to
	// spot new open goals in the overview). Wired ONLY for the main agent; nil for the
	// goals decomposer (round-0 has no running planner to inform) and workers → those
	// fall back to the bare notify.
	notifyGoal func(texts []string)
	// notifyHint, if set, wakes the planner AND records ONE "human added N strategy hints: …"
	// trigger for a whole add_hint call (batch-aware — one call, one trigger) so the next
	// round is told the round was fired by a new hint and spells the hint out, instead of
	// the planner having to spot it folded into the graph overview. Wired for the main
	// agent + cross-task orchestration; nil elsewhere → falls back to the bare notify.
	notifyHint func(texts []string)
	// attributions, if set, returns Guard failure-attribution stats (ok/blocked/error
	// counts + B6 recent samples, guard/guard.go AttributionStats) for graph_overview
	// guard_attributions block — the planner sees "this task got bounced by WAF/intercept N times,
	// which commands were recently blocked" and changes tactics (v0.3.88 checkup N5 + B6 sample completion). nil = block omitted.
	attributions func() map[string]any
}

// SetAttributions wires the Guard failure-attribution reader (see ToolSet.attributions).
func (t *ToolSet) SetAttributions(fn func() map[string]any) { t.attributions = fn }

// SetNotifyGoal wires the goal-add trigger callback (see ToolSet.notifyGoal). Set only
// by the main-agent chat, so runtime-added goals are announced to the planner by name.
func (t *ToolSet) SetNotifyGoal(fn func([]string)) { t.notifyGoal = fn }

// SetNotifyHint wires the hint-add trigger callback (see ToolSet.notifyHint). Set by
// the main-agent chat and cross-task orchestration, so a runtime-added hint fires a
// planner round announced by name instead of a bare wake.
func (t *ToolSet) SetNotifyHint(fn func([]string)) { t.notifyHint = fn }

// SetResumeTask wires the task-revive callback (see ToolSet.resumeTask). Set only by
// the main-agent chat, so runtime-added goals can pull a finished task back to running.
func (t *ToolSet) SetResumeTask(fn func()) { t.resumeTask = fn }

// SetNotify wires the planner-wake callback (see ToolSet.notify). Set by callers
// that hold the task handle (main-agent chat, cross-task orchestration).
func (t *ToolSet) SetNotify(fn func()) { t.notify = fn }

// SetNotifyFinding wires the finding-wake callback (see ToolSet.notifyFinding).
func (t *ToolSet) SetNotifyFinding(fn func(int64, string)) { t.notifyFinding = fn }

// EnrichTrigger is the enrichment engine seen from the tool layer (see package
// enrich). Kept as an interface here to avoid coupling agent → enrich.
type EnrichTrigger interface {
	ResolveDomain(id int64, host string)
	ProbeSite(id int64, url string)
}

// WriteCounts breaks down what a worker persisted this run, by node kind, so the
// engine can log an accurate "wrote back" summary instead of lumping assets and
// findings under "facts" (record_fact → Facts, insert_assets → Assets,
// report_finding → Findings; each element of a batch counts once).
type WriteCounts struct {
	Facts    int
	Assets   int
	Findings int
}

// Total is every node persisted this run, regardless of kind — the
// "explored but persisted nothing" signal (Total == 0).
func (w WriteCounts) Total() int { return w.Facts + w.Assets + w.Findings }

// String renders the per-kind breakdown for logs, e.g. "facts1 assets25 vulns0".
func (w WriteCounts) String() string {
	return fmt.Sprintf("facts%d assets%d vulns%d", w.Facts, w.Assets, w.Findings)
}

// Writes reports what this run wrote back, split by node kind (so the engine can
// tell "explored but persisted nothing" apart from a completed intent, and log an
// honest breakdown instead of calling assets/findings "facts").
func (t *ToolSet) Writes() WriteCounts { return t.writes }

func NewToolSet(ts *db.ExplorationStore, worker string) *ToolSet {
	return &ToolSet{ts: ts, worker: worker}
}

// SetTaskID sets the PG task id on this ToolSet so that report_finding can
// dual-write to the standalone findings table (which survives task deletion).
func (t *ToolSet) SetTaskID(id int64) { t.taskID = id }

// SetArtifactRecorder injects the evidence-attachment store (host implementation).
func (t *ToolSet) SetArtifactRecorder(r ArtifactRecorder) { t.artifactRecorder = r }

// SetRunDir injects this run's work dir (the relative-path base for save_evidence).
func (t *ToolSet) SetRunDir(dir string) { t.runDir = dir }

// SetScopeFlags (v0.4.63): the three toggles for authorization-boundary guards and cross-task dedup,
// read from settings by server at assembly; changes take effect on the next intent. All off = old soft-constraint behavior.
func (t *ToolSet) SetScopeFlags(scopeGuard, scopeInheritWrites, crossTaskNotifyDedup bool) {
	t.ScopeWriteGuard = scopeGuard
	t.ScopeInheritWrites = scopeInheritWrites
	t.CrossTaskNotifyDedup = crossTaskNotifyDedup
}

// SetCoverageEnabled records whether this task has the asset-coverage feature on
// (default enabled). Passing false makes graphOverviewData omit the coverage block
// and DropCoverageTools filter the two coverage-only tools out of the agent's tool
// list. It does NOT stop scope accumulation: insertAssets' auto-scope hook runs
// either way, because task_scope is the task's range boundary (the filter basis for
// asset queries), not merely a coverage denominator.
func (t *ToolSet) SetCoverageEnabled(enabled bool) { t.coverageDisabled = !enabled }

// CoverageDisabled reports whether the coverage feature is off for this task.
func (t *ToolSet) CoverageDisabled() bool { return t.coverageDisabled }

// coverageOnlyTools are the LLM tools that only make sense when asset coverage is
// on. When the feature is off they are filtered out of the agent's tool list so
// they neither pollute the prompt nor let the model build a disabled denominator.
// add_task_scope is deliberately NOT here: task_scope is the task's range boundary
// (the filter basis for asset queries), not merely a coverage denominator, so the
// agents that own scope definition keep it either way — in lockstep with insertAssets'
// auto-scope hook, which also runs regardless of the switch.
var coverageOnlyTools = map[string]bool{"list_untested_assets": true}

// DropCoverageTools returns tools with the coverage-only ones removed when this
// task has the feature disabled; otherwise it returns tools unchanged.
func (t *ToolSet) DropCoverageTools(tools []actool.CoreTool) []actool.CoreTool {
	if !t.coverageDisabled {
		return tools
	}
	out := tools[:0:0]
	for _, tool := range tools {
		if coverageOnlyTools[tool.Name()] {
			continue
		}
		out = append(out, tool)
	}
	return out
}

// Cross-task reuse: exported accessors returning the per-task tool logic bound to
// THIS ToolSet's store. Host-side orchestration tools build a ToolSet for an
// arbitrary task, then Call these — so cross-task reads/hint reuse the exact
// same logic as the in-task tools. (readTool ignores ToolContext, so Call(…,nil)
// is safe; add_hint is a writeTool but also doesn't deref the context here.)
func (t *ToolSet) GraphOverviewTool() actool.CoreTool      { return t.graphOverview() }
func (t *ToolSet) ListFindingsTool() actool.CoreTool       { return t.listFindings() }
func (t *ToolSet) GetWorkerTraceTool() actool.CoreTool     { return t.getWorkerTrace() }
func (t *ToolSet) ListWorkerTracesTool() actool.CoreTool   { return t.listWorkerTraces() }
func (t *ToolSet) SearchWorkerTracesTool() actool.CoreTool { return t.searchAllWorkerTraces() }
func (t *ToolSet) NodeDetailTool() actool.CoreTool         { return t.nodeDetail() }
func (t *ToolSet) AddHintTool() actool.CoreTool            { return t.addHint() }

// SetEnrich wires the async enrichment engine (DNS/HTTP auto-completion).
func (t *ToolSet) SetEnrich(e EnrichTrigger) { t.enrich = e }

// SetOwnerNode sets the exploration node that writes anchor to (worker: its
// intent node; planner/main: the begin root). Assets created/referenced while
// ownerNode is set are anchored to it as lineage (not visibility).
func (t *ToolSet) SetOwnerNode(id int64) { t.ownerNode = id }

// anchorOwner records a lineage edge from this run's owner node to an asset
// (no-op if unset). Provenance only — the asset graph is global and shared, so
// this no longer affects which assets a task can read.
func (t *ToolSet) anchorOwner(assetID int64) {
	if t.ts != nil && t.ownerNode > 0 && assetID > 0 {
		_ = t.ts.Anchor(t.ownerNode, assetID)
	}
}

// pid parses an id that may arrive as a JSON number or string ("" / 0 → 0).
func pid(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}
	return 0
}

// pidList parses a list of ids (number|string), dropping zeros/invalids.
func pidList(raw []json.RawMessage) []int64 {
	var out []int64
	for _, r := range raw {
		if v := pid(r); v > 0 {
			out = append(out, v)
		}
	}
	return out
}

// maxIntentSummaryRunes is the rune cap for an intent summary.
//
// Why cap it: production measured 205 intents averaging 737 chars, max 2267 —
// far beyond the "one sentence describing the direction" design intent. Over-length causes two concrete problems:
//
//  1. **The planner's judgment distorts**. The planner uses the summary to judge "is this direction close"
//     — the longer and more detailed the summary, the easier the planner thinks "so much info,
//     must be close, give it one more chance". Production shows exhausted(99) far outnumbers done(18),
//     and continuation chains reached three generations (#635→#578→#660). Long summary → more continuations →
//     longer intents → even longer summaries — a positive feedback loop.
//  2. **Writeback gets squeezed out**. The longer the summary, the more tokens the worker spends
//     phrasing it, while detail is where details belong.
//
// Why 400: a complete technical description in one sentence is roughly 100-200 chars; 400 covers
// "goal + what to do + why it's worth doing + where it left off" — with room for one continuation's context.
// Content beyond that length is mostly repeated narration.
//
// Over-limit handling is **truncate keeping the head** (goal + what-to-do at the front), not reject — rejecting
// wastes a whole planner round with zero intents, costlier. A marker is appended at the end so the planner
// knows it was truncated.
const maxIntentSummaryRunes = 400

// clampIntentSummary truncates an over-long summary to the cap, keeping the head (goal + what-to-do at
// the front) and appending a truncation marker.
func clampIntentSummary(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxIntentSummaryRunes {
		return s
	}
	head := string([]rune(s)[:maxIntentSummaryRunes])
	return head + "… (summary over-long, truncated)"
}

// maxContinuationDepth is the max continuation generations allowed on one direction.
//
// Why 3: continuing isn't bad — when a direction was budget-cut but has a clear next step,
// continuing once is right (26 of 205 production intents were continuations). The problem is **no gate**:
// production saw three-generation continuations (#635 → #578 → #660), each rebuilding context from zero,
// re-reading the same files, re-scanning the same assets.
//
// 3 means: a direction can be continued at most 3 times (first probe + 3 continuations = 4 generations). Still no
// result by then means the issue isn't "not enough time" but "this route doesn't work" or "wrong tactics" —
// switch direction instead of continuing.
//
// Deliberately not 2: two continuations are common and legitimate (interrupted by restart + budget cut);
// capping too tight would kill legitimate deep-dives.
const maxContinuationDepth = 3

// continuationDepthOf reads the continuation generation recorded on an intent node.
//
// Old intents (created before this feature) lack the field in payload — return 1 (treat as first probe);
// they never had structured continuation relations and shouldn't be hurt by the generation cap.
func continuationDepthOf(n *db.Node) int {
	if n == nil {
		return 1
	}
	var p map[string]any
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		return 1
	}
	switch v := p["continuation_depth"].(type) {
	case float64:
		if v >= 1 {
			return int(v)
		}
	case int:
		if v >= 1 {
			return v
		}
	}
	return 1
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}
func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func intp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func idp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func readTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func writeTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// readExpTool / writeExpTool build a domain tool whose handler dereferences the
// task-bound ExplorationStore. Two ToolSets carry a nil store: the catalog's
// seed-only shell (never called) and the server-level one behind buildDomainReg,
// which the tools table can bind to ANY agent — including ones that never run
// inside a task (auto/pentest/reporter/custom agent/side-question). Refusing there
// keeps a mis-bound tool a bad tool call; without the guard it was a nil deref,
// and tool handlers run on the harness's own goroutine, so the panic is out of
// reach of every recover() in the server and kills the whole process.
func (t *ToolSet) readExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return readTool(name, desc, schema, t.needExploration(name, run))
}

func (t *ToolSet) writeExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return writeTool(name, desc, schema, t.needExploration(name, run))
}

// needExploration wraps a handler so it only runs with an exploration store.
// Tools that degrade more usefully than "unavailable" (report_finding points at
// add_task_hint, set_goals/set_constraints at the task itself) keep their own
// bespoke guard instead.
func (t *ToolSet) needExploration(name string, run func(context.Context, json.RawMessage) (actool.Result, error)) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if t.ts == nil {
			return actool.Errorf(name + " requires task context (exploration graph): the current agent isn't running inside a task and can't reach the task's exploration graph — this tool is unavailable. Use it inside a task, or use a cross-task read tool with task_id (get_task_node_detail / list_task_findings / get_task_graph etc.)."), nil
		}
		return run(ctx, in)
	}
}

func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// --- read tools (planner + worker) ---

func (t *ToolSet) graphOverview() actool.CoreTool {
	return t.readExpTool("graph_overview",
		"(exploration chain graph) distilled posture summary: asset counts, sites without endpoints, frontier, findings, hints (human/main-agent strategy hints that must be factored in when generating intents). Call it first when planning.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.graphOverviewData())
		})
}

// graphOverviewData computes the distilled situational snapshot shared by the
// graph_overview tool and the planner's wake-up prompt (which pre-injects it so
// the model needn't spend a turn calling the tool — every plan round starts with
// an empty context and always needs this first).
func (t *ToolSet) graphOverviewData() map[string]any {
	out := map[string]any{}
	// goals summary folded in so the planner needn't call list_goals each round.
	goals, _ := t.ts.ListByKind(db.KindGoal, 100)
	gsum := make([]map[string]any, 0, len(goals))
	for _, g := range goals {
		var p map[string]any
		_ = json.Unmarshal(g.Payload, &p)
		gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
	}
	out["goals"] = gsum
	// hints: strategic hints hung on the graph by humans/main agent via add_hint; folded in so the
	// planner reads them every round when generating intents (otherwise written but never read).
	hints, _ := t.ts.ListByKind(db.KindHint, 50)
	hsum := make([]map[string]any, 0, len(hints))
	for _, h := range hints {
		var p map[string]any
		_ = json.Unmarshal(h.Payload, &p)
		hint := map[string]any{"id": h.ID, "state": h.State, "text": p["text"]}
		if findingTrafficBindingEnabled() && p["traffic_refs"] != nil {
			hint["traffic_refs"] = p["traffic_refs"]
		}
		hsum = append(hsum, hint)
	}
	out["hints"] = hsum
	// lineage from the exploration edges: an intent's parents (what it
	// derived_from — possibly several facts combined) and its yields (the
	// facts/findings it produced). factFrom maps a fact → the intent that
	// produced it. This is the relationship layer the flat lists lacked.
	edges, _ := t.ts.Edges(5000)
	parentsOf := map[int64][]int64{}
	yieldsOf := map[int64][]int64{}
	factFrom := map[int64]int64{}
	for _, e := range edges {
		switch e.Rel {
		case db.RelDerivedFrom, db.RelSpawns: // upstream: derived_from (fact/finding/intent→intent) or spawns (origin fact→goal, legacy begin→intent)
			parentsOf[e.To] = append(parentsOf[e.To], e.From)
		case db.RelYields: // intent --yields--> fact/finding
			yieldsOf[e.From] = append(yieldsOf[e.From], e.To)
			factFrom[e.To] = e.From
		}
	}
	// cold-digest §6: members folded into an active digest are shown via cold_digests
	// (below), not the flat recent_* lists. `covered` maps member id → its digest id.
	// §6 render-time revival check: a covered member that has become hot again (a new
	// intent derived from it) must reappear this round — so `hidden` folds a member out
	// only when it is covered AND still cold.
	covered, _ := t.ts.CoveredMembers()
	// Render-time hot set (ancestor of a live intent / fact under a live intent).
	// §6 revival check: a covered member that revived (now hot) must NOT stay folded
	// — hidden() only folds a member out when it is covered AND still cold. Computed
	// every round (cheap for real graph sizes); nil map degrades safely.
	var hotAtRender map[int64]bool
	if cg, _, err := loadColdGraph(t.ts); err == nil {
		hotAtRender = cg.hotSet()
	}
	hidden := func(id int64) bool { _, c := covered[id]; return c && !hotAtRender[id] }
	// B7: intent-level tokens (llm_usage books by session suffix i<n>). Pull the whole graph once, mark
	// tokens on every open/running/recent_done intent — planner/human sees "which direction burned how much"
	// directly in the loop, the most direct ledger for judging whether to continue.
	tokByIntent, _ := t.ts.TokenByIntent()
	tokens := make(map[int64]int64, len(tokByIntent))
	for _, it := range tokByIntent {
		tokens[it.IntentID] = it.InputTokens + it.OutputTokens
	}
	const openIntentsCap = 30
	fr, _ := t.ts.Frontier(openIntentsCap) // priority DESC, id ASC — top N by priority; true total in frontier_open
	out["open_intents"] = compactIntents(fr, parentsOf, yieldsOf, tokens)
	all, _ := t.ts.ListByKind(db.KindIntent, 300)
	var running, recentDone []*db.Node
	for _, n := range all {
		switch n.State {
		case "running":
			running = append(running, n)
		case "done", "blocked", "exhausted":
			if hidden(n.ID) {
				continue // in a cold_digest and still cold — shown via cold_digests (§6.2)
			}
			recentDone = append(recentDone, n) // newest first (all sorted id desc); folded already excluded, take the latest N on output
		}
	}
	out["running_intents"] = compactIntents(running, parentsOf, yieldsOf, tokens)
	// done_intents_total: total finished intents (done/blocked/exhausted), named parallel to recent_done_intents
	// — the latter is just its latest-window truncated view. The two keys side by side are self-describing: "you see N of total",
	// so the planner deduping doesn't take "not shown" as "never dispatched" — no extra prompt explanation needed.
	if dt, err := t.ts.CountFinishedIntents(); err == nil {
		out["done_intents_total"] = dt
	}
	// frontier_open: true count of open intents (open_intents is only its top-N-by-priority truncated view).
	if fo, err := t.ts.CountOpenIntents(); err == nil {
		out["frontier_open"] = fo
	} else {
		out["frontier_open"] = len(fr)
	}
	// findings (confirmed vulns) and facts (worker exploration results) are
	// now distinct node kinds. recent_facts surfaces fact summaries (esp.
	// negative results) so the planner sees them in one call; full content
	// via node_detail(id).
	vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
	factNodes, _ := t.ts.ListByKind(db.KindFact, 1000) // newest first
	out["findings_total"] = len(vulnNodes)             // total confirmed vulns (goal judgment reads it); details in finding_list (latest window)
	out["facts"] = len(factNodes)                      // exploration facts/conclusions count (incl. negative conclusions)
	// findings are a task's highest-value output → the overview carries a latest window (≤10, vulnNodes already id-desc = newest first),
	// letting the planner see recently confirmed vulns at a glance when judging goals each round; use list_findings for full/earlier.
	// Each keeps only {id, summary, from_intent?}: from_intent is the intent that produced this vuln.
	// evidence/assets/vulnclass/severity/state etc. remain available via list_findings / node_detail(id).
	const findingListCap = 10
	findingList := make([]map[string]any, 0, findingListCap)
	for _, n := range vulnNodes {
		if len(findingList) >= findingListCap {
			break
		}
		var fp map[string]any
		_ = json.Unmarshal(n.Payload, &fp)
		m := map[string]any{"id": n.ID, "summary": fp["summary"]}
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // which intent produced this vuln
		}
		findingList = append(findingList, m)
	}
	out["finding_list"] = findingList
	// recent_facts: the latest window of non-folded facts (≤N, factNodes id-desc = newest first). Those folded into
	// a digest and still cold (hidden) go through cold_digests, not repeated here. Each {id, summary, from_intent?,
	// confidence?}; details like evidence via node_detail(id). Earlier ones via list_facts.
	const recentFactsCap = 20
	recentFacts := make([]map[string]any, 0, recentFactsCap)
	for _, n := range factNodes {
		if len(recentFacts) >= recentFactsCap {
			break
		}
		if hidden(n.ID) {
			continue // folded into a digest and still cold — see cold_digests
		}
		m := compactNode(n)
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // which intent produced this fact
		}
		// confidence rides in the overview: lets the planner spot which conclusions are merely inferred
		// (especially negative conclusions — don't take them as verdicts); evidence is long, left for node_detail(id).
		var fp map[string]any
		if json.Unmarshal(n.Payload, &fp) == nil {
			if c, ok := fp["confidence"].(string); ok && c != "" {
				m["confidence"] = c
			}
		}
		recentFacts = append(recentFacts, m)
	}
	out["recent_facts"] = recentFacts
	// recent_done_intents: latest window of non-folded finished intents (≤N, recentDone already id-desc).
	// Earlier: see done_intents_total count + node_detail(id).
	const recentDoneCap = 12
	if len(recentDone) > recentDoneCap {
		recentDone = recentDone[:recentDoneCap]
	}
	out["recent_done_intents"] = compactIntents(recentDone, parentsOf, yieldsOf, tokens)
	// Endgame posture (marginal returns): after the last N planning rounds, did the whole task produce
	// any new fact/finding. ≥3 consecutive zero-output rounds with an empty frontier → hint to close with goal_met
	// (budget protection: dispatching now probably burns tokens for nothing). Computed here so the planner needn't count.
	if t.ts != nil && t.taskID > 0 {
		out["stall"] = t.stallOverview()
	}
	// Guard attribution (ok/blocked/error counts): high blocked = target is defending (WAF/intercept rules) —
	// same-tactics retries burn tokens; high error = tools/env breaking. nil (unwired, e.g. test construction) = block omitted.
	if t.attributions != nil {
		if att := t.attributions(); len(att) > 0 {
			out["guard_attributions"] = att
		}
	}
	// Host-tool inventory: tools on this machine's PATH callable via Bash (available/missing + install hints) —
	// pick techniques by what's actually installed: in binary deployments, whatever the system has is usable.
	out["tools"] = hosttools.Summary()
	// cold-digest §6.1: digest bodies of folded cold zones, top N by latest-member-time desc; truncated older digests
	// only get bare ids (still expandable via expand_digest) — the cold zone's only exit shouldn't stretch unbounded.
	const coldDigestsCap = 15
	if cds, more := coldDigestsRecent(t.ts, coldDigestsCap); len(cds) > 0 {
		out["cold_digests"] = cds // [{id, body, member_count}] — read body directly (§6.1)
		if len(more) > 0 {
			out["cold_digests_more"] = more // ids of truncated older digests; expand via expand_digest(id)
		}
	}
	// the original task (root) so the planner always has it, not just the
	// decomposed goals.
	if description, goal, err := t.ts.Root(); err == nil {
		out["task"] = map[string]any{"description": description, "goal": goal}
	}
	// Direct source tasks are a live, read-only blackboard view. Keep their
	// summaries in a separate field so their intents never enter this task's
	// frontier or get mistaken for locally claimable work.
	out["related_tasks"] = t.relatedTaskOverviews()
	// coverage: a rough asset-test coverage reference — the share of in-scope (task_scope) assets touched by a fact,
	// plus by_type (total/tested per type). For the specific untested assets the agent calls list_untested_assets on demand. Task-context only.
	// When asset coverage is off (coverageDisabled): keep only host_count (host-number awareness), dropping
	// denominator/tested/pct/by_type/note coverage metrics — avoids polluting context and teasing
	// the hidden add_task_scope/list_untested_assets.
	if t.as != nil && t.ts != nil && t.taskID > 0 {
		{
			m := map[string]any{}
			if !t.coverageDisabled {
				if cov, err := t.as.TaskCoverageWithSources(t.taskID); err == nil {
					m["denominator"] = cov.Denominator
					m["tested"] = cov.Tested
					m["by_type"] = cov.ByType
					m["note"] = "coverage = asset-test coverage (incl. endpoints and all related assets), a rough estimate for reference only: includes this task's and directly related tasks' scope plus fact anchors; related scope is read-only. Container-type assets / mass enumeration skew it low — don't take it as fully tested; use add_task_scope to extend this task's scope, list_untested_assets for untested assets [usually don't call list_untested_assets — just proceed with the task];"
					if cov.Denominator == 0 {
						m["pct"] = nil
						m["status"] = "scope unanchored"
					} else {
						m["pct"] = cov.Pct
					}
				}
			}
			if hosts, err := t.as.HostsByTaskWithSources(t.taskID); err == nil {
				// Only the host count is given — the host list is no longer flattened into graph_overview (in large-scope
				// tasks it carried huge repeated string lists per round with limited planning value); query list_assets on demand.
				m["host_count"] = len(hosts)
			}
			if len(m) > 0 {
				out["coverage"] = m
			}
		}
	}
	return out
}

// workerOverviewData is the worker-start lean situational snapshot. Task-5 measurements:
// workers consumed 76.8% of all tokens, ≈3M input per intent — every worker start rebuilt a planner-grade
// posture (cold graph ×2, all lineage edges, intent token ledger, coverage CTE computed-then-dropped,
// whole cold_digests bodies), then injected it verbatim into the kickoff message — the largest fixed waste.
// A worker only needs "what did others find" for dedup and association: goals/hints/counts/latest findings/facts/root task/
// host-tool inventory. Planning-only fields (frontier, running/recent_done intents, cold folding,
// stall, guard attribution, related_tasks, lineage, TokenByIntent, coverage) are all excluded from
// the worker view — saving both the per-start rebuild compute and the injection prefix length.
func (t *ToolSet) workerOverviewData() map[string]any {
	out := map[string]any{}
	goals, _ := t.ts.ListByKind(db.KindGoal, 100)
	gsum := make([]map[string]any, 0, len(goals))
	for _, g := range goals {
		var p map[string]any
		_ = json.Unmarshal(g.Payload, &p)
		gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
	}
	out["goals"] = gsum
	hints, _ := t.ts.ListByKind(db.KindHint, 20)
	hsum := make([]map[string]any, 0, len(hints))
	for _, h := range hints {
		var p map[string]any
		_ = json.Unmarshal(h.Payload, &p)
		hsum = append(hsum, map[string]any{"id": h.ID, "state": h.State, "text": p["text"]})
	}
	out["hints"] = hsum
	vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
	factNodes, _ := t.ts.ListByKind(db.KindFact, 1000)
	out["findings_total"] = len(vulnNodes)
	out["facts"] = len(factNodes)
	const findingListCap = 10
	findingList := make([]map[string]any, 0, findingListCap)
	for _, n := range vulnNodes {
		if len(findingList) >= findingListCap {
			break
		}
		var fp map[string]any
		_ = json.Unmarshal(n.Payload, &fp)
		findingList = append(findingList, map[string]any{"id": n.ID, "summary": fp["summary"]})
	}
	out["finding_list"] = findingList
	const recentFactsCap = 20
	recentFacts := make([]map[string]any, 0, recentFactsCap)
	for _, n := range factNodes {
		if len(recentFacts) >= recentFactsCap {
			break
		}
		m := compactNode(n)
		var fp map[string]any
		if json.Unmarshal(n.Payload, &fp) == nil {
			if c, ok := fp["confidence"].(string); ok && c != "" {
				m["confidence"] = c
			}
		}
		recentFacts = append(recentFacts, m)
	}
	out["recent_facts"] = recentFacts
	out["tools"] = hosttools.Summary()
	if t.as != nil && t.taskID > 0 {
		if hosts, err := t.as.HostsByTaskWithSources(t.taskID); err == nil {
			out["host_count"] = len(hosts)
		}
	}
	if description, goal, err := t.ts.Root(); err == nil {
		out["task"] = map[string]any{"description": description, "goal": goal}
	}
	return out
}

func inheritedMap(m map[string]any, sourceTaskID int64) map[string]any {
	m["source_task_id"] = sourceTaskID
	m["inherited"] = true
	return m
}

const (
	relatedOverviewTotalTextRunes      = 48_000
	relatedOverviewMaxTextPerSource    = 8_000
	relatedOverviewMaxGoalsPerSource   = 8
	relatedOverviewMaxHintsPerSource   = 6
	relatedOverviewMaxFactsPerSource   = 12
	relatedOverviewMaxFindingsPerTask  = 6
	relatedOverviewMaxIntentsPerTask   = 8
	relatedOverviewMaxScopePerSource   = 12
	relatedOverviewMaxDigestsPerSource = 6
)

// overviewTextBudget bounds inherited prompt text while preserving a fair slice
// for every direct source. Full evidence remains available through the on-demand
// read tools, so truncation here does not discard persisted blackboard data.
type overviewTextBudget struct {
	remaining int
	truncated bool
}

func relatedOverviewBudgetForSources(sourceCount int) int {
	if sourceCount <= 0 {
		return 0
	}
	if sourceCount > db.MaxTaskSourceCount {
		sourceCount = db.MaxTaskSourceCount
	}
	perSource := relatedOverviewTotalTextRunes / sourceCount
	if perSource > relatedOverviewMaxTextPerSource {
		perSource = relatedOverviewMaxTextPerSource
	}
	return perSource
}

func (b *overviewTextBudget) take(value any, fieldLimit int) string {
	var text string
	switch value := value.(type) {
	case string:
		text = strings.TrimSpace(value)
	case nil:
		return ""
	default:
		text = strings.TrimSpace(fmt.Sprint(value))
	}
	if text == "" {
		return ""
	}
	if b.remaining <= 0 || fieldLimit <= 0 {
		b.truncated = true
		return ""
	}
	runes := []rune(text)
	limit := fieldLimit
	if limit > b.remaining {
		limit = b.remaining
	}
	if len(runes) > limit {
		b.truncated = true
		if limit == 1 {
			text = "…"
		} else {
			text = string(runes[:limit-1]) + "…"
		}
		runes = []rune(text)
	}
	b.remaining -= len(runes)
	return text
}

func recentTerminalIntents(store *db.ExplorationStore, limit int) []*db.Node {
	if limit <= 0 {
		return []*db.Node{}
	}
	const batch = 300
	cursor := int64(0)
	out := make([]*db.Node, 0, limit)
	for len(out) < limit {
		page, more, err := store.ListByKindPage(db.KindIntent, cursor, batch)
		if err != nil || len(page) == 0 {
			break
		}
		for _, intent := range page {
			switch intent.State {
			case "done", "blocked", "exhausted", "stopped":
				out = append(out, intent)
			}
			if len(out) >= limit {
				break
			}
		}
		if !more {
			break
		}
		cursor = page[len(page)-1].ID
	}
	return out
}

// relatedTaskOverviews distills persistent blackboard state from direct source
// tasks. It intentionally reads each source's local store methods, never its own
// related sources, so inheritance is one level only.
func (t *ToolSet) relatedTaskOverviews() []map[string]any {
	sources, err := t.ts.DirectSourceStores()
	if err != nil {
		return []map[string]any{}
	}
	if len(sources) > db.MaxTaskSourceCount {
		sources = sources[:db.MaxTaskSourceCount]
	}
	perSourceTextBudget := relatedOverviewBudgetForSources(len(sources))
	out := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		ts := source.Store
		// §2 cross-task: render the source task's OWN folded view — fold out the
		// members it has already folded, and surface its cold_digests read-only.
		hidden := hiddenMembersFor(ts)
		budget := overviewTextBudget{remaining: perSourceTextBudget}
		item := map[string]any{
			"source_task_id": source.Task.TaskID,
			"inherited":      true,
			"task": map[string]any{
				"description": budget.take(source.Task.Description, 800),
				"goal":        budget.take(source.Task.Goal, 800),
				"status":      source.Task.Status,
			},
		}
		stats, statsErr := ts.Stats()

		edges, _ := ts.Edges(5000)
		parentsOf := map[int64][]int64{}
		yieldsOf := map[int64][]int64{}
		factFrom := map[int64]int64{}
		for _, edge := range edges {
			switch edge.Rel {
			case db.RelDerivedFrom, db.RelSpawns:
				parentsOf[edge.To] = append(parentsOf[edge.To], edge.From)
			case db.RelYields:
				yieldsOf[edge.From] = append(yieldsOf[edge.From], edge.To)
				factFrom[edge.To] = edge.From
			}
		}

		goals, _ := ts.ListByKind(db.KindGoal, relatedOverviewMaxGoalsPerSource)
		goalSummary := make([]map[string]any, 0, len(goals))
		for _, goal := range goals {
			var payload map[string]any
			_ = json.Unmarshal(goal.Payload, &payload)
			goalSummary = append(goalSummary, inheritedMap(map[string]any{
				"id": goal.ID, "state": goal.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["goals"] = goalSummary

		hints, _ := ts.ListByKind(db.KindHint, relatedOverviewMaxHintsPerSource)
		hintSummary := make([]map[string]any, 0, len(hints))
		for _, hint := range hints {
			var payload map[string]any
			_ = json.Unmarshal(hint.Payload, &payload)
			hintSummary = append(hintSummary, inheritedMap(map[string]any{
				"id": hint.ID, "state": hint.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["hints"] = hintSummary

		facts, _ := ts.ListByKind(db.KindFact, relatedOverviewMaxFactsPerSource)
		findings, _ := ts.ListByKind(db.KindFinding, relatedOverviewMaxFindingsPerTask)
		intentNodes, _ := ts.ListByKind(db.KindIntent, 300)
		terminalIntent := make(map[int64]bool, len(intentNodes))
		for _, intent := range intentNodes {
			terminalIntent[intent.ID] = inheritedIntentSummaryState(intent.State)
		}
		item["facts"] = len(facts)
		item["findings"] = len(findings)
		if statsErr == nil {
			item["facts"] = stats[db.KindFact]
			item["findings"] = stats[db.KindFinding]
			if stats[db.KindGoal] > len(goals) || stats[db.KindHint] > len(hints) ||
				stats[db.KindFact] > len(facts) || stats[db.KindFinding] > len(findings) {
				budget.truncated = true
			}
		}
		recentFindings := make([]map[string]any, 0, len(findings))
		for _, finding := range findings {
			entry := inheritedMap(compactFinding(finding), source.Task.TaskID)
			entry["summary"] = budget.take(entry["summary"], 400)
			recentFindings = append(recentFindings, entry)
		}
		item["recent_findings"] = recentFindings
		recentFacts := make([]map[string]any, 0, len(facts))
		for _, fact := range facts {
			if hidden(fact.ID) {
				continue // folded into this source's cold_digests — shown there (§2/§6.2)
			}
			m := inheritedMap(compactNode(fact), source.Task.TaskID)
			m["summary"] = budget.take(m["summary"], 400)
			if from := factFrom[fact.ID]; from > 0 && terminalIntent[from] {
				m["from_intent"] = from
			}
			var payload map[string]any
			if json.Unmarshal(fact.Payload, &payload) == nil {
				if confidence, ok := payload["confidence"].(string); ok && confidence != "" {
					m["confidence"] = confidence
				}
			}
			recentFacts = append(recentFacts, m)
		}
		item["recent_facts"] = recentFacts

		recentDoneRaw := recentTerminalIntents(ts, relatedOverviewMaxIntentsPerTask)
		recentDone := recentDoneRaw[:0] // in-place filter: drop this source's folded intents (§2)
		for _, intent := range recentDoneRaw {
			if hidden(intent.ID) {
				continue
			}
			recentDone = append(recentDone, intent)
		}
		for _, intent := range recentDone {
			intent.Inherited = true
			intent.SourceTaskID = source.Task.TaskID
		}
		intentResults := compactIntents(recentDone, parentsOf, yieldsOf, nil)
		for i, intent := range recentDone {
			intentResults[i]["summary"] = budget.take(intentResults[i]["summary"], 400)
			acts, _, err := ts.ActivityPageForTerminalIntent(intent.ID, 0, 20)
			if err != nil {
				continue
			}
			var resultSummary, textFallback string
			for _, activity := range acts {
				switch activity.Kind {
				case "result":
					resultSummary = activity.Summary
				case "text":
					textFallback = activity.Summary
				}
			}
			if resultSummary == "" {
				resultSummary = textFallback
			}
			if resultSummary != "" {
				intentResults[i]["result_summary"] = budget.take(resultSummary, 800)
			}
		}
		item["recent_intent_results"] = intentResults
		// §2 cross-task: the source task's folded cold region, read-only, newest-member
		// first & capped like the current task's. Members (and overflow digests) are
		// resolvable via expand_digest(id)/node_detail(id), which search source tasks.
		if cds, more := coldDigestsRecent(ts, relatedOverviewMaxDigestsPerSource); len(cds) > 0 {
			for _, cd := range cds {
				cd["inherited"] = true
				cd["source_task_id"] = source.Task.TaskID
			}
			item["cold_digests"] = cds
			if len(more) > 0 {
				item["cold_digests_more"] = more // ids of truncated older digests; expand via expand_digest(id)
			}
		}
		if statsErr == nil {
			item["node_stats"] = stats
		}

		if t.as != nil {
			if scopeRows, err := t.as.ListTaskScope(source.Task.TaskID); err == nil && len(scopeRows) > 0 {
				scopeCount := len(scopeRows)
				if len(scopeRows) > relatedOverviewMaxScopePerSource {
					scopeRows = scopeRows[:relatedOverviewMaxScopePerSource]
					budget.truncated = true
				}
				scope := make([]map[string]any, 0, len(scopeRows))
				for _, row := range scopeRows {
					entry := map[string]any{"kind": row.Kind, "source": budget.take(row.Source, 300)}
					switch {
					case row.Domain != "":
						entry["value"] = budget.take(row.Domain, 400)
					case row.Net != "":
						entry["value"] = budget.take(row.Net, 400)
					case row.Value != "":
						entry["value"] = budget.take(row.Value, 400)
					case row.CompanyID != nil:
						entry["company_id"] = *row.CompanyID
					}
					scope = append(scope, entry)
				}
				item["asset_scope"] = scope
				item["asset_scope_count"] = scopeCount
			}
			if coverage, err := t.as.TaskCoverage(source.Task.TaskID, source.Task.ExplorationID); err == nil {
				item["asset_coverage"] = map[string]any{
					"denominator": coverage.Denominator,
					"tested":      coverage.Tested,
					"pct":         coverage.Pct,
					"by_type":     coverage.ByType,
				}
			}
		}
		if budget.truncated {
			item["summary_truncated"] = true
		}
		out = append(out, item)
	}
	return out
}

func inheritedIntentSummaryState(state string) bool {
	switch state {
	case "done", "blocked", "exhausted", "stopped":
		return true
	default:
		return false
	}
}

// compactNode distills any exploration node to id + summary + state, dropping the
// big detail/evidence (fetch that on demand via node_detail).
func compactNode(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if n.Inherited {
		inheritedMap(m, n.SourceTaskID)
	}
	return m
}

// compactFinding is compactNode plus the vuln-specific vulnclass/severity.
func compactFinding(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if n.Inherited {
		inheritedMap(m, n.SourceTaskID)
	}
	if vc, ok := p["vulnclass"]; ok && vc != nil && vc != "" {
		m["vulnclass"] = vc
	}
	if sv, ok := p["severity"]; ok && sv != nil && sv != "" {
		m["severity"] = sv
	}
	return m
}

func (t *ToolSet) listFindings() actool.CoreTool {
	return t.readExpTool("list_findings", "Lists this task's and directly related tasks' [confirmed vulns] (compact: id+task_id+intent_id+vulnclass+severity+summary+status). Related-task entries carry source_task_id/inherited=true and are read-only. Vulns only here — ordinary exploration facts use list_facts, details via node_detail(id).",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKindWithSources(db.KindFinding, 500)
			if err := t.ts.PopulateFindingTrafficIDs(f); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			intentOf, _ := t.ts.FindingIntentsWithSources() // finding id -> the intent id that produced it
			taskID := t.taskID
			if taskID <= 0 {
				taskID, _ = t.ts.TaskID()
			}
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				m := compactFinding(n)
				if n.FindingID > 0 {
					m["finding_id"], m["finding_node_id"], m["traffic_count"] = n.FindingID, n.ID, n.TrafficCount
				}
				if n.Inherited {
					m["task_id"] = n.SourceTaskID
				} else {
					m["task_id"] = taskID
				}
				if iid, ok := intentOf[n.ID]; ok {
					m["intent_id"] = iid
				}
				out = append(out, m)
			}
			return jsonResult(out)
		})
}

// factsPageSize is the default page size for list_facts. Facts pile up on long
// tasks; returning all of them at once (the old behaviour) could blow up the
// context, so default to the newest page and let the agent page/filter for more.
const factsPageSize = 20

func (t *ToolSet) listFacts() actool.CoreTool {
	return t.readExpTool("list_facts", "Paginated list of this task's and directly related tasks' [exploration facts/conclusions], newest first (compact: id+summary+status; over-long summaries truncate, full text via node_detail(id)). All params optional: limit (default 20, cap 100), before (cursor — pass the last page's next_before for an older page; omit/0 = latest page), q (filter summaries by keyword). Returns {facts, total, has_more, next_before}: total is the filtered count; when has_more=true, keep paging with next_before. Related-task entries carry source_task_id/inherited=true and are read-only. Vulns: see list_findings.",
		obj(map[string]any{
			"limit":  intp("items to return, default 20, cap 100"),
			"before": intp("pagination cursor: only return older facts with id below this value; omit or 0 = latest page"),
			"q":      str("filter fact summaries by keyword (case-insensitive); omit = no filter"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit  int    `json:"limit"`
				Before int64  `json:"before"`
				Q      string `json:"q"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = factsPageSize
			}
			if limit > 100 {
				limit = 100
			}
			f, hasMore, total, err := t.ts.ListByKindPageWithSources(db.KindFact, a.Before, limit, strings.TrimSpace(a.Q))
			if err != nil {
				return actool.Result{}, err
			}
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				out = append(out, compactFact(n))
			}
			res := map[string]any{"facts": out, "total": total, "has_more": hasMore}
			if hasMore && len(f) > 0 {
				res["next_before"] = f[len(f)-1].ID // pass it back for the next (older) page
			}
			return jsonResult(res)
		})
}

// factSummaryMax caps a fact summary in list_facts output. Facts carry one-line
// conclusions, but nothing enforces brevity; a runaway summary must not bloat a
// whole page. Full text stays available via node_detail(id).
const factSummaryMax = 160

// compactFact is compactNode with the summary rune-capped for list_facts, so a
// page of facts stays bounded regardless of how long any single summary grew.
func compactFact(n *db.Node) map[string]any {
	m := compactNode(n)
	if s, ok := m["summary"].(string); ok && len([]rune(s)) > factSummaryMax {
		m["summary"] = string([]rune(s)[:factSummaryMax]) + "…"
		m["summary_truncated"] = true
	}
	return m
}

func (t *ToolSet) nodeDetail() actool.CoreTool {
	return t.readExpTool("node_detail", "Fetches the full content of an [exploration-graph node] by id, from this task or a directly related task. Inherited nodes carry source_task_id/inherited=true and are read-only. Exploration-node ids only, as returned by list_facts/list_findings/graph_overview — for assets use list_assets/asset_neighbors.",
		obj(map[string]any{"id": idp("exploration-graph node id (not an asset id)")}, "id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.ID)
			if id <= 0 {
				return actool.Errorf("id is required"), nil
			}
			n, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == nil {
				return actool.Errorf(fmt.Sprintf("exploration node %d not found. If you meant an asset, use list_assets / asset_neighbors (assets and exploration nodes are different id spaces — an asset id can't be passed to node_detail).", id)), nil
			}
			if err := t.ts.PopulateFindingTrafficIDs([]*db.Node{n}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(n) // full payload incl. detail / evidence, plus explicit finding IDs
		})
}

// --- planner write tools ---

// intentItem is one exploration direction in an add_intent batch/single call.
type intentItem struct {
	Summary   string            `json:"summary"`
	Dimension string            `json:"dimension,omitempty"` // attack-chain auto-hop: dimension of the continuing intent (injection/authz/…)
	AssetIDs  []json.RawMessage `json:"asset_ids"`
	ParentIDs []json.RawMessage `json:"parent_ids"`
	Priority  int               `json:"priority"`
	// Continues holds the upstream intent id(s) this intent [continues] (0/1/many).
	//
	// Why it's needed: continuation chains previously existed only in summaries' **natural language**
	// ("continue the budget-cut intent #432", "continue #635/#578 interrupted twice by backend restarts").
	// Production: 26 of 205 intents were continuations (12.7%), and #660's summary literally said "continued twice".
	//
	// Text-form continuations had two problems:
	//  1. **Generation uncountable**. #660 continues #635, #635 continues #578, but #660's parent
	//     in the graph is #14 (a fact) — the continuation relation was never expressed in data, so
	//     "how deep is this chain" was unanswerable. And generation count is the key gate against infinite continuation.
	//  2. **Unqueryable**. Finding "all intents continuing #578" required a full summary-text scan.
	//
	// Once structured: generations become countable, queryable, cappable. parent_ids semantics are unchanged
	// (only fact/finding allowed — an intent must anchor on confirmed knowledge) — continues is an **additional**
	// continuation marker, not a replacement for parent_ids.
	Continues []json.RawMessage `json:"continues"`
	// Hypothesis: this direction's hypothesis (optional) — which fact it infers from, citing the fact id.
	// The worker takes it as the "definition of done" verification target (v0.3.95 B3).
	Hypothesis string `json:"hypothesis"`
	// SuccessCriteria: what counts as done/not-done (optional) — the expected fact/finding shape.
	SuccessCriteria string `json:"success_criteria"`
	// RequiresIntents holds the prerequisite intent ids of a strict serial chain (recorded only when the platform gate is off).
	RequiresIntents []json.RawMessage `json:"requires_intents"`
}

// addOneIntent creates one intent node, links upstream lineage, and returns its id.
// Constraint: an intent can only anchor on confirmed knowledge — every parent_id must be an existing
// fact/finding node (can't hang on other intents/goals/hints). Leave parent_ids empty for a top-level new direction; falls back to the origin fact.
// This enforces "every intent links to a fact node — discovery-driven, not made-up planning" at the creation path.
func (t *ToolSet) addOneIntent(it intentItem) (int64, error) {
	summary := clampIntentSummary(it.Summary)
	if strings.TrimSpace(summary) == "" {
		return 0, fmt.Errorf("summary must not be empty")
	}
	// Intent granularity gate (v0.4.44): an intent summary can't just parrot the task description/goal —
	// the most common round-1 mistake is the planner wrapping the whole goal into one intent; a worker
	// receiving it effectively receives the entire task. Detected deterministically via prefix match + length.
	if rootDesc, rootGoal, rootErr := t.ts.Root(); rootErr == nil {
		for _, src := range []string{rootDesc, rootGoal} {
			src = strings.TrimSpace(src)
			if len(src) < 40 {
				continue
			}
			// Prefix-match the first 60 bytes of the goal text (enough to distinguish parroting from normal quoting)
			probe := src
			if len(probe) > 60 {
				probe = probe[:60]
			}
			if strings.Contains(summary, probe) {
				return 0, fmt.Errorf(
					"Intent summary parrots the task goal/description — not an executable sub-step. " +
						"Split it into 3-5 concrete intents (e.g. \"DNS resolution + subdomain enumeration\", \"port scan + service identification\", \"unauthorized-surface probing\"), " +
						"each summary stating [which asset + what concrete action + expected output]; the full goal context belongs in the task description — no need to repeat it.")
			}
		}
	}
	// Validate anchors first (before creating the node — bad anchors would leave orphan intents).
	parents := pidList(it.ParentIDs)
	for _, pidv := range parents {
		n, err := t.ts.GetNodeWithSources(pidv)
		if err != nil || n == nil {
			return 0, fmt.Errorf("parent_id %d doesn't exist in this task or directly related tasks: parent_ids must be existing [fact/finding] node ids; for a top-level new direction leave parent_ids empty", pidv)
		}
		if n.Kind != db.KindFact && n.Kind != db.KindFinding {
			return 0, fmt.Errorf("parent_id %d is a %q node and can't anchor an intent: intents can only anchor on confirmed [fact/finding] nodes — not on intents/goals/hints; for a top-level new direction leave parent_ids empty", pidv, n.Kind)
		}
	}
	priority := it.Priority
	if priority == 0 {
		priority = 5
	}
	// Continuation validation + generation computation.
	//
	// Constraint: continues can only point at **existing intent** nodes (you continue an exploration
	// direction, not a fact). Generation = 1 + max generation on the upstream continuation chain.
	//
	// Why cap generations: an ungated continuation chain grows unboundedly. Production saw a three-generation
	// chain — #635 → #578 → #660, the summary saying "continue #635/#578, interrupted twice by backend restarts,
	// still attacking the crown-jewel chain of ZStack management-API credentials (#635 already ran 56 rounds/28 min last round)".
	// Each generation rebuilds context from zero, re-reads the same files, re-scans the same assets — and the
	// chain being continued may not be worth continuing at all.
	continues := pidList(it.Continues)
	depth := 1
	for _, cid := range continues {
		cn, err := t.ts.GetNodeWithSources(cid)
		if err != nil || cn == nil {
			return 0, fmt.Errorf("continues %d doesn't exist: continues must be existing [intent] node ids", cid)
		}
		if cn.Kind != db.KindIntent {
			return 0, fmt.Errorf("continues %d is a %q node and can't be a continuation source: continues must be [intent] ids (you continue an exploration direction)", cid, cn.Kind)
		}
		// An intent can't continue from one that's [still running] — that's a parallel race.
		// open is allowed: it may be an intent reverted by pause — re-approaching from another angle is reasonable.
		if cn.State == "running" {
			return 0, fmt.Errorf("continues %d is still executing — can't continue it: wait for it to end before dispatching a continuation", cid)
		}
		if d := continuationDepthOf(cn); d+1 > depth {
			depth = d + 1
		}
	}
	if depth > maxContinuationDepth {
		return 0, fmt.Errorf("continuation generation cap reached (%d generations): this direction has already been continued %d times — continuing further is most likely duplicate work. "+
			"Instead: ① switch to a fundamentally different approach (different entry/method/target surface); ② or abandon this direction and turn to uncovered ones",
			maxContinuationDepth, depth)
	}
	requires := pidList(it.RequiresIntents)
	for _, rid := range requires {
		rn, err := t.ts.GetNode(rid)
		if err != nil || rn == nil {
			return 0, fmt.Errorf("requires_intents %d doesn't exist in this task: only existing intent ids of this task are allowed", rid)
		}
		if rn.Kind != db.KindIntent {
			return 0, fmt.Errorf("requires_intents %d is a %q node: only intent ids allowed (a prerequisite is an exploration direction)", rid, rn.Kind)
		}
		if rn.State == "deleted" {
			return 0, fmt.Errorf("requires_intents %d has been deleted — can't be a prerequisite", rid)
		}
	}
	anchors := pidList(it.AssetIDs)
	// Asset interception: if an asset bound to the intent hits a system intercept rule, the intent is refused.
	if t.as != nil && len(anchors) > 0 {
		hits, err := t.as.CheckAssetsIntercept(t.taskID, anchors)
		if err != nil {
			return 0, fmt.Errorf("asset-interception check failed: %w", err)
		}
		if len(hits) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "intent \"%s\" binds assets that failed test-scope validation — stop testing the related assets: ", it.Summary)
			for _, h := range hits {
				fmt.Fprintf(&b, "\n - %s", h.Describe())
			}
			return 0, fmt.Errorf("%s", b.String())
		}
	}
	payload := map[string]any{"summary": summary}
	if h := strings.TrimSpace(it.Hypothesis); h != "" {
		payload["hypothesis"] = h
	}
	if sc := strings.TrimSpace(it.SuccessCriteria); sc != "" {
		payload["success_criteria"] = sc
	}
	if len(anchors) > 0 {
		payload["asset_ids"] = anchors
	}
	if len(continues) > 0 {
		// Stored as a structured field so continuation generations are countable and queryable (see intentItem.Continues' comment).
		payload["continues"] = continues
		payload["continuation_depth"] = depth
	}
	if len(requires) > 0 {
		payload["requires_intents"] = requires
	}
	// Dispatch dedup: if a highly similar open/running intent already exists in the task, don't re-dispatch — two parallel
	// workers doing the same thing is pure waste; the planner sees the notice and can rephrase the difference.
	if existID, existSum, similar, err := t.ts.FindSimilarOpenIntent(summary); err == nil && similar {
		return 0, fmt.Errorf("a highly similar unfinished intent #%d \"%s\" already exists — not re-dispatching; if this is genuinely different work, state the difference in the summary",
			existID, firstLine(existSum, 60))
	}
	id, err := t.ts.AddIntent(payload, priority, anchors, "planner")
	if err != nil {
		return 0, err
	}
	// upstream lineage: link each (validated) fact/finding parent → this intent, so
	// "multiple facts combine into one new intent" is expressible.
	for _, parent := range parents {
		_ = t.ts.Link(parent, db.RelDerivedFrom, id)
	}
	// a top-level intent (no explicit parent) connects to the origin fact, so every
	// intent still traces back to a fact node — at task start the only fact is the
	// origin, and the first intents derive from it.
	if len(parents) == 0 {
		if origin, _ := t.ts.OriginFactID(); origin > 0 {
			_ = t.ts.Link(origin, db.RelDerivedFrom, id)
		}
	}
	return id, nil
}

// SetIntentQueueLimit installs the dispatch-threshold resolver (nil = unlimited).
func (t *ToolSet) SetIntentQueueLimit(fn func() (int, int)) { t.intentQueue = fn }

// SetIntentRequiresGate controls the requires_intents serial gate (default off, recorded only).
func (t *ToolSet) SetIntentRequiresGate(on bool) { t.intentRequiresGate = on }

// queueBudget returns the dispatch threshold and worker count; nil resolver = 0,0 (unlimited).
func (t *ToolSet) queueBudget() (limit, workers int) {
	if t == nil || t.intentQueue == nil {
		return 0, 0
	}
	return t.intentQueue()
}

// intentRoundAddCap returns how many intents this round may still add (-1 = unlimited), plus the current backlog and threshold.
//
// Threshold T = max(limit, 2*workers):
//   - active >= T      → 0 this round (wait for output first; the planning round still runs — can read results/prove goals/write facts)
//   - active >= T-2    → 1 this round (only fill the most critical next step)
//   - otherwise        → 3 this round
func (t *ToolSet) intentRoundAddCap() (capN, active, threshold int) {
	capN = -1
	if t.worker != "planner" {
		return
	}
	limit, workers := t.queueBudget()
	if limit <= 0 || t.ts == nil {
		return
	}
	n, err := t.ts.CountActiveIntents()
	if err != nil {
		return
	}
	active = n
	threshold = limit
	if 2*workers > threshold {
		threshold = 2 * workers
	}
	switch {
	case active >= threshold:
		capN = 0
	case active >= threshold-2:
		capN = 1
	default:
		capN = 3
	}
	return
}

func (t *ToolSet) addIntent() actool.CoreTool {
	return t.writeExpTool("add_intent", "Generates [exploration directions] into the frontier, linked into the exploration chain. An intent is an open exploration direction, not a fixed type — describe in one free-form summary sentence what to explore/verify/exploit.\n"+
		"★Prefer batch: put multiple new directions from one round into the intents array in a single call (saves round-trips vs one-by-one). Returns an ids array, same length and order as intents (failed items get id=0, details in errors). For a single intent, omit intents and use the top-level summary.",
		obj(map[string]any{
			"intents":          map[string]any{"type": "array", "description": "[Prefer this] array of exploration directions to add, processed in order. Each element's fields mirror the top-level fields below (summary/asset_ids/parent_ids/priority). Returned ids match this array's length and order.", "items": map[string]any{"type": "object"}},
			"summary":          str("[single] One sentence describing this exploration direction: what to do + why. A clear direction suffices — asset ids aren't required."),
			"asset_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "[Target asset ids] this direction tests/attacks (**try to pass**, 0/1/many; asset ids from list_assets, not exploration node ids): which assets (sites/endpoints/params/hosts etc.) this direction targets. Whenever the direction revolves around concrete assets, pass them — it's the structured marker of 'which targets this probes', used for coverage dedup and linking the intent into the asset chain. Leave empty only for purely global recon with no concrete target assets."},
			"parent_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Upstream anchor ids (optional, 0/1/many): which [confirmed facts(findings)] this direction was synthesized from. **Only existing fact/finding node ids — not intents/goals/hints**: an intent must anchor on confirmed knowledge — discovery-driven, not made-up planning. Pass multiple when several facts jointly produced the intent; leave empty for a top-level brand-new recon direction (auto-attached to the task's origin fact)."},
			"continues":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "[Only when this direction continues an old one] upstream [intent] node ids (0/1/many) — which cut-off/wrapped-up intent(s) this direction picks up. **Fill only when the summary explicitly says 'continue #NNN'**, and it must match the intent ids mentioned there. Continuation generations are capped (max 3); exceeding is rejected — then switch to a fundamentally different approach or another direction instead of continuing. Leave empty for top-level new directions."},
			"priority":         intp("Priority 0-10, default 5. Exploit-chain step directly approaching the goal = 8-10; newly discovered entry surface first probe = 6-7; coverage fill/re-verify = 3-4; pure intel = 1-2. Differentiate same-round intents by value — don't leave everything at 5."),
			"requires_intents": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "[Strict serial chains only] prerequisite intent ids this direction depends on: workers won't pick up this intent until those produce results (recorded only when the platform gate is off). Fill only when a previous step's **actual output** is the next step's input; don't fill for parallel coverage directions — they'd wait for nothing."},
			"hypothesis":       str("[Recommended] this direction's hypothesis: inferred from which fact and how (cite the fact id). The worker verifies against it, and your next round's 'did it produce' judgment gets an anchor to compare."),
			"success_criteria": str("[Recommended] what counts as done/not-done: the expected fact/finding shape (e.g. 'request/response that captured the admin cookie' / 'output proving parameter X is not injectable')."),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Intents    []intentItem `json:"intents"`
				intentItem              // single mode: top-level summary/asset_ids/parent_ids/priority
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Intents) > 0
			items := a.Intents
			if !batch {
				items = []intentItem{a.intentItem}
			}

			origLen := len(items)
			ids := make([]int64, origLen)
			errs := map[string]string{}
			createdAny := false
			capN, active, threshold := t.intentRoundAddCap()
			for i, it := range items {
				if capN >= 0 && t.intentAdded >= capN {
					errs[strconv.Itoa(i)] = fmt.Sprintf(
						"Dispatch throttled: %d unfinished intents in this task (threshold %d) — no more this round (%d already created). "+
							"Wait for worker output before dispatching more, or merge several directions into one; the planning round itself is unaffected — "+
							"you can still read results, prove_goal, write facts. Set intent_queue_limit=0 to disable throttling.",
						active, threshold, t.intentAdded)
					continue
				}
				id, err := t.addOneIntent(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				t.intentAdded++
				createdAny = true
			}
			if len(items) < origLen {
				ids = ids[:len(items)]
			}

			// A human dispatching an intent via the main agent → if the task is already done (goalless branch with
			// no open goals), pull it back to running so a worker can pick the intent up. resumeTask is only wired
			// by the main agent's Chat (SetResumeTask); the planner's ToolSet has nil here, so this is a no-op
			// when the planner itself calls add_intent — its normal intent production is unaffected. The intent node
			// was already created (open) above, so revival won't be misjudged as drained.
			if createdAny && t.resumeTask != nil {
				t.resumeTask()
			}

			if !batch { // single: keep the original return shape
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("intent created: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) retireIntent() actool.CoreTool {
	return t.writeExpTool("retire_intent",
		"Retires [not-yet-started] queued intents (open). Call when new facts have invalidated an intent's premise — e.g. the target proved to be dead, "+
			"the real business entry was located elsewhere, or the direction was ruled out by conclusions. Retiring doesn't delete evidence/lineage — it only marks deleted with a reason recorded, "+
			"and workers won't pick it up again. A running intent can't be retired — kill it with kill_work first.\n"+
			"Guardrails: max 6 per round; retiring for 'duplicate' requires superseded_by naming the surviving replacement intent (can't point at a retired one); "+
			"claiming 'premise invalidated' requires citing the fact/finding node that negated it in reason.",
		obj(map[string]any{
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "intent node ids to retire (must be open; multiple allowed; max 6 cumulative per round)"},
			"reason": str("Retirement reason (required): state which fact negated its premise, or why this direction is no longer needed"),
			"superseded_by": map[string]any{"type": "array", "items": map[string]any{"type": "integer"},
				"description": "[Required when retiring for duplication] the surviving replacement intent id (open/running/done). Must not point at a deleted intent — that would break the coverage chain. Not needed for premise-invalidated retirements."},
		}, "ids", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IDs          []json.RawMessage `json:"ids"`
				Reason       string            `json:"reason"`
				SupersededBy []json.RawMessage `json:"superseded_by"`
			}
			_ = json.Unmarshal(in, &a)
			ids := pidList(a.IDs)
			reason := strings.TrimSpace(a.Reason)
			sup := pidList(a.SupersededBy)
			if len(ids) == 0 {
				return actool.Errorf("ids must not be empty"), nil
			}
			if reason == "" {
				return actool.Errorf("reason is required: state which fact/conclusion negated its premise"), nil
			}
			if remaining := maxIntentRetirePerRun - t.retiredThisRun; remaining <= 0 {
				return actool.Errorf(fmt.Sprintf("retirement cap of %d reached this round: let workers digest the backlog and clean up next round (avoiding chain-misfires from clearing everything at once)", maxIntentRetirePerRun)), nil
			} else if len(ids) > remaining {
				return actool.Errorf(fmt.Sprintf("at most %d more retirements this round, %d submitted: split across rounds, preferring replacements with fuller evidence", remaining, len(ids))), nil
			}
			if len(sup) > 0 {
				for _, sid := range sup {
					if sid <= 0 {
						continue
					}
					for _, id := range ids {
						if sid == id {
							return actool.Errorf(fmt.Sprintf("superseded_by can't point at intent #%d being retired this same call (self-replacement means no coverage)", sid)), nil
						}
					}
					sn, err := t.ts.GetNode(sid)
					if err != nil || sn == nil {
						return actool.Errorf(fmt.Sprintf("superseded_by #%d doesn't exist: the replacement must be an existing intent of this task", sid)), nil
					}
					if sn.Kind != db.KindIntent {
						return actool.Errorf(fmt.Sprintf("superseded_by #%d is a %q node: only intent ids allowed", sid, sn.Kind)), nil
					}
					switch sn.State {
					case "open", "running", "done":
						// a surviving replacement — acceptable
					default:
						return actool.Errorf(fmt.Sprintf("superseded_by #%d is currently %s: the replacement has been retired/terminated — chained retirements are forbidden (first confirm a surviving intent or fact still backs this coverage)", sid, sn.State)), nil
					}
				}
				reason += "; replacement intent: " + joinNodeRefs(sup)
			}
			if reasonClaimsPremiseInvalid(reason) && !t.reasonCitesKnowledge(reason) {
				return actool.Errorf("reason claims 'premise invalidated/negated' but cites no existing fact/finding node: write the negating fact id, or use superseded_by to express duplication"), nil
			}
			retired := []int64{}
			errs := map[string]string{}
			for _, id := range ids {
				key := strconv.FormatInt(id, 10)
				n, err := t.ts.GetNode(id)
				if err != nil || n == nil {
					errs[key] = "intent doesn't exist"
					continue
				}
				if n.Kind != db.KindIntent {
					errs[key] = "not an intent node: " + n.Kind
					continue
				}
				switch n.State {
				case "open":
					// retireable
				case "running", "paused":
					errs[key] = "still running: terminate with kill_work first, then retire"
					continue
				default:
					errs[key] = "already terminal (" + n.State + ") — nothing to retire"
					continue
				}
				if _, err := t.ts.SoftDeleteIntent(id, "planner-retired: "+reason); err != nil {
					errs[key] = err.Error()
					continue
				}
				t.retiredThisRun++
				retired = append(retired, id)
			}
			out := map[string]any{"retired": retired, "retired_this_round": t.retiredThisRun, "round_limit": maxIntentRetirePerRun}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

const maxIntentRetirePerRun = 6

func reasonClaimsPremiseInvalid(reason string) bool {
	for _, w := range []string{"premise", "negated", "invalidated", "disproved", "answered", "dead goal", "premise", "negated", "invalidated", "disproved", "already answered", "dead goal"} {
		if strings.Contains(reason, w) {
			return true
		}
	}
	return false
}

func (t *ToolSet) reasonCitesKnowledge(reason string) bool {
	for _, id := range nodeRefIDs(reason) {
		n, err := t.ts.GetNode(id)
		if err != nil || n == nil {
			continue
		}
		if n.Kind == db.KindFact || n.Kind == db.KindFinding {
			return true
		}
	}
	return false
}

func nodeRefIDs(s string) []int64 {
	var out []int64
	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j > i+1 {
			if n, err := strconv.ParseInt(s[i+1:j], 10, 64); err == nil && n > 0 && n < 1<<40 {
				out = append(out, n)
			}
		}
		i = j
	}
	return out
}

func joinNodeRefs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, "#"+strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, "/")
}

func (t *ToolSet) listGoals() actool.CoreTool {
	return t.readExpTool("list_goals", "Lists this task's goal nodes and their status (open/met) for judging attainment.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			g, _ := t.ts.ListByKind(db.KindGoal, 100)
			return jsonResult(g)
		})
}

func (t *ToolSet) proveGoal() actool.CoreTool {
	return t.writeExpTool("prove_goal", "Call when you judge a finding/fact proves a goal: links the evidence node to the goal node and marks the goal met.",
		obj(map[string]any{
			"goal_id":     idp("goal node id"),
			"evidence_id": idp("id of the finding/fact node proving it"),
			"reason":      str("why this evidence satisfies the goal"),
		}, "goal_id", "evidence_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				GoalID     json.RawMessage `json:"goal_id"`
				EvidenceID json.RawMessage `json:"evidence_id"`
				Reason     string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			goal, ev := pid(a.GoalID), pid(a.EvidenceID)
			if goal == 0 || ev == 0 {
				return actool.Errorf("goal_id and evidence_id are required"), nil
			}
			goalNode, err := t.ts.GetNode(goal)
			if err != nil || goalNode == nil || goalNode.Kind != db.KindGoal {
				return actool.Errorf("goal_id must be a goal node of this task (related-task goals are read-only)"), nil
			}
			evidenceNode, err := t.ts.GetNodeWithSources(ev)
			if err != nil || evidenceNode == nil || (evidenceNode.Kind != db.KindFact && evidenceNode.Kind != db.KindFinding) {
				return actool.Errorf("evidence_id must be a fact/vuln node of this task or a directly related task"), nil
			}
			_ = t.ts.Link(ev, db.RelProves, goal)
			_ = t.ts.SetNodeState(goal, "met")
			// Each time a goal is marked met, check whether [all goals] of this task are met; if so, auto-judge
			// the task complete (set GoalMet) — no need to rely on the model explicitly calling goal_met.
			if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil && len(goals) > 0 {
				allMet := true
				for _, g := range goals {
					if g.State != "met" {
						allMet = false
						break
					}
				}
				if allMet {
					t.GoalMet = true
					t.Reason = fmt.Sprintf("all %d goals met (last triggered by goal %d)", len(goals), goal)
					return actool.Text(fmt.Sprintf("goal %d marked met; all goals of this task attained — task auto-judged complete", goal)), nil
				}
			}
			return actool.Text(fmt.Sprintf("goal %d marked met", goal)), nil
		})
}

func (t *ToolSet) goalMet() actool.CoreTool {
	return writeTool("goal_met", "[Ends the entire task immediately] — call ONLY when you're certain [all of the task's goals are truly attained, wrap up overall] (note: it's the task [as a whole] completing; attaining just one goal/one flag/one vuln [doesn't count] — use prove_goal for that goal instead). ⚠️It's not for \"ending this planning round\": when this round has no new intents to dispatch, or you're waiting for worker output — [just end the round, don't call this tool] (0 intents is completely normal). For normal judgment prefer prove_goal to prove goals one by one; goal_met is just a shortcut that bypasses per-goal proof and closes globally.",
		obj(map[string]any{"reason": str("Attainment reason (must be evidence the goals are truly attained — not a round-ending reason like \"no new directions this round\")")}, "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Reason string }
			_ = json.Unmarshal(in, &a)
			// v0.6.31 internal-build same gate: forbid overall wrap-up while unattained/unproven goals exist.
			// The old implementation let the planner goal_met-end a task on 'marginal returns exhausted' (goals marked unverified)
			// while UI/reports showed 'completed' — exactly where 'partly done but self-judged complete' came from.
			if t.ts != nil {
				unmet := 0
				var ids []string
				if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil {
					for _, g := range goals {
						if g.State != "met" {
							unmet++
							if len(ids) < 5 {
								ids = append(ids, fmt.Sprintf("#%d", g.ID))
							}
						}
					}
				}
				if unmet > 0 {
					return actool.Errorf(fmt.Sprintf("%d goals still unattained (%s) — overall wrap-up forbidden: goal_met may only be called after all goals are proven via prove_goal. Keep dispatching deep-dive/exploit-chain intents; if objectively stuck, write the blocking evidence as a fact (incl. tried techniques and failure output) — the task will end 'incomplete' via timeout/round cap rather than showing attained.", unmet, strings.Join(ids, ", "))), nil
				}
			}
			t.GoalMet = true
			t.Reason = a.Reason
			// Auditable: goal_met is a "claimed overall attainment" without prove_goal's per-goal evidence chain.
			// Mark the still-unmet goals as unverified so reports and UI can tell 'proven' from 'claimed' —
			// instead of letting a lazy wrap-up look identical to a verified attainment.
			// Skip when t.ts is nil (a no-task-context ToolSet, e.g. during tool-catalog construction): that path
			// can't reach here anyway, but a nil dereference would take the whole process down — not worth the bet.
			unproven := 0
			if t.ts != nil {
				if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil {
					for _, g := range goals {
						if g.State != "met" {
							unproven++
							_ = t.ts.MarkGoalUnverified(g.ID, a.Reason)
						}
					}
				}
			}
			return actool.Text(fmt.Sprintf("acknowledged: task marked complete (%d goals lack per-goal evidence — noted for the record)", unproven)), nil
		})
}

// --- worker write tools ---

func (t *ToolSet) addFinding() actool.CoreTool {
	return writeTool("report_finding", "Records a confirmed vuln — provide verifiable evidence (command output, logs, etc.) via evidence. Pass the current intent_id in task context. The returned finding_id is the standalone vuln-record ID; finding_node_id is the exploration node ID (keep that node number in the first line).", obj(map[string]any{
		"vulnclass": str("Vuln class — [must] pick from the standard classes: " + db.VulnClassPromptText() + ". Put a concrete CVE/vuln number in name and pick 'known vuln' as the class; only use 'other' when truly nothing fits"), "name": str("vuln name"), "severity": str("critical|high|medium|low"), "summary": str("finding summary"),
		"intent_id": idp("the current task's intent id"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "affected asset ids"},
		"evidence":         str("evidence/PoC text"),
		"evidence_hint_id": idp("optional: this task's hint node id corresponding to this vuln — auto-carries its structured traffic_refs; can't reference an inherited hint or another vuln's hint"),
		"traffic_refs": map[string]any{"type": "array", "description": "optional; for HTTP/HTTPS vulns first search and verify each request/response actually supports the vuln conclusion, then fill real IDs in replay order. For non-HTTP vulns like TCP, or when nothing was captured / no exact record found, omit or pass [] — the report isn't blocked; explain in evidence and provide other verifiable evidence instead. Don't guess IDs, infer association by domain/time, or re-probe just to fill. Roles: baseline = normal control / proof = vuln proof / verification = supplementary verification / supporting = auxiliary evidence. If an ID doesn't exist, the vuln still stores normally and that ID is listed in the return's skipped_traffic_refs — verify real IDs with traffic_get and rebind via bind_finding_traffic.",
			"items": obj(map[string]any{"traffic_id": str("a real traffic ID returned by traffic_search"), "role": map[string]any{"type": "string", "enum": []string{"baseline", "proof", "verification", "supporting"}}, "note": str("how this traffic supports the vuln conclusion")}, "traffic_id")},
	}, "vulnclass", "severity", "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			VulnClass, Name, Severity, Summary, Evidence string
			IntentID                                     json.RawMessage   `json:"intent_id"`
			AssetIDs                                     []json.RawMessage `json:"asset_ids"`
			TrafficRefs                                  []db.TrafficRef   `json:"traffic_refs"`
			EvidenceHintID                               json.RawMessage   `json:"evidence_hint_id"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.ts == nil {
			return actool.Errorf("report_finding requires task context; from a platform conversation hand the vuln to the target task via add_task_hint, carrying existing traffic_refs in the hint for the task's agent to register. Already-registered vulns can be re-bound via bind_finding_traffic."), nil
		}
		// Evidence bar (v0.4.5): critical/high needs sufficient verifiable evidence; when short it's bounced —
		// the model can add evidence or downgrade and retry, instead of a 'one-line high-severity' entering reports.
		if msg := validateFindingEvidence(a.Severity, a.Evidence); msg != "" {
			return actool.Errorf(msg), nil
		}
		// Mechanical verification-credential check (v0.4.52): critical/high must carry mechanically reproducible
		// verification credentials — HTTP status codes/curl output/tool hit results, etc. Pure version-matching fails.
		if msg := validateMechanicalEvidence(a.Severity, a.Evidence); msg != "" {
			return actool.Errorf(msg), nil
		}
		// Evidence verbatim re-verification (v0.4.29, P0b #2, PentestGPT-inspired, self-built): warn first, then block.
		// At least one line of evidence must be found verbatim in this run's real tool echoes —
		// 'none' at level=block only bounces critical/high (the two tiers with the costliest false positives).
		verifyNote := ""
		if ledger, mode := ToolOutputsFromContext(ctx); ledger != nil && mode != EvidenceVerifyOff && strings.TrimSpace(a.Evidence) != "" {
			matched, total := ledger.VerifyEvidence(a.Evidence)
			switch evidenceVerdict(matched, total) {
			case "none":
				if mode == EvidenceVerifyBlock && (a.Severity == "critical" || a.Severity == "high") {
					return actool.Errorf(fmt.Sprintf(
						"Evidence verbatim re-verification failed: not a single evidence line could be sourced verbatim in this session's tool output (compared %d valid lines). "+
							"critical/high must carry this session's real command output: paste the key tool-echo lines verbatim into evidence (command + output signatures), "+
							"or downgrade to medium and report again, or use record_fact to log it as a lead to verify.", total)), nil
				}
				verifyNote = fmt.Sprintf("⚠️ Evidence-source check: 0/%d lines found verbatim in this session's tool output — report readers can't re-verify; consider pasting the commands and raw output.", total)
			case "partial":
				verifyNote = fmt.Sprintf("⚠️ Evidence-source check: only %d/%d lines found verbatim in this session's tool output — the rest is paraphrase; quote the source text for key conclusions.", matched, total)
			}
		}
		// Full-verification / SRC evidence-completeness review (read-only, non-blocking): 13 checks + src_ready + missing,
		// written into the receipt for the model's self-check; gaps in high/critical vulns carry into auto-hop intents for filling.
		review := ReviewEvidence(a.Severity, a.VulnClass, a.Evidence)
		// Auto-binding off: ignore the evidence params instead of rejecting the call.
		// stripTrafficParameters already removes them from the advertised schema, but
		// models routinely emit fields anyway — failing here would discard a confirmed
		// finding over a stray parameter. The success path below reports evidence_status
		// "not_bound" with the "closed — can be linked manually on the page" note, which is what the caller needs.
		if !findingTrafficBindingEnabled() {
			a.TrafficRefs, a.EvidenceHintID = nil, nil
		}
		if len(a.EvidenceHintID) > 0 && pid(a.EvidenceHintID) <= 0 {
			return actool.Errorf("evidence_hint_id must be a valid hint node ID; omit it when there's no handover hint"), nil
		}
		// Vuln-asset auto-anchoring (v0.4.40, same strategy as record_fact): when the model gives no asset_ids,
		// reverse-lookup task assets from the summary/evidence text and fill — the attribution chain keeps the finding
		// linked to assets/intents so reports and per-asset aggregation don't miss entries.
		if len(a.AssetIDs) == 0 {
			if auto := t.autoAnchorFact(map[string]any{
				"summary":  a.Summary,
				"detail":   a.Evidence,
				"evidence": a.Evidence,
			}); len(auto) > 0 {
				for _, id := range auto {
					if raw, err := json.Marshal(id); err == nil {
						a.AssetIDs = append(a.AssetIDs, raw)
					}
				}
			}
		}
		refs, err := t.findingRefsFromHint(pid(a.EvidenceHintID), a.TrafficRefs)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		// Authorization-boundary guard (v0.4.63): a finding's asset_ids may only land on own-scope assets.
		if msg := t.scopeGuardError(pidList(a.AssetIDs)); msg != "" {
			return actool.Errorf(msg), nil
		}
		input := db.RecordFindingInput{TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: pid(a.IntentID), VulnClass: a.VulnClass, Name: a.Name, Severity: a.Severity, Summary: a.Summary, Evidence: a.Evidence, Worker: t.worker, AssetIDs: pidList(a.AssetIDs), CrossTaskNotifyDedup: t.CrossTaskNotifyDedup}
		var recorded *db.RecordedFinding
		if t.findingRecorder != nil {
			recorded, err = t.findingRecorder.Record(ctx, input, refs)
		} else if len(refs) > 0 {
			return actool.Errorf("traffic-evidence store unavailable; vuln not registered"), nil
		} else {
			recorded, err = t.ts.RecordFinding(ctx, input)
		}
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.notifyFinding != nil {
			iid := input.IntentID
			if iid <= 0 {
				iid = t.ownerNode
			}
			t.notifyFinding(iid, a.Summary)
		} else if t.notify != nil {
			t.notify()
		}
		t.writes.Findings++
		// Keep the first line's node-ID contract for existing reporter triggers.
		for i := range recorded.Traffic.Bindings {
			recorded.Traffic.Bindings[i].Snapshot.ReqHead = ""
			recorded.Traffic.Bindings[i].Snapshot.RespHead = ""
		}
		result := struct {
			*db.RecordedFinding
			EvidenceStatus     string `json:"evidence_status"`
			EvidenceNote       string `json:"evidence_note,omitempty"`
			EvidenceVerifyNote string `json:"evidence_verify_note,omitempty"`
			ChainIntentID      int64  `json:"chain_intent_id,omitempty"`
			SRCReview          any    `json:"src_review,omitempty"`
			ChainNote          string `json:"chain_note,omitempty"`
		}{RecordedFinding: recorded, EvidenceStatus: "bound", EvidenceVerifyNote: verifyNote, SRCReview: review}
		if len(recorded.CrossTaskDupTasks) > 0 {
			ids := make([]string, 0, len(recorded.CrossTaskDupTasks))
			for _, tid := range recorded.CrossTaskDupTasks {
				ids = append(ids, strconv.FormatInt(tid, 10))
			}
			result.EvidenceNote = (func(prev string) string {
				if prev != "" {
					return prev + " "
				}
				return ""
			})(result.EvidenceNote) + fmt.Sprintf(
				"◎ Cross-task notice: a vuln with the same fingerprint already exists in task %s — this push was suppressed by cross-task dedup (the vuln record stays in this task, visible on the page). "+
					"This usually means the asset belongs to another task's scope — check this task's authorization boundary and stop digging into other tasks' assets.", strings.Join(ids, "/"))
		}
		if len(recorded.Traffic.Bindings) == 0 {
			result.EvidenceStatus = "not_bound"
			result.EvidenceNote = "Vuln saved, no traffic bound. TCP/no-capture cases can continue normally; if you have verified HTTP traffic, rebind via an available bind_finding_traffic or the vuln page, then complete the evidence handover. Don't re-create the vuln."
			if !findingTrafficBindingEnabled() {
				result.EvidenceNote = "Vuln saved. Agent auto traffic-binding is off — traffic can be linked manually on the page."
			}
		}
		if recorded.Duplicate {
			// Fingerprint hit: evidence merged into the existing record. The hard-gate semantics must be spelled out,
			// or the model reads 'duplicate' as failure and re-reports it differently.
			result.EvidenceNote = "★ This vuln was already reported (finding_id=" + strconv.FormatInt(recorded.FindingID, 10) +
				"); this evidence was [merged] into the existing record — that's not a failure: no need to report_finding again, and definitely don't re-report under a different title/class. " +
				"Just keep exploring other directions; if the original record's severity changed, it was updated in this merge."
			if len(recorded.Traffic.Bindings) == 0 {
				result.EvidenceStatus = "merged"
			}
		}
			// Some refs didn't bind (traffic ID nonexistent/body unreadable): the vuln is stored, but the model must
			// know which evidence didn't take effect — otherwise it thinks evidence is complete and the report loses it.
			// Placed after the duplicate branch: both notes must stay (merge first, then the failed refs).
		if len(recorded.SkippedRefs) > 0 {
			ids := make([]string, 0, len(recorded.SkippedRefs))
			for _, r := range recorded.SkippedRefs {
				ids = append(ids, r.TrafficID)
			}
			result.EvidenceStatus = "partially_bound"
			result.EvidenceNote += " ⚠ These traffic refs didn't take effect (ID nonexistent or body unreadable): " + strings.Join(ids, ", ") +
				". Effective refs bound normally; if these IDs do exist, verify the real IDs with traffic_get and rebind via bind_finding_traffic."
		}
		// Attack-chain auto-hop (v0.4.63 red-team batch delegation): only newly created findings hop; duplicate reports (merged) don't dispatch.
		if !recorded.Duplicate {
			if cid, note := t.dispatchChainIntent(a.VulnClass, a.Name, a.Summary, a.Severity,
				pidList(a.AssetIDs), recorded.NodeID, pid(a.IntentID), review.Missing); cid > 0 || note != "" {
				result.ChainIntentID = cid
				result.ChainNote = note
			}
		}
		// Retroactive attribution (v0.4.47): all evidence under the same intent dir with empty finding_id is attributed at once.
		if bindIntent := pid(a.IntentID); bindIntent > 0 && t.taskID > 0 {
			if n, err := t.ts.RetroBindIntentEvidence(t.taskID, bindIntent, recorded.FindingID); err == nil && n > 0 {
				result.EvidenceNote += fmt.Sprintf(" ✨ Auto-attributed %d historical evidence items of this intent.", n)
			}
		}
		raw, _ := json.Marshal(result)
		return actool.Text(fmt.Sprintf("finding recorded: %d\n%s", recorded.NodeID, raw)), nil
	})
}

// recordFact writes a general exploration RESULT/conclusion (not a vuln, not a
// new asset) into the EXPLORATION graph, chained to the intent that produced it.
// This is the home for observations and — importantly — negative results
// ("port closed", "param not injectable", "no login found"). Such conclusions
// must NOT be stuffed into the asset graph via upsert_asset.
// factItem is one fact in a record_fact batch/single call.
type factItem struct {
	Summary    string            `json:"summary"`
	Detail     string            `json:"detail"`
	Evidence   string            `json:"evidence"`   // one line of key evidence (command + key output lines) backing the conclusion, for later re-checks
	Confidence string            `json:"confidence"` // observed (directly seen) | inferred (deduced from phenomena)
	IntentID   json.RawMessage   `json:"intent_id"`
	AssetIDs   []json.RawMessage `json:"asset_ids"`
}

// recordOneFact writes one fact node and links it to the intent (intent→yields→fact). defaultIntent is
// the default intent for batch calls (used when this item doesn't give intent_id).
func (t *ToolSet) recordOneFact(it factItem, defaultIntent int64) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary must not be empty")
	}
	payload := map[string]any{"summary": it.Summary}
	if it.Detail != "" {
		payload["detail"] = it.Detail
	}
	if e := strings.TrimSpace(it.Evidence); e != "" {
		payload["evidence"] = e
	}
	if c := strings.TrimSpace(it.Confidence); c != "" {
		payload["confidence"] = c
	}
	intent := pid(it.IntentID)
	if intent <= 0 {
		intent = defaultIntent
	}
	if intent > 0 {
		node, err := t.ts.GetNode(intent)
		if err != nil || node == nil || node.Kind != db.KindIntent {
			return 0, fmt.Errorf("intent_id must be an intent of this task (related-task intents are read-only)")
		}
	}
	// a fact is its OWN node kind (distinct from a vuln finding).
	assetIDs := pidList(it.AssetIDs)
	missing := t.missingAssetIDs(assetIDs)
	// Coverage attribution (v0.4.27): when the model gives no asset_ids, reverse-lookup task assets from the fact text to auto-anchor.
	// Task-5 measurement: the main reason only 30% of 493 endpoints were tested wasn't lack of testing — workers
	// probed heavily via Bash curl then called record_fact without asset_ids, so coverage couldn't be reconciled and the
	// planner was misled into re-scanning the surface. Anchors are provenance edges: auto-anchoring only affects
	// coverage stats and lineage display — it doesn't change fact content.
	if len(assetIDs) == 0 {
		if auto := t.autoAnchorFact(payload); len(auto) > 0 {
			assetIDs = auto
		}
	}
	// Authorization-boundary guard (v0.4.63): a fact's anchors may only land on own-scope assets.
	if msg := t.scopeGuardError(assetIDs); msg != "" {
		return 0, fmt.Errorf("%s", msg)
	}
	id, err := t.ts.AddNode(db.KindFact, payload, 5, "confirmed", t.worker, assetIDs)
	if err != nil {
		return 0, err
	}
	if intent > 0 {
		_ = t.ts.Link(intent, db.RelYields, id) // chain: intent -> fact
	}
	t.writes.Facts++
	// The fact was written, but edges pointing at nonexistent assets were dropped from the anchors. Tell the model —
	// next time it'll know that asset id doesn't exist; otherwise it keeps using the same fake id and the planner
	// sees an asset chain missing the assets that should have been linked.
	if len(missing) > 0 {
		t.lastMissingAssets = append(t.lastMissingAssets, missing...)
	}
	return id, nil
}

// missingAssetIDs returns the subset of ids that do NOT exist in the asset
// table. Used to tell the model "this asset id is not real" instead of silently
// dropping the anchor.
func (t *ToolSet) missingAssetIDs(ids []int64) []int64 {
	if len(ids) == 0 || t.as == nil {
		return nil
	}
	found, err := t.as.GetByIDs(ids)
	if err != nil {
		return nil
	}
	have := make(map[int64]bool, len(found))
	for _, a := range found {
		if a != nil {
			have[a.ID] = true
		}
	}
	var missing []int64
	for _, id := range ids {
		if !have[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

// scopeGuardError is the authorization-boundary gate for writeback anchors (v0.4.63, layer ④ of the
// cross-task asset-bleed defense): a fact/finding's asset_ids may only reference 'own-scope' assets —
//
//	own    : matches this task's own scope, or was discovered/registered by this task (task_ids contains it) → allow;
//	source : only matches a source/inherited task's scope → deny by default (inherited scope is read-only; if
//	         genuinely authorized, add explicitly via add_task_scope, or enable scope_inherit_writes);
//	foreign: completely out of bounds → always deny.
//
// An empty return means allowed; non-empty is a corrective notice for the model (with asset labels, so it can self-correct).
// Query failures fail open (empty return) — a gate malfunction mustn't jam all normal tasks; the caller logs it.
func (t *ToolSet) scopeGuardError(ids []int64) string {
	if !t.ScopeWriteGuard || t.as == nil || t.taskID <= 0 || len(ids) == 0 {
		return ""
	}
	own, source, foreign, err := t.as.ClassifyAssetsForTask(t.taskID, ids)
	if err != nil {
		return "" // fail-open: classification-query failures don't block normal tasks; caller's log is the backstop
	}
	_ = own
	if t.ScopeInheritWrites {
		source = nil
	}
	if len(source) == 0 && len(foreign) == 0 {
		return ""
	}
	label := func(ids []int64) string {
		assets, err := t.as.GetByIDs(ids)
		if err != nil {
			return ""
		}
		parts := make([]string, 0, len(assets))
		for i, a := range assets {
			if a == nil {
				continue
			}
			name := a.Domain
			if name == "" {
				name = a.URL
			}
			if name == "" {
				name = a.IP
			}
			if name == "" {
				name = a.AppName
			}
			if name == "" {
				name = a.RootDomain
			}
			if i >= 6 {
				parts = append(parts, fmt.Sprintf("…and %d more", len(assets)))
				break
			}
			parts = append(parts, fmt.Sprintf("#%d %s", a.ID, name))
		}
		return strings.Join(parts, ", ")
	}
	var b strings.Builder
	b.WriteString("Scope guard: the following assets aren't in this task's own scope — writeback/reporting forbidden:")
	if len(source) > 0 {
		b.WriteString(fmt.Sprintf("\n· source/inherited task scope (read-only, not writable by default): %s", label(source)))
	}
	if len(foreign) > 0 {
		b.WriteString(fmt.Sprintf("\n· completely out of bounds: %s", label(foreign)))
	}
	b.WriteString("\nHow to proceed (pick one): ① change this conclusion's asset_ids to own-scope assets, or drop asset_ids so only the conclusion itself is recorded; " +
		"② if the asset is genuinely within this task's authorization, add it via add_task_scope first, then retry. " +
		"Cross-domain attribution conclusions must be re-verified with evidence on both domains first (this domain re-checked 200/identical content); unverified ones must be written as inferred, never observed.")
	return b.String()
}

var (
	factURLRe  = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	factHostRe = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b`)
)

// autoAnchorFact infers anchors for a fact that came in without asset_ids:
// pull URLs/hosts out of the fact text, match them against task-owned assets,
// cap the result (a fact name-dropping 20 hosts must not mark 20 assets tested).
// Best effort — any failure just yields no anchors, the fact is written anyway.
func (t *ToolSet) autoAnchorFact(payload map[string]any) []int64 {
	if t.as == nil || t.taskID <= 0 {
		return nil
	}
	parts := make([]string, 0, 3)
	for _, k := range []string{"summary", "detail", "evidence"} {
		if s, ok := payload[k].(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	text := strings.Join(parts, "\n")
	hostSet := map[string]bool{}
	var hosts []string
	for _, m := range factHostRe.FindAllString(text, 16) {
		h := strings.ToLower(m)
		if !hostSet[h] && net.ParseIP(h) == nil && strings.Contains(h, ".") {
			hostSet[h] = true
			hosts = append(hosts, h)
		}
		if len(hosts) >= 12 {
			break
		}
	}
	urlSet := map[string]bool{}
	var urls []string
	for _, m := range factURLRe.FindAllString(text, 16) {
		m = strings.TrimRight(m, ".,;,.;))]")
		if u, err := url.Parse(m); err == nil && u.Host != "" {
			m = fmt.Sprintf("%s://%s%s", u.Scheme, strings.ToLower(u.Host), u.EscapedPath())
		}
		if !urlSet[m] {
			urlSet[m] = true
			urls = append(urls, m)
		}
		if len(urls) >= 12 {
			break
		}
	}
	if len(hosts) == 0 && len(urls) == 0 {
		return nil
	}
	ids, err := t.as.ResolveHostAssets(t.taskID, hosts, urls, 6)
	if err != nil {
		return nil
	}
	return ids
}

func (t *ToolSet) recordFact() actool.CoreTool {
	return t.writeExpTool("record_fact", "Writes an exploration [fact/conclusion] into the exploration graph, linked to the producing intent (intent_id). For recording exploration results — both [positive conclusions] like fingerprints/enumeration and [negative conclusions] like 'port closed'/'param not injectable'/'no login entry found'.\n"+
		"⚠️Multiple observations from one probe must be [merged into ONE fact], not split into several — merge whatever can be merged: summary = one sentence summarizing this conclusion, detail = related details (may hold multiple items). E.g. a fingerprint intent → one fact {summary:'identified site X's tech stack and response features', detail:'nginx 1.25 / Vue3 / 200 / title=.. / body_len=..'} — not one fact each for status code, fingerprint, title. An intent usually yields one fact; splitting too fine inflates the graph unboundedly.\n"+
		"★The facts array writes multiple [distinct] conclusions at once (each may omit intent_id — the top-level intent_id is the default). Returns an ids array, same length and order as facts.\n"+
		"⚠️Only write conclusions you [actually saw] in tool output — don't imagine. evidence and confidence exist to keep inaccurate conclusions from polluting the graph:\n"+
		"  · evidence = [one line] of key evidence backing this conclusion (command + the one or two most-proving output lines); **keep it terse** — details already live in detail, don't paste big output here.\n"+
		"  · confidence = observed (directly seen in output) | inferred (deduced from phenomena).\n"+
		"  · **Negative conclusions** (not injectable / port closed / no entry found etc.) are written as \"observation + tentative reading\" only — state what you actually saw; whether to abandon the direction is the planner's call, made globally. Always give evidence; mark inferred when techniques weren't exhausted or evidence is weak (incl. only-probed-once, looks-like) — mark observed only when truly exhausted and directly seen.",
		obj(map[string]any{
			"facts":      map[string]any{"type": "array", "description": "[For multiple distinct conclusions] fact array; element fields mirror the top-level fields below (summary/detail/evidence/confidence/intent_id/asset_ids); omitted intent_id falls back to the top-level one. Returned ids match this array's length and order.", "items": map[string]any{"type": "object"}},
			"summary":    str("[One summary sentence] of this exploration's conclusion (a digest of detail)"),
			"intent_id":  idp("id of the intent producing this fact (the intent you claimed; the batch default)"),
			"detail":     str("Related details of this fact: put all observations from this probe here"),
			"evidence":   str("[One line] of key evidence: command + the most-proving output line(s). Keep it terse — don't paste big output (details go in detail)."),
			"confidence": str("observed (directly seen in output) | inferred (deduced from phenomena). Mark negative conclusions honestly."),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "related asset ids (optional, 0/1/many): which assets this fact involves"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Facts    []factItem `json:"facts"`
				factItem            // single mode + batch default intent_id
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Facts) > 0
			items := a.Facts
			// Max 10 per call (v0.4.44): prevents a worker writing dozens of over-split facts in one call and
			// flooding the graph. Over-limit is truncated and the return tells the model.
			if len(items) > 10 {
				items = items[:10]
			}
			if !batch {
				items = []factItem{a.factItem}
			}
			defaultIntent := pid(a.factItem.IntentID) // top-level intent_id = batch default

			ids := make([]int64, len(items))
			errs := map[string]string{}
			t.lastMissingAssets = nil
			for i, it := range items {
				id, err := t.recordOneFact(it, defaultIntent)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			missing := t.lastMissingAssets

			if !batch { // single: keep the original return shape
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(factRecordText(ids[0], missing)), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			if len(missing) > 0 {
				out["skipped_asset_ids"] = missing
				out["note"] = fmt.Sprintf("the following asset ids don't exist — anchors skipped (the fact itself was written): %v", missing)
			}
			return jsonResult(out)
		})
}

// factRecordText renders the record_fact single-item result. Missing asset ids
// are reported explicitly: silently dropping the anchor would leave the model
// convinced it linked the fact to an asset, and it would keep reusing the same
// fabricated id on every later write-back.
func factRecordText(id int64, missing []int64) string {
	if len(missing) == 0 {
		return fmt.Sprintf("fact recorded: %d", id)
	}
	return fmt.Sprintf("fact recorded: %d (note: asset ids %v don't exist — anchors skipped; the fact itself was saved. Use list_assets for real ids)", id, missing)
}

type hintItem struct {
	Text        string            `json:"text"`
	AssetIDs    []json.RawMessage `json:"asset_ids"`
	TrafficRefs []db.TrafficRef   `json:"traffic_refs"`
}

// addOneHint hangs a hint node (active/human) onto the exploration graph; assets may be anchored; returns the id.
func (t *ToolSet) addOneHint(it hintItem) (int64, error) {
	if len(it.TrafficRefs) > 0 && !findingTrafficBindingEnabled() {
		return 0, fmt.Errorf("agent auto traffic-binding is off — hints carrying traffic_refs weren't saved; enable it in system settings, or hand over text only")
	}
	if strings.TrimSpace(it.Text) == "" {
		return 0, fmt.Errorf("text must not be empty")
	}
	var anchors []int64
	for _, raw := range it.AssetIDs {
		if tid := pid(raw); tid > 0 {
			anchors = append(anchors, tid)
		}
	}
	refs, err := db.NormalizeTrafficRefs(it.TrafficRefs)
	if err != nil {
		return 0, err
	}
	payload := map[string]any{"text": it.Text}
	if len(refs) > 0 {
		payload["traffic_refs"] = refs
	}
	// Waking the planner isn't done per-item here — addHint triggers it once after the whole batch (carrying the hint text),
	// avoiding a multi-hint add_hint spamming the planner's trigger lines one by one.
	return t.ts.AddNode(db.KindHint, payload, 0, "active", "human", anchors)
}

type goalItem struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass"`
}

// addOneGoal hangs a goal node (open) onto the exploration graph: linked to the task root (origin fact, rel spawns).
// origin takes t.worker (default system): goals written by the decomposer are marked "goals", by the main agent at
// runtime "human". Waking the planner is done once by setGoals after the whole batch (see below) — here we only persist.
func (t *ToolSet) addOneGoal(it goalItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text must not be empty")
	}
	payload := map[string]any{"text": text}
	if vc := db.NormalizeVulnClass(it.VulnClass); vc != "" {
		payload["vulnclass"] = vc
	}
	origin := t.worker
	if origin == "" {
		origin = "system"
	}
	id, err := t.ts.AddNode(db.KindGoal, payload, 0, "open", origin, nil)
	if err != nil {
		return 0, err
	}
	if of, _ := t.ts.OriginFactID(); of > 0 && id > 0 {
		_ = t.ts.Link(of, db.RelSpawns, id) // goals descend from the task root (origin fact)
	}
	return id, nil
}

// setGoals adds exploration goals (goal nodes) to [this task]. It's both the goal decomposer's submit tool and the main
// agent's runtime goal-adding tool — one governed tool, its description/schema editable on the web, bindable per agent.
func (t *ToolSet) setGoals() actool.CoreTool {
	return writeTool("set_goals",
		"Adds exploration goals (goal) to [this task]. A goal = a final deliverable/verifiable result — not an attack step or a recon action.\n"+
			"★Prefer batch: put multiple goals in the goals array in one call — returned ids match its length and order (failed items id=0, details in errors). For a single goal omit goals and use top-level text.\n"+
			"vulnclass optional: the corresponding vuln class — standard classes: "+db.VulnClassPromptText()+"; leave empty for business-logic goals. The system marks met when attained; this tool only adds.",
		obj(map[string]any{
			"goals":     map[string]any{"type": "array", "description": "[Prefer this] goals array to add, processed in order. Each element: text (required, one independently verifiable final goal) + vulnclass (optional). Returned ids match this array's length and order.", "items": map[string]any{"type": "object"}},
			"text":      str("[single] one independently verifiable final goal"),
			"vulnclass": str("[single] the corresponding vuln class (if clear), standard classes: " + db.VulnClassPromptText() + "; may be left empty for business-logic goals"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_goals not enabled: ExplorationStore not initialized"), nil
			}
			var a struct {
				Goals    []goalItem `json:"goals"`
				goalItem            // single mode: top-level text/vulnclass
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Goals) > 0
			items := a.Goals
			if !batch {
				items = []goalItem{a.goalItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneGoal(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			if len(addedTexts) > 0 {
				// Wake the planner (once per batch). Prefer notifyGoal: one set_goals call records a single "human added
				// N goals: …" trigger instead of spamming per-item; decomposer/worker lack this callback → fall back to bare
				// notify (the decomposer's round-0 has no notify wired either — a no-op, since the planner hasn't started).
				switch {
				case t.notifyGoal != nil:
					t.notifyGoal(addedTexts)
				case t.notify != nil:
					t.notify()
				}
				// Goals added by the main agent at runtime → pull a completed/paused task back to running (the terminal-state gate
				// swallows ordinary notify — an explicit revive is required). Only mainagent wires this callback; decomposer/worker are nil.
				if t.resumeTask != nil {
					t.resumeTask()
				}
			}

			if !batch { // single: keep the original return shape
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("goal added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

type constraintItem struct {
	Text string `json:"text"`
	Type string `json:"type"` // allow | deny
}

// addOneConstraint persists one operation constraint to task_constraints. origin takes t.worker (default system):
// the decomposer writes "goals", the main agent writes "human".
func (t *ToolSet) addOneConstraint(it constraintItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text must not be empty")
	}
	kind := strings.TrimSpace(strings.ToLower(it.Type))
	if kind == "" {
		kind = "deny" // default to deny: more conservative when the type isn't marked
	}
	if kind != "allow" && kind != "deny" {
		return 0, fmt.Errorf("type must be allow or deny")
	}
	return t.ts.AddConstraint(kind, text, t.worker)
}

// setConstraints adds operation constraints to [this task] (allow = what's allowed / deny = what's forbidden). It's both
// the goal decomposer's round-0 constraint-extraction submit tool and the main agent's runtime constraint-adding tool —
// one governed tool, its description/schema editable on the web, bindable per agent. Constraints inject into planner/worker
// system prompts to bound exploration.
func (t *ToolSet) setConstraints() actool.CoreTool {
	return writeTool("set_constraints",
		"Adds operation constraints to [this task] to bound exploration: type=allow (operations permitted) or deny (operations forbidden).\n"+
			"A constraint = a rule about 'which operations may/may not be done' (e.g. 'only test the current port, don't scan others', 'no write ops on the production DB', 'passive recon only') — not a goal, not an attack step.\n"+
			"★Prefer batch: put multiple constraints in the constraints array in one call — returned ids match its length and order (failed items id=0, details in errors). For a single constraint omit constraints and use top-level text/type.\n"+
			"Only register constraints [explicitly stated] in the task goal/description — don't invent any; when unsure about the type, use deny (more conservative).",
		obj(map[string]any{
			"constraints": map[string]any{"type": "array", "description": "[Prefer this] constraints array to add, processed in order. Each element: text (required, one constraint) + type (allow|deny). Returned ids match this array's length and order.", "items": map[string]any{"type": "object"}},
			"text":        str("[single] content of one operation constraint"),
			"type":        str("[single] allow (permitted) or deny (forbidden); defaults to deny"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_constraints not enabled: ExplorationStore not initialized"), nil
			}
			var a struct {
				Constraints    []constraintItem `json:"constraints"`
				constraintItem                  // single mode: top-level text/type
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Constraints) > 0
			items := a.Constraints
			if !batch {
				items = []constraintItem{a.constraintItem}
			}
			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneConstraint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			if !batch { // single: keep the simple return shape
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("constraint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) addHint() actool.CoreTool {
	return t.writeExpTool("add_hint", "Hangs a human/main-agent strategy hint onto the exploration graph — the planner reads it when generating intents next time.\n"+
		"★Prefer batch: put multiple hints in the hints array in one call (saves round-trips vs one-by-one). Returns an ids array, same length and order as hints (failed items id=0, details in errors). For a single hint omit hints and use top-level text.",
		obj(map[string]any{
			"hints":        map[string]any{"type": "array", "description": "[Prefer this] hints array to add, processed in order. Each element's fields mirror the top-level fields below (text/asset_ids/traffic_refs). Returned ids match this array's length and order.", "items": obj(map[string]any{"text": str("hint content"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": HintTrafficSchema()})},
			"text":         str("[single] hint content, e.g. 'focus on post-auth endpoints'"),
			"traffic_refs": HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "anchored asset ids (optional, 0/1/many)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Hints    []hintItem `json:"hints"`
				hintItem            // single mode: top-level text/asset_ids
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Hints) > 0
			items := a.Hints
			if !batch {
				items = []hintItem{a.hintItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneHint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			if len(addedTexts) > 0 {
				// Wake the planner (once per batch). Prefer notifyHint: one add_hint call records a single "human added
				// N strategy hints: …" trigger — the planner is explicitly told 'this round was triggered by new hints' and sees
				// the hint content; without that callback it falls back to bare notify (a bare wake — the hint still folds into the graph for it to read).
				switch {
				case t.notifyHint != nil:
					t.notifyHint(addedTexts)
				case t.notify != nil:
					t.notify()
				}
			}

			if !batch { // single: keep the original return shape
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("hint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// killWorkTool lets the planner terminate a single running work (by intent id).
func (t *ToolSet) killWorkTool() actool.CoreTool {
	return t.writeExpTool("kill_work", "Terminates a running intent (work). Use to stop a runaway/pointless exploration; the terminated intent is marked stopped and won't auto-requeue. Check what it's doing with get_worker_output first.",
		obj(map[string]any{"intent_id": idp("intent id to terminate (= work handle)")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.killWork == nil {
				return actool.Errorf("kill_work is currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id must be an intent of this task (related-task intents are read-only)"), nil
			}
			if err := t.killWork(id); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("termination signal sent to intent %d's work", id)), nil
		})
}

// steerWorkTool lets the planner inject a mid-run course-correction into a running
// work WITHOUT killing it: the message reaches the worker before its next tool call,
// which re-plans its next step (already-gathered context is kept). For in-intent
// nudges ("stop doing X, focus Y"); if the whole direction is wrong use kill_work + a new intent.
func (t *ToolSet) steerWorkTool() actool.CoreTool {
	return t.writeExpTool("steer_work", "Injects a course-correction instruction into a running intent (work) in real time — doesn't interrupt it, doesn't lose progress: the worker receives your instruction before its next action and adjusts. For [in-intent] corrections like 'stop X, focus Y'; if the whole direction is wrong use kill_work + a new intent. Check what it's doing with get_worker_output first.",
		obj(map[string]any{
			"intent_id": idp("intent id to correct (= work handle)"),
			"message":   str("the course-correction instruction for the worker — clearly say what to stop and what to turn to"),
		}, "intent_id", "message"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.steerWork == nil {
				return actool.Errorf("steer_work is currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Message  string          `json:"message"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id must be an intent of this task (related-task intents are read-only)"), nil
			}
			if strings.TrimSpace(a.Message) == "" {
				return actool.Errorf("message is required"), nil
			}
			if err := t.steerWork(id, a.Message); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("course-correction injected into intent %d's work (effective next step)", id)), nil
		})
}

// getWorkerOutput returns a work's final (or as-of-abort) conclusion text by intent id.
func (t *ToolSet) getWorkerOutput() actool.CoreTool {
	return t.readExpTool("get_worker_output", "Fetches an intent's (work's) final output conclusion from this task or a directly related task. Related-task results carry source_task_id/inherited=true and are read-only. Normally ended works return their summary; terminated (stopped)/abnormal works return their last output as of the abort.",
		obj(map[string]any{"intent_id": idp("intent id (= work handle)")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			intentNode, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id doesn't belong to this task or its directly related tasks"), nil
			}
			acts, _, err := t.ts.ActivityListWithSources(id, 0, 1000)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var chosen, fallback *db.Activity
			for i := range acts {
				switch acts[i].Kind {
				case "result":
					chosen = &acts[i]
					fallback = &acts[i]
				case "text":
					fallback = &acts[i]
				}
			}
			pick := chosen
			if pick == nil {
				pick = fallback
			}
			if pick == nil {
				if intentNode.Inherited {
					return jsonResult(inheritedMap(map[string]any{
						"intent_id": id, "final_text": "(this work has no output yet)",
					}, intentNode.SourceTaskID))
				}
				return actool.Text("(this work has no output yet)"), nil
			}
			detail, _ := t.ts.ActivityDetailWithSources(pick.ID)
			if detail == "" {
				detail = pick.Summary
			}
			result := map[string]any{
				"intent_id": id, "final_text": detail,
				"summary": pick.Summary, "is_error": pick.IsError,
			}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// traceSteps renders summary-only trace rows, re-truncating each summary to 100
// chars — the stored summary is capped at 200 for the UI transcript; the trace
// tools want it tighter since a whole work's step list is many rows.
func traceSteps(acts []db.Activity) []map[string]any {
	steps := make([]map[string]any, 0, len(acts))
	for i := range acts {
		step := map[string]any{
			"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
			"is_error": acts[i].IsError, "summary": firstLine(acts[i].Summary, 100),
		}
		if acts[i].Inherited {
			inheritedMap(step, acts[i].SourceTaskID)
		}
		steps = append(steps, step)
	}
	return steps
}

// getWorkerTrace exposes a work's execution PROCESS (not just its final output):
// list step summaries, keyword-search within one work, or pull full detail of a
// few specific steps. Thinking steps are excluded everywhere.
func (t *ToolSet) getWorkerTrace() actool.CoreTool {
	return t.readExpTool("get_worker_trace",
		"Views an intent's (work's) [execution process] (unlike get_worker_output which only gives the final conclusion). Three usages:\n"+
			"① intent_id only → returns a per-step summary stream of that work (summary≤100 chars, with step_id; just an action outline, no full output);\n"+
			"② intent_id + q → returns only step summaries matching the keyword (searched in both summaries and full output; still summaries only — use ③ for content);\n"+
			"③ intent_id + step_ids → returns those steps' full content (detail); max 5 per call — extras return the first 5 with the rest listed in notice/omitted_step_ids.\n"+
			"Typical flow: locate suspicious step_ids via ①/②, then fetch their full output via ③. Thinking steps excluded. Directly related tasks' historical traces supported; their results carry source_task_id/inherited=true and are read-only.",
		obj(map[string]any{
			"intent_id": idp("intent id (= work handle)"),
			"q":         str("keyword: only return steps whose summary/full output matches it (optional; mutually exclusive with step_ids)"),
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "step_ids to fetch full content for (from ①/② returns; max 5 per call — extras return the first 5, the rest listed in omitted_step_ids)"},
			"limit":     intp("return cap for the summary stream/search (optional)"),
		}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage   `json:"intent_id"`
				Q        string            `json:"q"`
				StepIDs  []json.RawMessage `json:"step_ids"`
				Limit    int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			intentNode, nodeErr := t.ts.GetNodeWithSources(id)
			if nodeErr != nil {
				return actool.Errorf(nodeErr.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id doesn't belong to this task or its directly related tasks"), nil
			}
			// ③ detail drill-down by step ids, thinking excluded by the store.
			if len(a.StepIDs) > 0 {
				// Dedup + drop invalid ids first so garbage/duplicates don't eat into
				// the per-call cap. detail is returned in full (untruncated), so the
				// cap bounds one tool result; over the cap we serve the first N and
				// tell the model exactly which ids were deferred, instead of erroring
				// and forcing it to re-plan the call.
				const maxStepIDs = 5
				var ids []int64
				seen := make(map[int64]bool)
				for _, raw := range a.StepIDs {
					if v := pid(raw); v > 0 && !seen[v] {
						seen[v] = true
						ids = append(ids, v)
					}
				}
				var omitted []int64
				if len(ids) > maxStepIDs {
					omitted = append(omitted, ids[maxStepIDs:]...)
					ids = ids[:maxStepIDs]
				}
				acts, err := t.ts.ActivityByIDsWithSources(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				steps := make([]map[string]any, 0, len(acts))
				for i := range acts {
					if acts[i].NodeID == nil || *acts[i].NodeID != id || acts[i].Inherited != intentNode.Inherited ||
						(acts[i].Inherited && acts[i].SourceTaskID != intentNode.SourceTaskID) {
						continue
					}
					step := map[string]any{
						"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
						"is_error": acts[i].IsError, "detail": acts[i].Detail,
					}
					if acts[i].Inherited {
						inheritedMap(step, acts[i].SourceTaskID)
					}
					steps = append(steps, step)
				}
				result := map[string]any{"intent_id": id, "steps": steps, "returned_step_ids": ids}
				if len(omitted) > 0 {
					// returned_step_ids/omitted_step_ids let the model decide programmatically
					// whether another call is worth it; the notice states the same in prose.
					result["omitted_step_ids"] = omitted
					result["notice"] = fmt.Sprintf(
						"at most %d steps' full content per call; the first %d were returned (%v), the remaining %d are %v. "+
							"If this already suffices, no need to fetch the rest; if more is needed, call again with those step_ids.",
						maxStepIDs, len(ids), ids, len(omitted), omitted)
				}
				if intentNode.Inherited {
					inheritedMap(result, intentNode.SourceTaskID)
				}
				return jsonResult(result)
			}
			// ①/② summary stream, optionally keyword-filtered; 100-char summaries.
			var acts []db.Activity
			var err error
			if strings.TrimSpace(a.Q) != "" {
				acts, err = t.ts.ActivityTraceSearchWithSources(id, a.Q, a.Limit)
			} else {
				acts, err = t.ts.ActivityTraceWithSources(id, a.Limit)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			result := map[string]any{"intent_id": id, "steps": traceSteps(acts)}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// searchAllWorkerTraces keyword-searches EVERY work's process in this task — for
// finding what a worker saw but never wrote back as a fact. Returns only matching
// summaries (≤100 chars), each tagged with its intent_id for follow-up drill-down.
func (t *ToolSet) searchAllWorkerTraces() actool.CoreTool {
	return t.readExpTool("search_all_worker_traces",
		"[Usually not recommended — the system already provides most of it] Keyword-search (q) inside [execution processes of other works in this task] — for recovering something a worker saw but never wrote into a fact (a path/token/error etc.). "+
			"Your own intent's steps are auto-excluded (they're already in your context). "+
			"Returns only matching steps' summaries (≤100 chars), each with its intent_id; fetch full content via get_worker_trace(intent_id, step_ids=[...]) accordingly.",
		obj(map[string]any{
			"q":     str("keyword (searched across all work steps' summaries + full output)"),
			"limit": intp("return cap, default 100 (optional)"),
		}, "q"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Q) == "" {
				return actool.Errorf("q is required"), nil
			}
			// Exclude the caller's own intent's steps (the worker's own trace is already in its context).
			acts, err := t.ts.ActivityTraceSearchAllWithSources(t.ownerNode, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits := make([]map[string]any, 0, len(acts))
			for i := range acts {
				var intent int64
				if acts[i].NodeID != nil {
					intent = *acts[i].NodeID
				}
				hit := map[string]any{
					"intent_id": intent, "step_id": acts[i].ID, "worker": acts[i].Worker,
					"kind": acts[i].Kind, "tool": acts[i].Tool, "is_error": acts[i].IsError,
					"summary": firstLine(acts[i].Summary, 100),
				}
				if acts[i].Inherited {
					inheritedMap(hit, acts[i].SourceTaskID)
				}
				hits = append(hits, hit)
			}
			return jsonResult(map[string]any{"query": a.Q, "hits": hits})
		})
}

// listWorkerTraces gives planner/mainagent a lightweight index of the works in
// this task — intent_id + one-line summary + state — so they can DISCOVER which
// works to inspect via get_worker_trace during cross-work review. Registered in
// MainAgentTools only: workers get their per-intent context from the engine and
// must not wander the graph (see the WorkerTools comment in tools_insert.go). Excludes
// still-open intents (not yet run → no process to inspect).
func (t *ToolSet) listWorkerTraces() actool.CoreTool {
	return t.readExpTool("list_worker_traces",
		"[Usually not recommended — the system already provides most of it] Lists the index of [works (intents) that already ran] in this task: intent_id + one-line direction (summary) + status. "+
			"You (from the mainagent/planner view) can usually already see the global picture in graph_overview; when you need to review per-work execution, use it to discover which works are worth reading — then get_worker_trace(intent_id) for their steps and get_worker_trace(intent_id, step_ids=[...]) for details. "+
			"Only executed works are listed (running/done/exhausted/blocked/stopped) — not-yet-run open intents are excluded.",
		obj(map[string]any{
			"q":     str("filter by summary keyword (optional)"),
			"limit": intp("return cap, default 50 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			all, err := t.ts.ListByKindWithSources(db.KindIntent, 500)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Q))
			out := make([]map[string]any, 0, limit)
			for _, n := range all {
				if n.Inherited && n.State == "running" {
					continue
				}
				switch n.State {
				case "running", "done", "exhausted", "blocked", "stopped": // has run → has a process
				default:
					continue
				}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				summary, _ := p["summary"].(string)
				if q != "" && !strings.Contains(strings.ToLower(summary), q) {
					continue
				}
				item := map[string]any{"intent_id": n.ID, "summary": summary, "state": n.State}
				if n.Inherited {
					inheritedMap(item, n.SourceTaskID)
				}
				out = append(out, item)
				if len(out) >= limit {
					break
				}
			}
			return jsonResult(map[string]any{"works": out})
		})
}

// PlannerTools is the read + intent-generation + goal-judgement tool set.
func (t *ToolSet) PlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		// cold-digest §6.1: restore folded cold nodes (digest body → members → detail).
		t.expandDigest(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.listGoals(), t.addIntent(), t.retireIntent(), t.proveGoal(), t.goalMet(),
		t.killWorkTool(), t.steerWorkTool(),
		// report_finding: during posture judgment, if the planner itself has confirmed a vuln, register it directly (same tool as worker).
		t.addFinding(),
		// list_companies: view the company list + scope + asset counts (get company_id / understand attribution scope).
		t.listCompanies(),
		// list_assets: DSL search across the whole asset store during planning (complements list_untested_assets' 'in-scope untested' view
		// with 'search the whole store by domain/fingerprint/port/status-code etc.').
		t.listAssets(),
		// add_company_scope: add domains/IPs/CIDRs/ICPs/keywords into a company's asset scope during planning (auto-claims matching assets).
		t.addCompanyScope(),
		// add_task_scope: proactively pull a whole root domain/company/specific subdomain/IP into this task's test scope (the coverage denominator).
		t.addTaskScope(),
		// list_untested_assets: query this task's in-scope untested assets on demand (typed + paginated) and decide what to fill.
		t.listUntestedAssets(),
		// search_vulns / get_vuln: after identifying a target component, look up public known vulns (NVD+KEV) —
		// during planning, rank 'directions with ready-made exploits' into the todolist.
		t.searchVulns(), t.getVuln(), t.getPoc(), t.scanWithNuclei(), t.netContext(),
		// listener_*: reverse-connection receivers (red-team C2 front-end) — start/stop go through ask approval, sessions is read-only.
		t.listenerStart(), t.listenerStop(), t.listenerSessions(),
		// auth_request: assemble an authenticated request using credentials registered on the asset (prerequisite for lateral/privesc verification).
		t.authRequest(),
		// diff_responses: compare two responses' structural differences (common base for privesc/enumerable/state-machine classes).
		t.diffResponses(),
		// api_contract: read the API contract files a target exposes — a more precise endpoint list than crawling.
		t.apiContractTool(),
		// search_recent_critical: query recently disclosed critical vulns by [time] (no need to know the component/CVE first).
		t.searchRecentCritical(),
		// evidence_check (v0.4.71): during planning, re-verify whether high/critical vuln evidence supports the impact conclusion.
		t.evidenceCheck(),
	}
}

// stallOverview computes this task's 'marginal returns' posture: which round last produced,
// how many rounds since any new fact/finding (zero output = stop). Reads the activity round/result
// stream, computed in one SQL; per-turn overhead bounded by the exploration graph's EXPLAIN range.
// nil is also meaningful: the task is still young, too early to talk about wrapping up.
func (t *ToolSet) stallOverview() map[string]any {
	rounds, recentNew, openCnt, err := t.ts.StallOverview()
	if err != nil {
		return nil
	}
	out := map[string]any{"planner_rounds": rounds}
	if rounds < 5 {
		// early rounds are still laying groundwork — too early to talk marginal returns
		return out
	}
	out["new_facts_findings_6h"] = recentNew
	out["open_intents_now"] = openCnt
	// hint slot: zero new output + no open → suggest wrapping up
	if recentNew == 0 && openCnt == 0 {
		out["hint"] = "No new fact/finding in the last 6 hours and no open intents — marginal returns may be exhausted. If the goals were genuinely exhausted, " +
			"use goal_met to wrap up (reason stating honestly that marginal returns are exhausted); if untested directions remain, keep dispatching intents."
	}
	return out
}
