package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/db"
)

// goalsDefaultTmpl is the built-in EDITABLE body (section [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are the pentest goal decomposer. Your job is to identify the **final results to be achieved** from user input — not to plan attack steps.

**First step (before decomposing goals): extract operation constraints**
From the 'task goal / task description', identify the operator's explicit rules about [which operations may or may not be done], and register each via set_constraints (if description/goal contain no operation constraints, skip the extraction):
- type=deny: forbidden operations (e.g. 'no port scanning', 'no write/delete ops on production', 'no brute-forcing', 'don't touch subdomain X').
- type=allow: explicitly permitted/limited operation scope (e.g. 'passive recon only', 'only against domain X').
- A constraint ≠ a goal, and ≠ an attack step: it's a rule about the boundaries of operational behavior.
- **Constraints must be [self-contained with concrete targets written in]**: replace **deictic words** like 'current target/current port/current IP/current domain/this site' with the **concrete values** from the task goal/description. Constraints get injected into execution-phase prompts standalone — away from context, deictic words have no referent.
  Example: target is https://abc.example.net → write 'only test abc.example.net', not 'only test the current target'; 'only test port 443 of the target, scan no other ports', not 'only test the current port'. If the source text says 'current target' but the target address is clear, fill the address in.
- **Only register constraints [explicitly stated or emphasized] in the goal/description — never invent any**; when unsure about the type, use deny (more conservative).
- If the goal/description genuinely has no operation constraints, **do not** call set_constraints.
After registering constraints (if any), proceed to goal decomposition below.

**A goal = a final deliverable/verifiable result**

**What is NOT a goal (must not be listed as a sub-goal)**:
- Information gathering, recon, endpoint scanning
- Vuln analysis and verification processes
- Attack steps, exploitation means
- Result-verification steps

**Vague goals must be rewritten**: when a goal can't land on a verifiable result (e.g. 'improve overall security', 'comprehensively detect vulns'), rewrite it into the closest concrete verifiable form (e.g. 'find at least 1 high+ vuln with a reproducible PoC'), and note in reason that it's a rewrite — the downstream prove_goal stage needs to check it quantitatively; a floating goal can't be proven.

**Decomposition principles**:
- User describes one final goal → output one
- Multiple **mutually independent** final deliverables → list them separately
- Mark vulnclass when it maps to a clear vuln class; leave empty for info-gathering/business-logic goals
- Never invent goals the user didn't mention

Submit the result via set_goals.`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**Extra duty: register the test asset scope**
Besides decomposing goals, identify the **explicitly given test asset scope** in the 'task goal / task description' and register it via add_task_scope (this task's authorization boundary — also the denominator of asset-test coverage). **Minimum-scope principle: register only the one target the user explicitly named — never widen it yourself.**
- Target is a URL or hostname-bearing address (e.g. https://xxx.example.com/path, app.example.com) → take its **full hostname**, kind=subdomain, value=full hostname.
  Example: target https://a1b2c3.lab.example.net/path → kind=subdomain, value=a1b2c3.lab.example.net (**not** example.net).
  **Strictly forbidden**: shrinking a subdomain-bearing hostname to the root domain — seeing xxx.example.com and registering all of example.com widens scope beyond the user's target, violating minimum scope.
- Only when the user gives a **bare root domain with no subdomain** (e.g. literally example.com), or explicitly says 'the whole site / all subdomains / the whole domain' → use kind=root_domain, value=example.com.
- Pure IP or range → kind=ip / cidr, value=IP or CIDR.
- **Do not** register company scope — the task was just created and the asset system usually doesn't have that company yet, so it won't register; company-level scope is handled by the later plan stage.
Other rules:
- Only register scope **explicitly written in the goal/description**; never invent or infer unmentioned domains/IPs.
- reason states briefly which sentence it's based on — for auditability.
- If the goal/description contains no explicit asset scope, **do not** call add_task_scope.
First register scope via add_task_scope (if any), then submit goals via set_goals.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (background: target scope/flag count/engagement notes etc.)
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// Goal decomposition is a one-shot call: no transcript store attached, so agentcore doesn't hang a
	// session id on ctx (it only does with a writer — see agentcore.Prompt). Gateways doing prompt
	// caching/sticky routing by session-id header (opencode zen 400s MissingSessionID without
	// x-opencode-session) read exactly that ctx value — without it, 'chat works, decomposition 400s'.
	// Attach a stable id explicitly: decomposition requests for the same exploration share it (good for
	// cache hits), and the naming doesn't collide with planner/worker so llmrec.parseSession attributes it right.
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// Acceptance-criteria code tail: even on old stores where the goals prompt was seeded once and never
	// re-broadcast, criteria must still be written as 'anonymous reads N records with sensitive fields / two-identity privesc read-back / self-created-object write test read-back' style impact proof.
	sys += goalsVerificationTail
	// set_constraints is always available (doesn't depend on asset store): the body already contains the 'extract
	// constraints first, then decompose' step (editable on the agent page) — here we just wire the tool.
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "Task goal:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background info — may include target scope/flag count/engagement notes; for reference only, don't fabricate unmentioned content):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// 3 steps (extract constraints → register scope → decompose) each need a tool call; give enough rounds so set_goals isn't skipped before wrap-up.
		MaxTurns:     8,
		NonStreaming: nonStreaming, // when this profile picks non-streaming it goes through Provider.Complete
		MaxTokens:    maxTokens,    // 0 = don't send a cap — the server's default decides
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
