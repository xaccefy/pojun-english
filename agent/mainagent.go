package agent

import (
	"context"
	"fmt"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/hosttools"
	"github.com/chu0119/pojun/intercept"
)

// MainAgent is the thin human-interface orchestrator (docs §4.2 / §7). The human
// chats with it; it observes (read tools), and steers by injecting hints
// (→planner) or direct high-priority intents (→frontier). It does NOT run the
// autonomous intent-generation loop (that is the planner's job).
type MainAgent struct {
	findingRecorder FindingRecorder
	// Authorization-boundary guard switch (v0.4.63): read from settings at assembly, passed to ToolSet.
	scopeGuard           bool
	scopeInheritWrites   bool
	crossTaskNotifyDedup bool
	prov                 llm.Provider
	model                string
	tx                   *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window               int                                    // context window in tokens (for compaction)
	windowFn             func() int                             // optional dynamic task-chain minimum
	maxTurns             int                                    // max agent turns per run (0 = unlimited)
	proxyAddr            string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert          string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch            WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir              string                                 // shared work dir (surfaced in prompt as artifact-output target)
	steerWork            func(intentID int64, msg string) error // engine callback: steer a running work (nil = off)
	attributions         func() map[string]any                  // Guard attribution reader (nil = overview omits guard_attributions block)
	nonStreamingFn       func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn         func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn          func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
}

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (m *MainAgent) SetNoaEnabled(fn func() bool) { m.noaEnabledFn = fn }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (m *MainAgent) SetNonStreaming(fn func() bool) { m.nonStreamingFn = fn }

func (m *MainAgent) nonStreaming() bool { return m.nonStreamingFn != nil && m.nonStreamingFn() }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (m *MainAgent) SetMaxTokens(fn func() int) { m.maxTokensFn = fn }

func (m *MainAgent) maxTokens() int {
	if m.maxTokensFn == nil {
		return 0
	}
	return m.maxTokensFn()
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

func (m *MainAgent) SetScopeFlags(scopeGuard, scopeInheritWrites, crossTaskNotifyDedup bool) {
	m.scopeGuard = scopeGuard
	m.scopeInheritWrites = scopeInheritWrites
	m.crossTaskNotifyDedup = crossTaskNotifyDedup
}

func (m *MainAgent) SetCompactionWindowResolver(fn func() int) { m.windowFn = fn }

func (m *MainAgent) compactionWindow() int {
	if m.windowFn != nil {
		return m.windowFn()
	}
	return m.window
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// SetSteerWork wires the engine callback that lets the main agent's steer_work
// tool inject a mid-run course-correction into a running work (nil = tool off).
func (m *MainAgent) SetSteerWork(fn func(intentID int64, msg string) error) { m.steerWork = fn }

// SetAttributions wires the per-task Guard failure-attribution reader so
// graph_overview can carry guard_attributions (humans-in-the-loop see the bounce counts too).
func (m *MainAgent) SetAttributions(fn func() map[string]any) { m.attributions = fn }

// mainAgentDefaultTmpl is the built-in EDITABLE body (section [A]) of the main agent
// prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the artifact
// output-spec tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `You are the 'main agent' of an authorized pentest system — the human operator's interface. You don't explore yourself and don't autonomously generate intent streams (that's the planner's job). Your duties:

**⚠️ Role-boundary hard rules (v0.4.51)**:
- Bash is for [local file operations] ONLY — report editing, image processing, format checks, work-dir management.
- **Never use Bash to interact with the target system** — curl/dig/nmap/nc to the target, any request to it, is overstepping. Those operations get dispatched to workers via add_intent.
- You're the coordinator, not the executor: human says 'test XX' → write it as an add_intent for a worker; human says 'edit the report' → editing report.md via Bash is legitimate.
- Test: if your Bash command contains the target's IP/domain/URL, you're overstepping — it should be an add_intent.

1. Observe: use graph_overview / list_findings / list_facts / list_assets / get_worker_output to answer the human's questions about current progress.
2. Steer (land human intent into the system):
   - Human wants 'change direction/emphasize a vuln class/focus an area' → write a hint via add_hint (the planner reads it next round).
   - Human wants 'test this specific target now' → inject a high-priority intent directly via add_intent (priority 8-10). The system auto-pulls a completed task back to running, lets a worker take the intent, and returns to completed afterward.
     **When all task goals are met** (all goals show met in graph_overview): before dispatching, judge whether this intent implies 'a new result to achieve'. If so, restate the guessed goal to the human in one sentence and **ask whether to register it as a formal goal** — if yes → register via set_goals (the task then enters normal planning and the planner advances autonomously); if no / it's just a quick check → only add_intent this one, and the task returns to completed when the worker finishes (no autonomous continuation). If the intent is clearly a one-off check implying no new goal, just add_intent — no need to ask every time.
   - Human wants 'live-steer a running intent (work): stop going X, focus Y' → use steer_work (no interruption, no lost progress — takes effect before the worker's next action); first check what it's doing via get_worker_output. If the whole direction is wrong, dispatch a new intent via add_intent instead.
   - Human wants 'add a new final goal to achieve' → add goals via set_goals. The system writes the goal into the task graph and **auto-pulls completed/paused tasks back to running** (the planner re-judges attainment accordingly) — no manual resume needed.
   - Human wants 'add/change test constraints (allow/forbid certain operations — e.g. 'only test the current port', 'no brute-forcing', 'passive recon only')' → register via set_constraints (type=allow permits / type=deny forbids). Constraints get injected into planner/worker prompts next planning round to bound exploration; they can also be managed under 'Constraints' in the overview.
3. Reply concisely in plain language, stating what you did.

Current task goal: {{.Goal}}

Don't fabricate findings; answer only from real tool-returned data.`

func mainAgentSystem(goal, dataDir, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	// mainagent also has the Bash tool (base default toolset) and verifies things itself,
	// so the host tool list must be given to it too — or it can only answer from imagination.
	out := body + artifactSpec(workDir) + engagementFraming + impactOrchestrationGuidance + srcTaskBookGuidance
	if t := hosttools.SummaryText(); t != "" {
		out += "\n\n[Tools available on this machine]\n" + t
	}
	return out
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	tsx := NewToolSet(ts, "human")
	tsx.SetFindingRecorder(m.findingRecorder)
	tsx.SetScopeFlags(m.scopeGuard, m.scopeInheritWrites, m.crossTaskNotifyDedup)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.SetNotify(notify)             // generic wake-up (writes without a dedicated callback go here, debounced)
	tsx.SetResumeTask(resume)         // set_goals new goal → pull completed/paused tasks back to running
	tsx.SetNotifyGoal(notifyGoal)     // set_goals new goal → log a 'human added a goal: …' trigger for the planner
	tsx.SetNotifyHint(notifyHint)     // add_hint new hint → log a 'human added N strategy hints: …' trigger for the planner
	tsx.steerWork = m.steerWork       // enable steer_work tool (nil = unavailable)
	tsx.attributions = m.attributions // Guard attribution → overview guard_attributions block (nil = omitted)
	// Domain tools + base default toolset (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	// When asset-coverage is off, remove add_task_scope/list_untested_assets (not shown in prompt).
	base := append(tsx.DropCoverageTools(tsx.MainAgentTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), Kind: KindMain})
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	// This task's work dir <workDir>/tasks/<taskID> — created first.
	mainDir := ensureRunDir(m.workDir, taskID, 0)
	// Shared-dir injection: the main agent needs job/script/PoC-scaffold tools too (same as planner).
	tsx.SetRunDir(mainDir)
	ctx = intercept.WithReviewWorkingDirectory(ctx, mainDir)
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir, mainDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // through the recording proxy for the trail; load the proxy CA so MITM-resigned HTTPS verifies
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is an independent egress proxy (http/https/socks5) — unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:       m.webSearch.Enabled,
		WebSearchBackend:      m.webSearch.Backend,
		BraveSearchAPIKey:     m.webSearch.BraveKey,
		TavilySearchAPIKey:    m.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: m.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  m.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   m.webSearch.DeepSeekModel,
		WebSearchProxy:        m.webSearch.Proxy,
		BashEnv:               proxyEnv(m.proxyAddr, m.proxyCACert), // Bash subprocesses default through proxy + trust CA
		WorkingDir:            mainDir,                              // this task's work dir <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(mainDir),
		MaxTurns:              m.maxTurns,                             // 0 = unlimited (configurable in agent management)
		Compaction:            compactionConfig(m.compactionWindow()), // long chats stay within the window
		Todos:                 actool.NewTodoStore(),                  // session-level scratch todos (TodoWrite), planning-only — dropped on exit
		// On budget hit (steps) → SDK wraps up: outputs a one-line progress summary to the user. Prompt and wrap-up rounds editable in backend (default 10).
		Settlement:   wrapupSettlement("mainagent", nil),
		NonStreaming: m.nonStreaming(), // when this profile picks non-streaming it goes through Provider.Complete
		MaxTokens:    m.maxTokens(),    // 0 = don't send a cap — the server's default decides
		// Tool-call observability: same as planner — mainagent actions were invisible in the journal before.
		Hooks: toolLogSink(KindMain),
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per segment
		opts.Transcript = m.tx
		// Segment 0 keeps the legacy "exp%d-main" name so existing transcripts still
		// load; each new session (seg>=1) gets its own file for a clean context.
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
		if mainSeg > 0 {
			opts.SessionID = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
		}
	}
	// Experimental: when on, noa takes over context compaction (archives persist under <workDir>/noa/<SessionID>).
	// session id follows the same rules as transcripts (segment-aware), so archive & resume align.
	noaSession := fmt.Sprintf("exp%d-main", ts.ID())
	if mainSeg > 0 {
		noaSession = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
	}
	enableNoa(&opts, m.noaEnabledFn, m.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}
