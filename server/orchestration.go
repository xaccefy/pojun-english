package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// jsonResult marshals v to a JSON tool result.
func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// This file implements the P2 'cross-task orchestration toolset' (docs/race-orchestration §2 P2). These are
// host tools — they need the Manager (any task's Store), the Engine (pause) and the task-create flow, so
// they live in the server layer. Read tools re-route the 'existing per-task tools' onto the target task's
// store (build a temp ToolSet and Call its matching tool), reusing identical logic; control tools
// (spawn/pause) call Manager/Engine directly. They seed into the tools table like traffic tools and bind
// per agent (only visible when bound to the orchestration agent).

// hostTools is the runtime host-tool provider fed to ToolAugment: traffic tools
// (gated by capture) + cross-task orchestration tools + user-defined custom tools.
// The second return is the names of custom tools flagged `deferred` (schema
// withheld, routed via SearchExtraTools/ExecuteExtraTool). Per-agent binding still
// decides who actually sees any of them.
//
//nolint:unused // used as the hostTools provider in wireAgentAugment
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append([]actool.CoreTool{}, s.m.HostTools()...)
	tools = append(tools, s.orchestrationTools()...)
	tools = append(tools, s.findingRetestTools()...)
	tools = append(tools, s.platformTools()...) // platform-op tools (create/edit skill/tool/MCP, for Auto)
	tools = append(tools, s.proxyTools()...)    // proxy pool: status query + bad-egress reporting
	custom, err := s.customTools()
	if err != nil {
		log.Printf("[custom-tool] load failed: %v", err)
		return tools, nil
	}
	tools = append(tools, custom...)
	// deferred custom tools → name -> its bound agent keys. ToolAugment turns a
	// name into a deferred entry only for agents it's actually bound to (so we don't
	// advertise a tool the per-agent binding will drop from the callable set).
	deferred := map[string][]string{}
	rows, _ := s.m.pg.ListCustomTools()
	for _, t := range rows {
		if t.Deferred && t.Enabled {
			deferred[t.Key] = t.Agents
		}
	}
	return tools, deferred
}

// orchestrationTools returns the cross-task tool set. Bound per-agent via the
// tools table (default: no binding — opt-in for orchestration agents).
func (s *Server) orchestrationTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListTasks(),
		s.toolListLLMProfiles(),
		s.toolSpawnTask(),
		s.toolPauseTask(),
		s.toolGetTaskGraph(),
		s.toolListTaskFindings(),
		s.toolAddHint(),
		s.toolGetWorkerTrace(),
		s.toolListWorkerTraces(),
		s.toolSearchWorkerTraces(),
		s.toolGetTaskNodeDetail(),
		s.toolUpdateFindingReport(),
		s.toolGetFindingTraffic(),
		s.toolBindFindingTraffic(),
	}
}

// --- schema helpers ---

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// parseProfileID reads an LLM profile id from a tool arg that may arrive as a JSON
// number (5) or a numeric string ("5"); returns 0 when absent/unparseable.
func parseProfileID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
		return v
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// delegateToTask resolves the `task_id` in the input, builds a ToolSet bound to
// that task's store, strips task_id, and calls the chosen per-task tool — so the
// cross-task read reuses the exact in-task logic against another task.
func (s *Server) delegateToTask(ctx context.Context, in json.RawMessage, pick func(*agent.ToolSet) actool.CoreTool) (actool.Result, error) {
	var head struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(in, &head)
	if strings.TrimSpace(head.TaskID) == "" {
		return actool.Errorf("task_id is required"), nil
	}
	t, ok := s.m.Task(head.TaskID)
	if !ok {
		return actool.Errorf("task does not exist: " + head.TaskID), nil
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(in, &m)
	delete(m, "task_id")
	inner, _ := json.Marshal(m)
	tsx := agent.NewToolSet(t.Store, "orchestrator")
	if s.m.Assets() != nil {
		tsx.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	}
	tsx.SetNotify(t.Notify)         // generic wake (write ops without a dedicated callback use it; read tools no-op)
	tsx.SetNotifyHint(t.NotifyHint) // add_hint → records a "human added N strategy hints: …" trigger and wakes the planner
	return pick(tsx).Call(ctx, inner, nil)
}

// --- tools ---

func (s *Server) toolListTasks() actool.CoreTool {
	return roTool("list_tasks",
		"Lists all tasks (id/desc/goal/status/runtime/parent/LLM profile) — the orchestration agent uses it for the big picture: which tasks stalled, which LLM each uses. Runtime: running = created→now, terminal = created→last-activity (seconds). llm_profile: the task's planner/worker profile name; (active) = follows the global active profile.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			lastAct, _ := s.m.PG().LastActivityAll()
			// id -> name to resolve each task's pinned LLM profile.
			profName := map[int64]string{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profName[p.ID] = p.Name
				}
			}
			out := make([]map[string]any, 0)
			for _, t := range s.m.List() {
				status := s.deriveTaskStatus(t)
				end := lastAct[t.ExpID]
				if live := s.engine.LastActivity(t.ID); live > end {
					end = live
				}
				dur := int64(0)
				if status == "running" {
					dur = time.Now().Unix() - t.CreatedAt
				} else if end > t.CreatedAt {
					dur = end - t.CreatedAt
				}
				row := map[string]any{"id": t.ID, "description": t.Description, "goal": t.Goal, "status": status, "run_seconds": dur}
				if t.ParentRef != "" {
					row["parent_ref"] = t.ParentRef
				}
				llmState := t.llmStateSnapshot()
				if llmState.ProfileID == nil {
					row["llm_profile"] = "(active)"
				} else if n, ok := profName[*llmState.ProfileID]; ok {
					row["llm_profile"] = n
				} else {
					row["llm_profile"] = fmt.Sprintf("#%d(deleted)", *llmState.ProfileID)
				}
				out = append(out, row)
			}
			return jsonResult(out)
		})
}

// toolListLLMProfiles lists the available LLM profiles (name/model/active) so an
// orchestration agent can pick one for spawn_task's llm_profile. Never leaks keys.
func (s *Server) toolListLLMProfiles() actool.CoreTool {
	return roTool("list_llm_profiles",
		"Lists available LLM profiles: id, name, model, format, whether active. Use the id for spawn_task's llm_profile_id to give a sub-task its own LLM (e.g. cheap model for recon, strong for exploitation). API Keys excluded.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profs, err := s.m.pg.ListProfiles()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(profs))
			for _, p := range profs {
				out = append(out, map[string]any{
					"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_active": p.IsDefault,
				})
			}
			return jsonResult(map[string]any{"profiles": out})
		})
}

func (s *Server) toolSpawnTask() actool.CoreTool {
	return wrTool("spawn_task",
		"Creates a sub-task and starts the exploration engine, returning task_id. Used to hand one thing (a problem/a goal) off as an independent task. parent_ref optional: the parent task id for a parent-child link. "+
			"**One task = one goal + its full pentest chain** (asset discovery→service ID→vuln probing→verification→report): all phases of one target belong in one task's goal — "+
			"don't split phases into parallel tasks (they'd re-scan the same assets and the later task starts with zero prior assets). Only multiple independent goals warrant multiple tasks.",
		objSchema(map[string]any{
			"description":            strParam("task description (short title)"),
			"goal":                   strParam("task goal (what to achieve)"),
			"parent_ref":             strParam("optional: parent task id (parent-child link)"),
			"source_task_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": fmt.Sprintf("optional: read-only inherited source task ids (max %d). The sub-task may read-reference those tasks' probed assets/conclusions as a starting point — unlike parent_ref's pure linkage, this is content inheritance.", db.MaxTaskSourceCount)},
			"llm_profile_id":         map[string]any{"type": "integer", "description": "optional: LLM profile id for this sub-task's planner/worker (see list_llm_profiles); empty = inherit parent's, then the global active profile"},
			"timeout_seconds":        map[string]any{"type": "integer", "description": "optional: task-level timeout (seconds). On expiry: graceful wrap-up into the timeout state; empty or 0 = unlimited"},
			"plan_heartbeat_seconds": map[string]any{"type": "integer", "description": "optional: planner heartbeat interval (seconds). This long after the last plan round ended / task started with no trigger → one plan round fires (deadlock backstop + wake to supervise in-flight workers). Empty or 0 = default 600 (10min);"},
			"seed_first_intent":      map[string]any{"type": "boolean", "description": "optional: for simple tasks — dispatch a seed intent (content = desc+goal) on create so workers skip the first planner round; default false (standard plan-then-run)."},
		}, "description", "goal"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Description          string          `json:"description"`
				Goal                 string          `json:"goal"`
				ParentRef            string          `json:"parent_ref"`
				SourceTaskIDs        []string        `json:"source_task_ids"`
				LLMProfileID         json.RawMessage `json:"llm_profile_id"`
				TimeoutSeconds       int             `json:"timeout_seconds"`
				PlanHeartbeatSeconds int             `json:"plan_heartbeat_seconds"`
				SeedFirstIntent      bool            `json:"seed_first_intent"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Description) == "" {
				a.Description = "unnamed task"
			}
			if strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal is required"), nil
			}
			if a.TimeoutSeconds < 0 {
				a.TimeoutSeconds = 0
			}
			// Read-only source-task inheritance: count cap + per-id valid/dedup/exists — same rules as HTTP task create.
			if len(a.SourceTaskIDs) > db.MaxTaskSourceCount {
				return actool.Errorf(fmt.Sprintf("at most %d related tasks allowed", db.MaxTaskSourceCount)), nil
			}
			sourceIDs := make([]int64, 0, len(a.SourceTaskIDs))
			seenSources := map[int64]bool{}
			for _, raw := range a.SourceTaskIDs {
				id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
				if err != nil || id <= 0 || seenSources[id] {
					return actool.Errorf("related task id invalid or duplicated"), nil
				}
				if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
					return actool.Errorf(fmt.Sprintf("related task #%d does not exist", id)), nil
				}
				seenSources[id] = true
				sourceIDs = append(sourceIDs, id)
			}
			// LLM profile resolution: explicit id > inherit parent's pin > active(nil).
			var pin *int64
			if id := parseProfileID(a.LLMProfileID); id > 0 {
				if _, ok := s.loadProfileConfig(id); !ok {
					return actool.Errorf(fmt.Sprintf("LLM profile #%d does not exist or has no API Key set", id)), nil
				}
				pin = &id
			} else if a.ParentRef != "" {
				if pt, ok := s.m.Task(a.ParentRef); ok {
					pin = pt.LLMProfileID
				}
			}
			var llmIDs []int64
			if pin != nil {
				llmIDs = []int64{*pin}
			}
			t, err := s.m.CreateTaskWithOptions(a.Description, a.Goal, db.TaskCreateOptions{
				SourceTaskIDs:        sourceIDs,
				LLMProfileIDs:        llmIDs,
				TimeoutSeconds:       a.TimeoutSeconds,
				PlanHeartbeatSeconds: a.PlanHeartbeatSeconds,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.ParentRef != "" {
				t.ParentRef = a.ParentRef
				if id, e := strconv.ParseInt(t.ID, 10, 64); e == nil {
					_ = s.m.PG().SetParentRef(id, a.ParentRef)
				}
			}
			// Shared post-create flow, reusing the same launchTask as HTTP task create (server.go createTask):
			// seed + background-visible goal decomposition (round-0/LLM step/per-goal) + engine.Run.
			// seed_first_intent defaults false (standard plan-then-run); simple tasks may enable direct work dispatch.
			s.launchTask(t, a.Description+" "+a.Goal, a.SeedFirstIntent)
			return actool.Text(fmt.Sprintf("task created: %s", t.ID)), nil
		})
}

func (s *Server) toolPauseTask() actool.CoreTool {
	return wrTool("pause_task", "pause the given task (stop its planner/worker loops).",
		objSchema(map[string]any{"task_id": strParam("task id to pause")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			t, ok := s.m.Task(a.TaskID)
			if !ok {
				return actool.Errorf("task does not exist: " + a.TaskID), nil
			}
			if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByOrchestrator); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("task paused: " + a.TaskID), nil
		})
}

func (s *Server) toolGetTaskGraph() actool.CoreTool {
	return roTool("get_task_graph", "read the given task's exploration-graph overview (same as graph_overview: asset counts/frontier/findings/coverage etc.), addressed by task_id.",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

func (s *Server) toolListTaskFindings() actool.CoreTool {
	return roTool("list_task_findings", "read the given task's confirmed vulns (incl. flag/PoC; each with id/task_id/intent_id/vulnclass/severity/summary/status), addressed by task_id.",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListFindingsTool)
		})
}

func (s *Server) toolAddHint() actool.CoreTool {
	return wrTool("add_task_hint", "inject a strategy hint into the given task (its planner reads it next round).\n"+
		"★Prefer batch: put multiple hints in the hints array in one call (returns an ids array, same length/order as hints, failed items id=0); for a single hint omit hints and pass top-level text.",
		objSchema(map[string]any{
			"task_id":      strParam("task id"),
			"hints":        map[string]any{"type": "array", "description": "[prefer this] hint array — each element shares the top-level fields (text/asset_ids/traffic_refs).", "items": objSchema(map[string]any{"text": strParam("hint content"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()})},
			"text":         strParam("[single] hint content"),
			"traffic_refs": agent.HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "anchored asset ids (optional, 0/1/many; asset ids inside that task)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
		})
}

func (s *Server) toolGetWorkerTrace() actool.CoreTool {
	return roTool("get_task_worker_trace",
		"view a work (intent)'s execution in the given task: get_task_worker_trace(task_id, intent_id) shows step summaries; then step_ids=[...] fetches those steps' full content (max 5 per call — extras listed under omitted_step_ids).",
		objSchema(map[string]any{
			"task_id":   strParam("task id"),
			"intent_id": map[string]any{"type": "integer", "description": "intent id (the work inside that task)"},
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "optional: step ids to fetch full content for (max 5; extras listed in omitted_step_ids)"},
		}, "task_id", "intent_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GetWorkerTraceTool)
		})
}

func (s *Server) toolListWorkerTraces() actool.CoreTool {
	return roTool("list_task_worker_traces", "list which works (intents) ran in the given task + step counts — for finding works worth opening (then get_task_worker_trace).",
		objSchema(map[string]any{"task_id": strParam("task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListWorkerTracesTool)
		})
}

func (s *Server) toolSearchWorkerTraces() actool.CoreTool {
	return roTool("search_task_worker_traces", "search all works' execution in the given task by keyword (returns matching step summaries + intent_id).",
		objSchema(map[string]any{"task_id": strParam("task id"), "q": strParam("search keyword")}, "task_id", "q"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).SearchWorkerTracesTool)
		})
}

func (s *Server) toolGetTaskNodeDetail() actool.CoreTool {
	return roTool("get_task_node_detail",
		"read a node's full content in the given task's exploration graph (finding/fact/intent/goal: summary + detail/evidence/PoC). id is an exploration-node id (from report_finding's return or list_task_findings). Use it to pull a vuln's full evidence before writing its report.",
		objSchema(map[string]any{
			"task_id": strParam("task id"),
			"id":      map[string]any{"type": "integer", "description": "exploration-node id (not an asset id)"},
		}, "task_id", "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).NodeDetailTool)
		})
}

// toolUpdateFindingReport writes/overwrites a finding's detailed Markdown report.
// finding_id is the id report_finding returned ("finding recorded: <id>", the
// finding node id). The write (SetFindingReportByNodeID) is keyed by node_id and
// task-agnostic, so this host tool needs no task_id / exploration store.
func (s *Server) toolUpdateFindingReport() actool.CoreTool {
	return wrTool("update_finding_report",
		"write/update a registered vuln's [detailed report] (full Markdown, replacing old content). finding_id takes the id report_finding returned (the number in \"finding recorded: <id>\"). Suggested sections: vuln overview, impact & harm, reproduction, evidence/PoC, fix advice.",
		objSchema(map[string]any{
			"finding_id":       map[string]any{"type": "integer", "description": "target vuln id (the id report_finding returned)"},
			"report":           strParam("full detailed report, Markdown"),
			"evidence_version": map[string]any{"type": "integer", "description": "the evidence version get_finding_traffic returned — prevents the report overwriting newer evidence changes"},
		}, "finding_id", "report"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				EvidenceVersion *int64          `json:"evidence_version"`
				FindingID       json.RawMessage `json:"finding_id"`
				Report          string          `json:"report"`
			}
			_ = json.Unmarshal(in, &a)
			nodeID := parseProfileID(a.FindingID) // reuse the 'number or numeric string' parser
			if nodeID <= 0 {
				return actool.Errorf("invalid finding_id"), nil
			}
			n, err := s.m.pg.SetFindingReportVersionByNodeID(ctx, nodeID, a.Report, a.EvidenceVersion)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == 0 {
				return actool.Errorf(fmt.Sprintf("no vuln record for finding_id=%d (register via report_finding first)", nodeID)), nil
			}
			return actool.Text(fmt.Sprintf("finding %d report updated (%d chars)", nodeID, len(a.Report))), nil
		})
}

// deriveTaskStatus mirrors listTasks' status derivation for the list_tasks tool.
func (s *Server) deriveTaskStatus(t *Task) string {
	lifecycle := t.lifecycleSnapshot()
	switch {
	case isTerminalStatus(lifecycle.Status):
		return lifecycle.Status
	case lifecycle.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case s.engine.ReadyFor(t) && s.engine.Started(t.ID):
		return "running"
	}
	return "created"
}

// orchestrationToolSeeds seeds the cross-task tools into the tools table so they
// are bindable per-agent (default: bound to nobody — opt-in for orchestration
// agents). First-insert only, like the traffic seeds.
func (s *Server) seedOrchestrationTools() {
	// task-op + platform tools default-bind to the built-in Auto agent (it exists to operate
	// the platform). SeedTool is first-insert; old-store rows get bound by seedAutoDefaultBindings.
	autoAgents, _ := json.Marshal([]string{"auto"})
	for _, t := range s.orchestrationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings := autoAgents
		if t.Name() == "bind_finding_traffic" {
			bindings = json.RawMessage(`["reporter"]`)
		}
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings)
	}
	for _, t := range s.platformTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	// Proxy-pool tools default-bind worker + planner: executors need to check pool status and report
	// bad egress when 'the target is unreachable'; planners reading posture benefit too.
	proxyAgents, _ := json.Marshal([]string{"worker", "planner"})
	for _, t := range s.proxyTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, proxyAgents)
	}
	s.refreshBuiltinToolSchemas()
	s.seedAutoDefaultBindings()
	s.seedPlannerDefaultBindings()
	s.seedPlannerListAssetsBinding()
	s.seedCompanyScopeRebind()
	s.seedWorkerReadToolsUnbind() // unbind list_facts/list_companies/list_worker_traces from worker by default (one-shot)
	s.seedWorkerReadbackRebind()  // fix an old migration's mis-delete: re-bind search_all_worker_traces/get_worker_trace/node_detail to worker (one-shot)
	s.seedAutoReportFindingBinding()
	s.reseedGoalsPrompt()             // goals prompt gains an 'extract op-constraints' step → append a new default version for old stores (one-shot)
	s.reseedMainAgentPrompt()         // mainagent prompt gains 'post-goal add_intent asks whether to register a goal' (one-shot)
	s.reseedPlannerPrompt()           // planner prompt: rewrite the '0 intents' legit-reason section + add quantitative acceptance checks (one-shot)
	s.reseedWorkerPrompt()            // worker prompt: add the negative-conclusion evidence bar (one-shot)
	s.seedReporterAgent()             // preset 'report writer' agent + tool bindings + finding trigger (one-shot)
	s.upgradeReporterTriggerMessage() // old-store migration: make the reporter pass evidence_version back (one-shot)
	s.seedFindingTrafficTools()       // add optional evidence params and read-only evidence tools, preserving user config
	s.seedFindingWorkflowTools()
	// Note: pentest's default tool bindings need no migration — BuiltinToolSeeds already seeds
	// list_assets/insert_assets/report_finding/list_findings/list_companies alongside pentest on
	// a fresh init (no old store exists, no migration).
}

// refreshBuiltinToolSchemas propagates code schema/description changes on the
// orchestration + platform tools into already-seeded rows ONCE per version flag —
// SeedTool is first-insert-only, so a new param (e.g. spawn_task's llm_profile) never
// reaches an old DB otherwise. Preserves each tool's agent binding + enabled flag.
// Bump the flag whenever these tools' schemas/descriptions change in code.
func (s *Server) refreshBuiltinToolSchemas() {
	const flag = "tool_schema_refresh_v8_spawntask_one_target"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := append(s.orchestrationTools(), s.platformTools()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[tools] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	// Meanwhile refresh some built-in agent tools to code defaults:
	//   - goal_met: old-seeded descriptions said "end this plan round" — misleading; the planner
	//     treated it as "end an empty round" and misjudged the whole task complete right after start.
	//   - insert_assets: new related input (whether the asset relates to the current task — decides
	//     coverage inclusion); SeedTool is first-insert, so old-seeded schemas never get the new param.
	//   - list_facts: switched to pagination with new limit/before/q params; old-seeded empty schemas
	//     would show "no params" in tool management and hide these from the model.
	refreshBuiltin := map[string]bool{"goal_met": true, "insert_assets": true, "list_facts": true}
	for _, sd := range agent.BuiltinToolSeeds() {
		if !refreshBuiltin[sd.Key] {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh %s desc failed: %v", sd.Key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] refreshed orchestration/platform tool schemas to code defaults (one-shot)")
}

// reseedGoalsPrompt refreshes the goals decomposer's prompt to [current code default] — the default
// body gained an 'extract op-constraints (set_constraints) before decomposing goals' step, and
// SeedPromptIfEmpty is first-insert: old stores' version 1 never gets it. Use versioning to [append a
// new version] and switch to it (ResetPromptToDefault); the old version stays in history — a user who
// customized can restore from versions. The settings flag guards → once only; bump the flag when the
// default changes again. Fresh stores need nothing (SeedPromptIfEmpty seeds the latest).
func (s *Server) reseedGoalsPrompt() {
	const flag = "goals_prompt_constraint_step_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // attempt once regardless of outcome
	a, err := s.m.pg.GetAgentByKey("goals")
	if err != nil || a == nil {
		return // fresh stores without agent rows get the latest default seeded by seedPrompts — no migration needed
	}
	tmpl := agent.BuiltinPromptSeeds()["goals"]
	if tmpl == "" {
		return
	}
	// Fresh stores: seedPrompts already seeded the latest default → current version equals code default, no duplicate append.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to reseed goals prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] goals prompt got a new default version (added the op-constraints step, one-shot)")
}

// reseedMainAgentPrompt refreshes the mainagent prompt to [current code default] — the default body
// gained 'after all goals met, when the human direct-dispatches via add_intent, ask whether to register
// it as a formal goal'. SeedPromptIfEmpty is first-insert — old versions never get it. Use versioning to
// [append a new version] and switch (ResetPromptToDefault); old versions stay in history for users who
// customized. Settings flag guards → once only. Fresh stores need nothing (SeedPromptIfEmpty seeds latest).
// Identical in shape to reseedGoalsPrompt.
func (s *Server) reseedMainAgentPrompt() {
	const flag = "mainagent_prompt_goalless_intent_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // attempt once regardless of outcome
	a, err := s.m.pg.GetAgentByKey("mainagent")
	if err != nil || a == nil {
		return // fresh stores without agent rows get the latest default seeded by seedPrompts — no migration needed
	}
	tmpl := agent.BuiltinPromptSeeds()["mainagent"]
	if tmpl == "" {
		return
	}
	// Fresh stores: seedPrompts already seeded the latest default → current version equals code default, no duplicate append.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to reseed mainagent prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] mainagent prompt got a new default version (added post-goal ask-to-register-goal, one-shot)")
}

// reseedPlannerPrompt refreshes the planner prompt to [current code default] — the default body got a
// slimming refactor, demoted 'restraint' to dedup-only, added 'depth over coverage' and the hard floor
// 'goals unmet + nothing running → must produce', and capped negative-conclusion re-checks. Bump the flag
// on every substantive default change (currently v2) so existing stores re-flush. SeedPromptIfEmpty is
// first-insert — old versions never get it; use versioning to [append a new version] and switch
// (ResetPromptToDefault). Old versions stay in history. Settings flag guards → once only. Fresh stores
// need nothing (SeedPromptIfEmpty seeds the latest). Identical in shape to reseedGoalsPrompt.
func (s *Server) reseedPlannerPrompt() {
	const flag = "planner_prompt_compact_realistic_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // attempt once regardless of outcome
	a, err := s.m.pg.GetAgentByKey("planner")
	if err != nil || a == nil {
		return // fresh stores without agent rows get the latest default seeded by seedPrompts — no migration needed
	}
	tmpl := agent.BuiltinPromptSeeds()["planner"]
	if tmpl == "" {
		return
	}
	// Fresh stores: seedPrompts already seeded the latest default → current version equals code default, no duplicate append.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to reseed planner prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] planner prompt got a new default version (slim refactor + restraint→dedup + depth-first + bounded negative re-checks, one-shot)")
}

// reseedWorkerPrompt refreshes the worker prompt to [current code default] — the default body's record_fact
// section dropped the whole 'negative conclusions write observation + tentative reading' sentence, and
// decoupled confidence (observed/inferred) from 'whether this intent exhausted its means' (both misled the
// planner); it also tightened the facts array to the rare 'fully independent, unmergeable' case. Bump flag to
// v3 so existing stores re-flush. SeedPromptIfEmpty is first-insert — old versions never get it; versioning
// appends a new version and switches (ResetPromptToDefault); old versions stay in history. Settings flag
// guards → once only. Fresh stores need nothing. Identical in shape to reseedGoalsPrompt.
func (s *Server) reseedWorkerPrompt() {
	const flag = "worker_prompt_compact_v4"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // attempt once regardless of outcome
	a, err := s.m.pg.GetAgentByKey("worker")
	if err != nil || a == nil {
		return // fresh stores without agent rows get the latest default seeded by seedPrompts — no migration needed
	}
	tmpl := agent.BuiltinPromptSeeds()["worker"]
	if tmpl == "" {
		return
	}
	// Fresh stores: seedPrompts already seeded the latest default → current version equals code default, no duplicate append.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to reseed worker prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] worker prompt got a new default version (context-check section narrowed to list_assets/list_findings, dropped list_facts/node_detail/asset_neighbors, one-shot)")
}

// reporterToolCallMessage must unconditionally require one get_finding_traffic read before writing the
// report. That tool is read-only and 'independent of the capture toggle' — auto-bind on or off, it can read
// human-bound evidence. Writing 'read only when auto-bind enabled' here would mean the reporter never passes
// evidence_version under the default-off config, SetFindingReportVersionByNodeID writes -1 legacy-style, and
// vuln detail + Markdown export stay permanently marked 'evidence changed, report pending update' with no UI
// to clear it.
const reporterToolCallMessage = "A vuln was just registered via report_finding. Read the returned JSON's finding_id (standalone vuln record ID) and finding_node_id (exploration node ID); " +
	"first call get_finding_traffic(finding_id) to read the current evidence list and its version (an empty list is normal — write the report anyway); " +
	"if the run guide enables auto-binding, verify and bind this vuln's traffic BEFORE reading. Node detail uses finding_node_id. " +
	"Finally call update_finding_report(finding_id=finding_node_id, report, evidence_version=the version actually read) to save — " +
	"evidence_version is required, else the report is permanently marked stale. Don't mix the two ID kinds."

// Legacy trigger message (0.3.8 and earlier). Only records still verbatim-identical to it get migrated — user-edited ones stay.
const reporterToolCallMessageV1 = "A vuln was just registered via report_finding. Take the finding_id " +
	"(the number in the tool's \"finding recorded: <id>\") and the task id from the trigger context, write the vuln's detailed report per your role, " +
	"then call update_finding_report(finding_id, report) to save."

// upgradeReporterTriggerMessage refreshes still-default reporter trigger messages in old stores to the new
// version. seedReporterAgent is guarded by reporter_agent_seed_v1 and only writes the trigger on agent
// creation — upgraded stores never get the new text: the tool schema gained evidence_version via
// seedFindingTrafficTools but nothing tells the reporter to use it. One-shot, overwriting only untouched text.
func (s *Server) upgradeReporterTriggerMessage() {
	const flag = "reporter_trigger_evidence_version_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // attempt once only
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] failed to read triggers: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || t.ToolCallMessage != reporterToolCallMessageV1 {
			continue // user-edited or not a finding trigger — leave alone.
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] trigger message upgrade failed: %v", err)
			return
		}
		log.Printf("[reporter] trigger message upgraded to read and pass evidence_version")
	}
}

// seedReporterAgent presets a 'report writer' custom agent (builtin=false — UI-editable/deletable):
// binds update_finding_report + task-query tools, and hangs a 'fires on report_finding call' trigger —
// every registered vuln invokes it to write the detailed report. One-shot (settings-flag-guarded): not
// recreated after the user deletes it. Dependency: orchestration tools were SeedTool'd above, so binding works.
//
// The flag guard isn't 'once done, never care': when the agent exists but its trigger/tool bindings are
// missing (mis-delete, DB migration, post-purge restore), the missing part **must be backfilled** — else
// registered vulns never trigger the report agent and traffic evidence goes unchecked. Existing parts are
// NOT overwritten — user edits stay.
func (s *Server) seedReporterAgent() {
	const flag = "reporter_agent_seed_v1"
	seeded := false
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		seeded = true
	}
	if !seeded {
		defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // attempt once regardless of outcome
	}

	exist, _ := s.m.pg.GetAgentByKey("reporter")
	if exist != nil {
		// agent already exists (builtin or user-made) — only backfill missing triggers/bindings, never overwrite.
		s.repairReporterAgent(exist)
		return // key already taken (user-created) — don't overwrite
	}
	a, err := s.m.pg.CreateAgent("reporter", "report writer",
		"vuln detailed-report writing: auto-triggers on vuln discovery, reads evidence and execution, writes the Markdown report back.")
	if err != nil {
		log.Printf("[reporter] failed to create agent: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.ReporterDefaultPrompt); err != nil {
		log.Printf("[reporter] seed prompt failed: %v", err)
	}
	// Trigger run policy: parallel + none — one vuln one report; concurrent findings each write their own.
	// merge must be none: otherwise (default all) a wave of findings merges into one run and parallel is moot.
	// maxParallel=5: at most 5 report sessions at once — bounds burst LLM calls.
	if err := s.m.pg.SetAgentTriggerBehavior("reporter", "parallel", "none", 5); err != nil {
		log.Printf("[reporter] failed to set trigger run policy: %v", err)
	}
	// Bind the tools it needs: write report + read evidence/execution/posture.
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_task_node_detail", "list_task_findings",
		"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
		"get_task_graph",
	}); err != nil {
		log.Printf("[reporter] tool binding failed: %v", err)
	}
	// Trigger: fires on report_finding calls (the tool returns "finding recorded: <id>" carrying finding_id,
	// and the task id is in the trigger message).
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:        "reporter",
		Enabled:         true,
		OnToolCall:      true,
		ToolNames:       []string{"report_finding"},
		ToolCallMessage: reporterToolCallMessage,
	}); err != nil {
		log.Printf("[reporter] failed to create trigger: %v", err)
	}
	log.Printf("[reporter] preset 'report writer' agent + finding trigger done")
}

// repairReporterAgent backfills the reporter's missing report_finding trigger and tool bindings.
// Existing parts are left alone — the user may have edited the tool list or trigger message.
func (s *Server) repairReporterAgent(a *db.Agent) {
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] failed to read triggers: %v", err)
		return
	}
	hasFindingTrigger := false
	for _, t := range triggers {
		if t.OnToolCall && containsString(t.ToolNames, "report_finding") {
			hasFindingTrigger = true
			break
		}
	}
	if !hasFindingTrigger {
		if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
			AgentKey:        "reporter",
			Enabled:         true,
			OnToolCall:      true,
			ToolNames:       []string{"report_finding"},
			ToolCallMessage: reporterToolCallMessage,
		}); err != nil {
			log.Printf("[reporter] failed to backfill report_finding trigger: %v", err)
		} else {
			log.Printf("[reporter] backfilled the missing report_finding trigger")
		}
	}
	// Same for tool bindings: backfill only the missing; bound ones stay.
	for _, key := range []string{
		"update_finding_report", "get_task_node_detail", "list_task_findings",
		"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
		"get_task_graph",
	} {
		if err := s.m.pg.AddAgentToToolBinding("reporter", []string{key}); err != nil {
			log.Printf("[reporter] failed to bind tool %s: %v", key, err)
		}
	}
	_ = a
}

// containsString reports whether list contains s.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// seedAutoReportFindingBinding adds "auto" to report_finding's binding ONCE so
// conversation-context agents can call it without requiring an intent_id.
func (s *Server) seedAutoReportFindingBinding() {
	const flag = "auto_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("auto", []string{"report_finding"}); err != nil {
		log.Printf("[auto] report_finding default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerDefaultBindings adds "planner" to report_finding's binding ONCE
// (guarded by a settings flag), so existing DBs — whose report_finding row was
// seeded as worker-only — also let the planner record findings. Fresh DBs already
// get it via PlannerTools(); this only backfills without overriding a user unbind.
func (s *Server) seedPlannerDefaultBindings() {
	const flag = "planner_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"report_finding"}); err != nil {
		log.Printf("[planner] report_finding default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerListAssetsBinding adds "planner" to list_assets's binding ONCE
// (guarded by a settings flag), so existing DBs — whose list_assets row was seeded
// as auto/pentest-only — also let the planner query the asset store by DSL. Fresh
// DBs already get it via PlannerTools(); this only backfills without overriding a
// user unbind.
func (s *Server) seedPlannerListAssetsBinding() {
	const flag = "planner_list_assets_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"list_assets"}); err != nil {
		log.Printf("[planner] list_assets default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCompanyScopeRebind changes add_company_scope's default binding ONCE on
// existing DBs (guarded by a settings flag): the tool moves off worker and onto
// planner — defining a company's asset scope is a planning/main/auto concern, not
// something a worker does mid-exploration. Fresh DBs already get planner via
// PlannerTools() and lack worker via WorkerTools(); this only backfills old rows.
// One-shot + flag-guarded so a user who later re-binds worker isn't overridden.
func (s *Server) seedCompanyScopeRebind() {
	const flag = "company_scope_rebind_v1" // worker→planner default-binding switch
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"add_company_scope"}); err != nil {
		log.Printf("[planner] add_company_scope default binding failed: %v", err)
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("worker", "add_company_scope"); err != nil {
		log.Printf("[worker] add_company_scope unbind failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadToolsUnbind strips the read-context tools off worker's default
// binding ONCE on existing DBs (guarded by a settings flag): a worker executes one
// intent and writes back — reading facts/companies and listing all workers' traces is
// a planning/main concern, not the executor's. Fresh DBs already lack these via
// WorkerTools(); this only backfills old rows without overriding a user who
// deliberately re-binds worker. Each RemoveAgentFromTool is per-tool +
// membership-guarded, so planner/mainagent bindings of the same tool are untouched.
//
// NOTE: search_all_worker_traces / get_worker_trace / node_detail are intentionally NOT
// unbound — worker owns them for cross-work look-back + node drill-down (see WorkerTools).
// They used to be in this list back when worker lacked them; seedWorkerReadbackRebind
// repairs DBs whose old run stripped them.
func (s *Server) seedWorkerReadToolsUnbind() {
	const flag = "worker_readtools_unbind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, k := range []string{
		"list_facts", "list_companies", "list_worker_traces",
	} {
		if err := s.m.pg.RemoveAgentFromTool("worker", k); err != nil {
			log.Printf("[worker] failed to unbind %s from worker: %v", k, err)
			return // on error don't set the flag — retry next start
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadbackRebind re-binds the cross-work look-back / drill-down tools onto
// worker ONCE (guarded by a settings flag): an earlier seedWorkerReadToolsUnbind wrongly
// stripped search_all_worker_traces / get_worker_trace / node_detail from worker after
// they had been added to WorkerTools(), so any DB that ran that migration lost them.
// Fresh DBs already have them via WorkerTools() and this is a harmless no-op there.
// One-shot + flag-guarded so a user who later deliberately unbinds them isn't overridden.
func (s *Server) seedWorkerReadbackRebind() {
	const flag = "worker_readback_rebind_v2" // v2: also adds node_detail
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{
		"search_all_worker_traces", "get_worker_trace", "node_detail",
	}); err != nil {
		log.Printf("[worker] read-back/detail tools rebind failed: %v", err)
		return // on error don't set the flag — retry next start
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedAutoDefaultBindings adds "auto" to the task-op + platform tools' bindings
// ONCE (guarded by a settings flag), so existing DBs whose tool rows were seeded
// before Auto existed still give Auto its default toolset — without re-adding it
// after a user deliberately unbinds.
func (s *Server) seedAutoDefaultBindings() {
	const flag = "auto_default_bindings_v3" // v3: replace legacy asset-tool names, add insert_assets/add_company_scope
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(platformToolKeys)+12)
	for _, t := range s.orchestrationTools() {
		keys = append(keys, t.Name())
	}
	keys = append(keys, platformToolKeys...)
	// asset tools: operating the platform, Auto often views/registers assets and manages company scope.
	keys = append(keys, "insert_assets", "add_company_scope", "list_assets")
	if err := s.m.pg.AddAgentToToolBinding("auto", keys); err != nil {
		log.Printf("[auto] default binding failed: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
	// goal_met default-binds planner (finish gate landed; instances that never bound get it added — those
	// manually unbound get it back — acceptable: this setting's named v4 marks the change, same semantics as auto's v3).
	const goalFlag = "goal_met_planner_binding_v1"
	if v, _, _ := s.m.pg.GetSetting(goalFlag); v != "true" {
		if err := s.m.pg.AddAgentToToolBinding("planner", []string{"goal_met"}); err != nil {
			log.Printf("[toolcatalog] goal_met bind-to-planner failed: %v", err)
		} else {
			_ = s.m.pg.SetSetting(goalFlag, "true")
			log.Printf("[toolcatalog] goal_met now default-binds planner (finish gate)")
		}
	}
}
