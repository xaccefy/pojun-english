package agent

import (
	"encoding/json"
	"fmt"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
)

const findingIDGuidance = "\n\n**Vuln ID conventions**: finding_id is the standalone vuln-record ID; finding_node_id is the exploration-node ID. The `id` fields of list_findings / list_task_findings / node_detail / get_task_node_detail stay exploration-node IDs — read the standalone number from the `finding_id` in the same return. get_finding_traffic / bind_finding_traffic use the standalone finding_id. The legacy update_finding_report's `finding_id` param still takes finding_node_id. Don't feed report_finding's first-line number into evidence tools, and don't guess other numbers after an ID error."

// evidenceDisciplineGuidance: evidence grading and reporting bar (borrowing Shannon's L1–L4 evidence
// ladder and the 'security mechanism vs external constraint' test question, v0.4.5). Lives in tool guidance,
// not the DB prompt: takes effect on upgrade without overwriting user-edited agent prompts.
const evidenceDisciplineGuidance = `

**Evidence grading & reporting bar (self-check BEFORE report_finding)**:
- Four levels: L1 the endpoint responds, params reach the backend; L2 input provably affects backend logic (quote closes, conditional diffs, error diffs); L3 real impact achieved (data exfil, reading others' data cross-privilege, command echo, auth bypass); L4 critical impact (full dataset, system takeover).
- **Only L3 permits critical / high**; L2 reports at most medium with exploitation conditions written in evidence; L1 reports no vuln — park it in TodoWrite as a doubt.
- When blocked, first ask: **is the blocker a 'security mechanism' (input validation, permission checks, framework/ORM guards, parameterized queries), or an 'external operational constraint' (gateway, WAF, IP allowlist, component not deployed, network isolation)?** Security-mechanism block = not a vuln (at most a hardening suggestion), don't report; external-constraint block = may report, but evidence must state that prerequisite and severity is judged by 'what you'd actually get bypassing the constraint' — noted accordingly.
- Observation ≠ inference: evidence holds only the request/response text and command output you **actually saw**; conclusions 'inferred from responses' go in summary/analysis — not evidence.
- Severity self-check: before assigning critical / high ask 'who ultimately suffers, and what did the attacker get that they shouldn't have?' If the reasoning mentions 'needs admin cooperation / limited impact / was already visible', it's not high-sev — **your reasoning can't contradict your rating**. critical is reserved for: no privileges or zero prerequisites, directly obtaining sensitive data or executing commands.`

// reporterEvidenceAnnex: report-structure supplement (injected on reporter only, since v0.4.5).
const reporterEvidenceAnnex = `

**Report-structure supplement**:
- After 'Reproduction Steps' add ` + "`## Prerequisites`" + `: accounts/permissions/network position/special config needed to reproduce; write 'none' if truly none.
- Add ` + "`## Impact Proof`" + `: a numbered list of 'verifiable impacts actually achieved' (e.g. read 2,731 user records incl. ID numbers, took over an admin session), each tied to its evidence source; grounds the severity — no speculation.
- ` + "`## Evidence`" + ` holds only verbatim material seen (requests/responses/command output); inferences go to ` + "`## Root Cause Analysis`" + ` — never mixed into evidence.
- Section titles state only 'what the flaw is, where' — **never the consequence**, no 'possibly exists / suspected / theoretically' wording.
- When some verifications couldn't run due to environment limits (no intranet, no account, unreachable component), append ` + "`## Unverified Scope`" + ` at the end stating it honestly; unverifiable parts must not be written as confirmed.
- When registered severity disagrees with your judgment, write 'recommended review to X level' under 'Impact and Harm' with reasoning — **never rewrite the registered value yourself**.
- On-site screenshots: first check this task's evidence attachments via ` + "`list_artifacts`" + ` (reporter has no task context — calls **must carry the current finding_id**, e.g. ` + "`list_artifacts {\"finding_id\": 123}`" + `; the tool reverse-looks-up the owning task); embed images related to this vuln (matching finding_id) into the 'Evidence' section via ` + "`![specific caption](artifact:<id>)`" + `. Captions state 'which system, which page, what it proves'; don't cite unrelated images and don't fabricate when none exist.
- **Bucket / file-read / upload-class vulns must have images**: if attachments contain file samples downloaded from the bucket/endpoint (especially photos), the 'Evidence' section must embed them (montage or single); captions state bucket/path, sample count and filenames (per montage watermarks). With only text and no sample images, honestly state 'no file-sample evidence retained' under 'Unverified Scope' — never write 'readable/accessible' as 'data obtained'.
- **SQL injection must have a 'Re-test Commands' section**: give the complete sqlmap command the worker actually ran this time (code block, with --batch --flush-session, real URL/params/--data/--cookie), noting expected output (Parameter/Type/DBMS). Commands come only from evidence or execution records — never invented; when the worker didn't run sqlmap, state 'no sqlmap re-test command obtained' — don't fabricate.`

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		// Evidence discipline is independent of the traffic-binding switch: with auto-binding off the reporter still passes the evidence bar.
		return out, evidenceGuidanceFor(agentKey, out)
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nBy default the report Agent checks and binds traffic before writing the report. The reporter keeps verification commands, key outputs and any real traffic IDs with their purposes in evidence for the report Agent to cross-check against execution records; no extra packet digging needed for binding. Explicit immediate binding stays compatible: traffic_refs or evidence_hint_id can submit verified references — the latter reads this task's specified hint's structured references. If a referenced traffic ID doesn't exist, the report still succeeds (the vuln isn't lost); non-applied IDs are listed in the return's skipped_traffic_refs — verify real IDs via traffic_get then bind with bind_finding_traffic. TCP/no-packet cases don't need these optional params. finding_id and finding_node_id in the return denote the standalone record and the exploration node."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing off a confirmed vuln, keep the verified traffic IDs, roles, notes and order in the corresponding hint's traffic_refs (single at top level, batch inside the corresponding hints element), and state in text which vuln it proves. Callers can't hand off text while dropping existing traffic references. Unverified candidates can't be passed as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic-evidence handoff (optional)**: auto-binding is done by default by the report Agent after the vuln is stored, before report writing. Reporters should keep verification commands, key outputs, existing real traffic IDs and their purposes in evidence, with intent_id, so the report Agent can trace; no extra packet digging just for binding. When Auto/Planner reports on someone's behalf, don't drop the executor's existing references. add_hint / add_task_hint can hand off via traffic_refs; explicit immediate binding stays compatible via report_finding's traffic_refs / evidence_hint_id. TCP or no-packet cases register normally — never guess IDs and don't re-probe just to fill bindings."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWithout task context, platform conversations don't call report_finding directly; hand off via add_task_hint to the corresponding task — its task Agent registers it — and verify via list_task_findings."
		}
		if has["prove_goal"] || has["goal_met"] {
		guidance += "\nBefore judging the goal complete, finish reporting/handing-off existing evidence. Don't end the task or cancel a Worker just because a text vuln is registered while the evidence handoff is unfinished; no-packet cases don't require waiting or forcing captures."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Auto-link traffic before reporting (enabled)**: you're responsible for checking and binding traffic for this trigger's vuln, then writing the report. First get the explicit finding_id and finding_node_id from report_finding's return JSON or get_task_node_detail / list_task_findings. Read the vuln detail, the corresponding intent's execution record and existing evidence list — prefer the real IDs the reporter handed off. If this verification was HTTP and traffic tools are available, filter candidates via traffic_search, then verify each with traffic_get that its request/response actually supports the vuln; domains and times are only filters — not proof of attribution. Bind confirmed evidence in reproduction order via bind_finding_traffic(finding_id, traffic_refs), choosing baseline / proof / verification / supporting with purpose notes. Operate only on this vuln — don't create duplicates or re-probe the target. After binding, call get_finding_traffic again for the latest version, read the needed content, then pass the version actually read as evidence_version to update_finding_report (whose finding_id param still takes finding_node_id). Existing bindings don't need re-adding. For TCP, uncollected, unavailable tools or no exact match — skip auto-binding, write the report on text/command evidence and note why; don't guess to fill traffic. On binding failure don't claim success; keep existing evidence and state the unbound reason in the report."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance + evidenceGuidanceFor(agentKey, out)
}

// evidenceGuidanceFor assembles evidence discipline (for reporters) and report-structure supplement
// (for reporter) per the agent's actually-visible toolset. Separate function so the 'auto traffic-binding
// off' branch still carries the discipline section.
func evidenceGuidanceFor(agentKey string, tools []actool.CoreTool) string {
	has := map[string]bool{}
	for _, t := range tools {
		has[t.Name()] = true
	}
	var g string
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		g += evidenceDisciplineGuidance
	}
	// The reporter's report-structure supplement is injected only when it truly has the report-writing tool:
	// assemblies without update_finding_report (e.g. test scenarios with auto-binding off) get none —
	// keeping the 'no report tool → no report guidance' contract.
	if agentKey == "reporter" && has["update_finding_report"] {
		g += reporterEvidenceAnnex
	}
	return g
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "optional: verified traffic references matching concrete vulns in this hint, order preserved; after handoff, report_finding can carry them via evidence_hint_id.", "items": obj(map[string]any{"traffic_id": str("real traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("which conclusion this traffic supports")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must be a hint node of this task (inherited hints can't be bound directly)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
