package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// A tool's JSON Schema must never have an empty required field name.
//
// Pitfall: `obj(props, required...)`'s second arg is the 'required field names' list — passing
// `obj(props, "")` produces `{"required": [""]}` — the model gets required to pass a field whose
// name is the empty string; validation always fails and the tool is dead.
//
// This class of bug only surfaces on a real model run (the model can't pass an empty-named field),
// so we scan every tool's schema here directly.
func TestNoToolHasEmptyRequiredFieldName(t *testing.T) {
	ts := NewToolSet(nil, "")

	check := func(t *testing.T, tl actool.CoreTool) {
		t.Helper()
		schema := tl.InputSchema()
		if schema == nil {
			return
		}
		raw, ok := schema["required"]
		if !ok {
			return
		}
		list, ok := raw.([]string)
		if !ok {
			// required may be []any (assembled from map[string]any) — assert element-wise.
			if anys, ok2 := raw.([]any); ok2 {
				for _, v := range anys {
					if s, ok3 := v.(string); ok3 && s == "" {
					t.Errorf("tool %s's schema has an empty required field name (required=%v) — the model can never supply it",
							tl.Name(), anys)
					}
				}
			}
			return
		}
		for _, r := range list {
			if r == "" {
				t.Errorf("tool %s's schema has an empty required field name (required=%v) — the model can never supply it",
					tl.Name(), list)
			}
		}
	}

	for _, tl := range ts.WorkerTools() {
		check(t, tl)
	}
	for _, tl := range ts.PlannerTools() {
		check(t, tl)
	}
	for _, tl := range ts.MainAgentTools() {
		check(t, tl)
	}
}

// The vuln-intel tools must be bound on all three roles — worker/planner/mainagent:
// workers use them after scanning assets, planners use them ordering todolists, and users
// in the loop ask 'what high-sev dropped recently'.
func TestRecentCriticalToolIsBoundToAllThreeRoles(t *testing.T) {
	ts := NewToolSet(nil, "")
	has := func(tools []actool.CoreTool) bool {
		for _, tl := range tools {
			if tl.Name() == "search_recent_critical" {
				return true
			}
		}
		return false
	}
	if !has(ts.WorkerTools()) {
		t.Error("worker lacks search_recent_critical — can't use 'what high-sev dropped recently' after scanning assets")
	}
	if !has(ts.PlannerTools()) {
		t.Error("planner lacks search_recent_critical — can't schedule 'existing exploit directions' during planning")
	}
	if !has(ts.MainAgentTools()) {
		t.Error("mainagent lacks search_recent_critical — in-loop users can't ask")
	}
}
