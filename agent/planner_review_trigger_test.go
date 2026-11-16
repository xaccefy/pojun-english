package agent

import (
	"strings"
	"testing"
)

// B2: a zero-write-back exhausted intent must surface as a "review" trigger that
// spells out the postmortem instruction + the last step summaries, so the planner
// folds the attempt into a fact instead of letting it vanish.
func TestRenderTriggersReviewCarriesPostmortem(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("review-trigger test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)

	intentID, err := tools.addOneIntent(intentItem{Summary: "probe /api/import's fastjson entry"})
	if err != nil {
		t.Fatal(err)
	}

	got := renderTriggers(store, []TriggerEvent{{
		Kind:     "review",
		IntentID: intentID,
		Detail:   "curl -s http://t/api/import returned 403; POST still 403",
	}})
	for _, want := range []string{
		"wrote nothing back",
		"curl -s http://t/api/import returned 403",
		"hypothesis",
		"probe /api/import's fastjson entry",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("review trigger missing %q in:\n%s", want, got)
		}
	}

	// With a missing summary, still give a proactive re-review fallback path (never hand the instruction back empty).
	got = renderTriggers(store, []TriggerEvent{{Kind: "review", IntentID: intentID}})
	if !strings.Contains(got, "get_worker_trace") {
		t.Errorf("empty-detail review should point at get_worker_trace, got:\n%s", got)
	}
}
