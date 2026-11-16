package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/chu0119/pojun/db"
)

// The continuation-depth cap must really take effect on the **write path** — covering generation
// math in unit tests isn't enough; verify addOneIntent rejects over-depth continuations.
//
// Regression background: continuation chains had no gate — production saw a third-generation chain
// (#635 → #578 → #660) where each generation rebuilt context from zero, reread the same files, rescanned the same assets.
func TestAddIntentRejectsContinuationBeyondDepth(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("continuation depth test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)

	// Build a chain: intent1 → intent2 → intent3, each continuing the previous.
	prevID, err := tools.addOneIntent(intentItem{Summary: "generation one: probe a direction"})
	if err != nil {
		t.Fatalf("first generation: %v", err)
	}
	mkID := func(id int64) json.RawMessage {
		b, _ := json.Marshal(id)
		return b
	}
	for gen := 2; gen <= maxContinuationDepth; gen++ {
		next, err := tools.addOneIntent(intentItem{
			Summary:   "continuation gen " + string(rune('0'+gen)),
			Continues: []json.RawMessage{mkID(prevID)},
		})
		if err != nil {
			t.Fatalf("gen %d continuation should be allowed (cap %d): %v", gen, maxContinuationDepth, err)
		}
		prevID = next
	}
	// One more generation exceeds the cap.
	if _, err := tools.addOneIntent(intentItem{
		Summary:   "continuation gen " + string(rune('0'+maxContinuationDepth+1)),
		Continues: []json.RawMessage{mkID(prevID)},
	}); err == nil {
		t.Fatalf("continuation beyond %d generations should be rejected", maxContinuationDepth)
	} else if !strings.Contains(err.Error(), "continuation generation") {
		t.Fatalf("rejection should state the continuation-generation cap: %v", err)
	}
}

// Continuation depth must be **recorded on the node** so the planner can read it (the prerequisite for data-layer accounting).
func TestAddIntentRecordsContinuationDepth(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("continuation depth record", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)

	first, err := tools.addOneIntent(intentItem{Summary: "first probe"})
	if err != nil {
		t.Fatal(err)
	}
	mkID := func(id int64) json.RawMessage {
		b, _ := json.Marshal(id)
		return b
	}
	second, err := tools.addOneIntent(intentItem{
		Summary:   "continuation of first probe",
		Continues: []json.RawMessage{mkID(first)},
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(second)
	if err != nil || node == nil {
		t.Fatalf("failed to get continuation intent: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if got := continuationDepthOf(node); got != 2 {
		t.Fatalf("continuation intent's generation should be 2, got %d", got)
	}
	if payload["continues"] == nil {
		t.Error("continuation intent should record continues")
	}
}

// Oversized intent summaries must be truncated — planner judgment distorts on long summaries
// (long → feels 'almost there' → continue → longer, positive feedback).
func TestAddIntentClampsLongSummary(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("summary truncation", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)

	long := "login-surface probing and default-credential attempts on target host 10.0.0.1, with lots of repeated narration" +
		strings.Repeat("extra detail", 200)
	id, err := tools.addOneIntent(intentItem{Summary: long})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(id)
	if err != nil || node == nil {
		t.Fatalf("failed to get intent: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	got, _ := payload["summary"].(string)
	if utf8.RuneCountInString(got) > maxIntentSummaryRunes+40 {
		t.Fatalf("summary not truncated: %d runes", utf8.RuneCountInString(got))
	}
	if !strings.HasPrefix(got, "login-surface probing and default-credential attempts") {
		t.Errorf("truncation should keep the head: %q", got[:min(40, len(got))])
	}
}

// continues can only point at **intent** nodes — pointing at a fact gets rejected.
func TestAddIntentRejectsContinuesToNonIntent(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("continues validation", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)

	factID, err := store.AddNode(db.KindFact, map[string]any{"summary": "a fact"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(factID)
	if _, err := tools.addOneIntent(intentItem{
		Summary:   "continue a fact (illegal)",
		Continues: []json.RawMessage{b},
	}); err == nil {
		t.Fatal("continues pointing at a fact should be rejected")
	}
}

// continues pointing at a nonexistent id should be rejected (not silently ignored).
func TestAddIntentRejectsUnknownContinues(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("continues unknown", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)

	b, _ := json.Marshal(int64(999999))
	if _, err := tools.addOneIntent(intentItem{
		Summary:   "continue a nonexistent intent",
		Continues: []json.RawMessage{b},
	}); err == nil {
		t.Fatal("continues pointing at a nonexistent node should be rejected")
	}
}
