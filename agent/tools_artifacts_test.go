package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
)

// TestListArtifactsResolvesTaskFromFinding v0.4.20: the reporter has no task context —
// list_artifacts must resolve the task via finding_id, else it always returns empty.
func TestListArtifactsResolvesTaskFromFinding(t *testing.T) {
	oldList, oldFind := ListTaskArtifacts, FindingTaskID
	defer func() { ListTaskArtifacts, FindingTaskID = oldList, oldFind }()

	var gotTask string
	ListTaskArtifacts = func(taskID string) ([]db.TaskArtifact, error) {
		gotTask = taskID
		return []db.TaskArtifact{{ID: 9, TaskID: taskID, Name: "proof.png", Kind: "image"}}, nil
	}
	FindingTaskID = func(findingID int64) (string, error) {
		if findingID != 42 {
			t.Fatalf("findingID=%d want 42", findingID)
		}
		return "7", nil
	}

	ts := NewToolSet(nil, "reporter") // deliberately no SetTaskID: simulates the reporter's chat toolset
	tool := ts.listArtifacts()
	in, _ := json.Marshal(map[string]any{"finding_id": 42})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if gotTask != "7" {
		t.Fatalf("taskID=%q want 7", gotTask)
	}
	if !strings.Contains(toolResultText(t, res), "proof.png") {
		t.Fatalf("result missing artifact: %s", toolResultText(t, res))
	}
}

// TestListArtifactsWithoutContextStaysEmpty: with neither taskID nor finding_id it must not
// mis-query other tasks (return empty rather than error).
func TestListArtifactsWithoutContextStaysEmpty(t *testing.T) {
	oldList := ListTaskArtifacts
	defer func() { ListTaskArtifacts = oldList }()
	ListTaskArtifacts = func(taskID string) ([]db.TaskArtifact, error) {
		t.Fatalf("must not query without task context, got %q", taskID)
		return nil, nil
	}
	ts := NewToolSet(nil, "reporter")
	tool := ts.listArtifacts()
	res, err := tool.Call(context.Background(), []byte(`{}`), nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if strings.TrimSpace(toolResultText(t, res)) != "[]" {
		t.Fatalf("want [], got %s", toolResultText(t, res))
	}
}
