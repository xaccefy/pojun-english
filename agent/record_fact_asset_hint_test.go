package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
)

// When record_fact gets a nonexistent asset id: the fact must still be written AND the model
// must be told that id doesn't exist.
//
// Regression background (2026-10-21 live incident): the model invented an asset id from memory;
// record_fact hit the FK constraint and the whole fact rolled back — planner couldn't see it and
// the same direction got re-probed. The model never learned its id was fake — kept reusing it.
//
// The fix has two layers: db layer skips dangling anchors (saves the fact); tool layer reports the
// invalid ids to the model (so it uses real ids from list_assets).
func TestRecordFactReportsMissingAssetIDs(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("fact-asset-hint", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	exp, err := d.CreateExploration("fact-asset-hint", "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	store := d.Exploration(exp)

	intentID, err := store.AddIntent(map[string]any{"summary": "probe some endpoint"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	assets := d.Assets()
	realID, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: "fact-hint-host.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{realID}) })

	tools := NewToolSet(store, "worker")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(assets, assets.Companies())

	const missingID = int64(987654321)
	input := fmt.Sprintf(`{"summary":"fact referencing a fake asset id","intent_id":%d,"asset_ids":[%d,%d]}`, intentID, realID, missingID)

	tool := tools.recordFact()
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatalf("record_fact must not fail on a missing asset id: %v", err)
	}
	text := res.Flatten()

	// The fact must really land.
	facts, err := store.ListByKind(db.KindFact, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("facts persisted = %d, want 1", len(facts))
	}

	// The real asset's anchor must survive.
	var anchored int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, facts[0].ID, realID).Scan(&anchored); err != nil {
		t.Fatal(err)
	}
	if anchored != 1 {
		t.Errorf("valid asset anchor = %d, want 1", anchored)
	}

	// The fake id must appear in the return — the model needs to know where it erred.
	if !strings.Contains(text, fmt.Sprint(missingID)) {
		t.Errorf("tool result must mention the missing asset id %d; got: %s", missingID, text)
	}
	if !strings.Contains(text, "list_assets") {
		t.Errorf("tool result must point the model at list_assets; got: %s", text)
	}
}

// With all asset ids valid, no extra warning should appear — don't pollute model context.
func TestRecordFactNoWarningWhenAssetsValid(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("fact-asset-ok", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	exp, err := d.CreateExploration("fact-asset-ok", "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, exp) })
	store := d.Exploration(exp)

	assets := d.Assets()
	realID, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: "fact-ok-host.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{realID}) })

	tools := NewToolSet(store, "worker")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(assets, assets.Companies())

	input := fmt.Sprintf(`{"summary":"fact with all-valid anchors","asset_ids":[%d]}`, realID)
	tool := tools.recordFact()
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatalf("record_fact: %v", err)
	}
	text := res.Flatten()
	if strings.Contains(text, "don't exist") {
		t.Errorf("no warning expected when every asset id is valid; got: %s", text)
	}
	if !strings.Contains(text, "fact recorded") {
		t.Errorf("unexpected result shape: %s", text)
	}
}

var _ = actool.CoreTool(nil)
