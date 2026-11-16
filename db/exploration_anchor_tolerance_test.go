package db

import (
	"testing"
)

// When an anchor references a nonexistent asset, the node itself must still be written.
//
// Regression background (2026-10-21 production incident): a worker called record_fact to
// write back an exploration fact, and asset_ids contained a nonexistent asset id (one the
// model made up from memory, or an asset that had been deleted). Since
// exploration_anchors.asset_id is FK REFERENCES assets(id), the INSERT reported
//
//	ERROR: insert or update on table "exploration_anchors" violates foreign key
//	       constraint "exploration_anchors_asset_id_fkey" (SQLSTATE 23503)
//
// And AddNode puts the node INSERT and the anchor INSERT in the **same transaction** — once
// the anchor failed, the whole transaction rolled back, and **the fact node disappeared
// along with the conclusion the model had worked hard to discover**. The planner never saw
// the fact, so the same direction got probed again — pure wasted effort.
//
// Correct semantics: an anchor is an "optional provenance edge", not the carrier of the fact.
// If the asset an anchor points to is gone, what is lost is the edge, not the fact.
func TestAddNodeSkipsMissingAssetAnchors(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "anchor tolerance")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	// One genuinely existing asset + one definitely nonexistent asset id.
	realID, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: "anchor-ok.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE id=$1`, realID) })
	const missingID = int64(999999999)

	// Write a fact anchored to both the existing and the nonexistent asset.
	nodeID, err := es.AddNode(KindFact, map[string]any{"summary": "must still write even with a bad id in the anchor"}, 5, "confirmed", "worker-1", []int64{realID, missingID})
	if err != nil {
		t.Fatalf("AddNode must not fail on a missing asset anchor: %v", err)
	}
	if nodeID <= 0 {
		t.Fatalf("node id = %d, want > 0", nodeID)
	}

	// The node must really be persisted (this is the regressed path).
	var cnt int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE id=$1 AND kind='fact'`, nodeID).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("fact node persisted = %d, want 1", cnt)
	}

	// The valid anchor must be kept.
	var anchored int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, nodeID, realID).Scan(&anchored); err != nil {
		t.Fatal(err)
	}
	if anchored != 1 {
		t.Errorf("valid asset anchor kept = %d, want 1", anchored)
	}

	// A nonexistent asset must not leave a dangling anchor row.
	var dangling int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, nodeID, missingID).Scan(&dangling); err != nil {
		t.Fatal(err)
	}
	if dangling != 0 {
		t.Errorf("dangling anchor = %d, want 0", dangling)
	}
}

// AddIntent goes through the same AddNode path; a bad anchor must not break intent
// writing either — if the intent cannot be written, the exploration direction is lost
// outright, which is worse than losing a fact.
func TestAddIntentSkipsMissingAssetAnchors(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "intent anchor tolerance")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	intentID, err := es.AddIntent(map[string]any{"summary": "intent with a bad id in the anchor"}, 5, []int64{999999998}, "planner")
	if err != nil {
		t.Fatalf("AddIntent must not fail on a missing asset anchor: %v", err)
	}
	if intentID <= 0 {
		t.Fatalf("intent id = %d, want > 0", intentID)
	}

	// The intent must really enter the frontier (so a worker can pick it up).
	fr, err := es.Frontier(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr) != 1 || fr[0].ID != intentID {
		t.Fatalf("frontier = %+v, want the intent to survive", fr)
	}
}
