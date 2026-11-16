package db

import "testing"

// TestReopenCanceledIntents only reopens blocked intents that were "cancelled because the service stopped"
// (leftovers from a deployment restart); intents the user blocked manually (reason without "context canceled") stay untouched.
// Background: the v0.4.56 retrospective found 11 canceled blocked intents in tasks 6/8/9 stuck forever.
func TestReopenCanceledIntents(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("reopen canceled", "revival self-heal regression")
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(expID)

	canceled1 := mustIntent(t, es, "canceled on restart 1")
	// Real-world chain: the worker sets the intent blocked and writes the cancellation reason because the service stopped.
	if err := es.SetIntentBlockedReason(canceled1, "error: context canceled"); err != nil {
		t.Fatal(err)
	}
	if err := es.SetIntentState(canceled1, "blocked"); err != nil {
		t.Fatal(err)
	}
	if _, err := es.db.Exec(
		`UPDATE exploration_nodes SET blocked_reason='error: context canceled' WHERE id=$1`, canceled1); err != nil {
		t.Fatal(err)
	}

	userBlocked := mustIntent(t, es, "user manually blocked")
	if _, err := es.db.Exec(
		`UPDATE exploration_nodes SET state='blocked', blocked_reason='user requested pausing this direction' WHERE id=$1`, userBlocked); err != nil {
		t.Fatal(err)
	}

	doneIntent := mustIntent(t, es, "completed intent is unaffected")
	if err := es.SetIntentState(doneIntent, "done"); err != nil {
		t.Fatal(err)
	}

	n, err := es.ReopenCanceledIntents()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("should reopen exactly 1 canceled intent, got %d", n)
	}
	after, err := es.GetNode(canceled1)
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || after.State != "open" || after.BlockedReason != "" {
		t.Fatalf("canceled intent not restored to open: %+v", after)
	}
	ub, err := es.GetNode(userBlocked)
	if err != nil {
		t.Fatal(err)
	}
	if ub == nil || ub.State != "blocked" {
		t.Fatalf("user-blocked intent should not be reopened: %+v", ub)
	}
	dn, err := es.GetNode(doneIntent)
	if err != nil {
		t.Fatal(err)
	}
	if dn == nil || dn.State != "done" {
		t.Fatalf("done intent should be unaffected: %+v", dn)
	}
}
