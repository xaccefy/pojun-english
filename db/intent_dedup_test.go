package db

import (
	"testing"
)

// Normalization must absorb case, whitespace, and Chinese/English punctuation — otherwise the same sentence with different punctuation gets judged as two separate entries.
func TestNormalizeIntentText(t *testing.T) {
	same := []string{
		"scan port 8080",
		"scanport8080",
		"scan port 8080.",
		"  scan port 8080 !! ",
	}
	want := normalizeIntentText(same[0])
	for _, s := range same {
		if got := normalizeIntentText(s); got != want {
			t.Errorf("normalize(%q)=%q, want %q", s, got, want)
		}
	}
	if normalizeIntentText("scanport8080") == normalizeIntentText("scanport443") {
		t.Error("different ports must not normalize to the same string")
	}
}

// FindSimilarOpenIntent is dispatch dedup: highly similar open/running intents in the same task
// are not dispatched again.
func TestFindSimilarOpenIntent(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	expID, err := d.CreateExploration("dedup intent test", "goal")
	if err != nil {
		t.Fatal(err)
	}
	ts := d.Exploration(expID)

	id, err := ts.AddIntent(map[string]any{"summary": "directory brute-force against example.com"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	// only punctuation/whitespace differs → judged duplicate
	if got, _, ok, err := ts.FindSimilarOpenIntent("directory brute-force against example.com."); err != nil || !ok {
		t.Fatalf("punctuation difference should be judged duplicate: ok=%v err=%v", ok, err)
	} else if got != id {
		t.Fatalf("should return existing intent id=%d, got %d", id, got)
	}

	// clearly different direction → not deduped
	if _, _, ok, err := ts.FindSimilarOpenIntent("subdomain enumeration for example.com"); err != nil || ok {
		t.Fatalf("different directions must not be deduped: ok=%v err=%v", ok, err)
	}

	// a completed intent no longer participates in dedup (re-dispatch allowed)
	if err := ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := ts.FindSimilarOpenIntent("directory brute-force against example.com"); ok {
		t.Fatal("a completed intent must not block new intents")
	}
}