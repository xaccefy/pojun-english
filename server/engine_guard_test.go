package server

import (
	"testing"

	"github.com/chu0119/pojun/db"
)

// v0.4.28 repeated-call detection (PentAGI mechanism, self-built): same tool + identical
// input intercepted from the 3rd consecutive time; a streak is intercepted at most twice
// then passes through; input changes reset immediately.
func TestRepeatTracker(t *testing.T) {
	rt := newRepeatTracker()
	in := []byte(`{"url": "https://a.example.com/x"}`)

	if _, block := rt.observe("http_probe", in); block {
		t.Fatal("1st identical call must pass")
	}
	if _, block := rt.observe("http_probe", in); block {
		t.Fatal("2nd identical call must pass")
	}
	if _, block := rt.observe("http_probe", in); !block {
		t.Fatal("3rd identical call must be blocked")
	}
	if _, block := rt.observe("http_probe", in); !block {
		t.Fatal("4th identical call must be blocked (2nd block)")
	}
	if _, block := rt.observe("http_probe", in); block {
		t.Fatal("5th identical call must pass after block cap (avoid livelock)")
	}
	// input change → reset.
	if _, block := rt.observe("http_probe", []byte(`{"url": "https://b.example.com/y"}`)); block {
		t.Fatal("changed input must reset and pass")
	}
	// switching tool names also resets.
	if _, block := rt.observe("list_assets", []byte(`{"url": "https://b.example.com/y"}`)); block {
		t.Fatal("different tool must reset and pass")
	}
}

// whitespace differences must not escape repeat detection (JSON canonicalization).
func TestRepeatTrackerWhitespaceInsensitive(t *testing.T) {
	rt := newRepeatTracker()
	rt.observe("Bash", []byte(`{"command":"id"}`))
	rt.observe("Bash", []byte(`{ "command" : "id" }`))
	if _, block := rt.observe("Bash", []byte("{\n  \"command\": \"id\"\n}")); !block {
		t.Fatal("whitespace-only differences must count as identical")
	}
}

// v0.4.28 intent soft budget: a single notice once cumulative usage tops out; no
// interruption below the cap; disabled means no-op.
func TestIntentBudgetWatcher(t *testing.T) {
	in := 700
	out := 200

	var msgs []string
	steer := func(m string) error { msgs = append(msgs, m); return nil }
	w := intentBudgetWatcher(intentBudgetConfig{Enabled: true, Tokens: 1000}, steer, "test")
	if w == nil {
		t.Fatal("watcher must be non-nil when enabled")
	}
	// usage below the cap doesn't trigger.
	w(db.Activity{Kind: "usage", InputTokens: &in, OutputTokens: &out})
	if len(msgs) != 0 {
		t.Fatalf("below budget must not steer, got %v", msgs)
	}
	// hitting the cap triggers once.
	in2 := 1200
	w(db.Activity{Kind: "usage", InputTokens: &in2, OutputTokens: &out})
	if len(msgs) != 1 {
		t.Fatalf("crossing budget must steer once, got %d", len(msgs))
	}
	// later usage doesn't re-notify.
	in3 := 1500
	w(db.Activity{Kind: "usage", InputTokens: &in3, OutputTokens: &out})
	if len(msgs) != 1 {
		t.Fatalf("must steer only once per intent, got %d", len(msgs))
	}
	// non-usage activities don't interfere.
	w(db.Activity{Kind: "tool_use"})

	// disabled produces no watcher.
	if intentBudgetWatcher(intentBudgetConfig{Enabled: false, Tokens: 1000}, steer, "test") != nil {
		t.Fatal("disabled budget must return nil watcher")
	}
}

// A settings read failure falls back to defaults — never turn the budget into a hard
// failure.
func TestIntentBudgetDefaults(t *testing.T) {
	c := intentBudgetFromPG(nil)
	if !c.Enabled || c.Tokens != defaultIntentBudgetTokens {
		t.Fatalf("nil pg must yield defaults, got %+v", c)
	}
}
