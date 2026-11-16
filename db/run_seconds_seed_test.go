package db

import (
	"testing"
)

// The **seed default** for an agent's single-run wall-clock budget must be 1200s (20 minutes).
//
// Why this value is locked down (corrected 2026-10-21):
//
// Upstream POJUN-upstream's seed default is 1200s; it forms a tight, fast-iteration loop of
// "short run → exhausted → planner judges progress from the trace → reassign or switch tactics".
//
// On 2026-10-20 we migrated it to 3600s, reasoning "89 intents exhausted vs 8
// done → too tight". That attribution was wrong: exhausted is not a failure signal, it is a
// signal that "this small step wasn't finished". Stretching to 3600s instead broke the loop —
// runs dragged to 1 hour, nearly always hitting hard limits, and the planner saw nothing but
// "run timed out" → reassigned the same chain → measured 4.1 hours of machine time with zero factual output.
//
// Another confounding factor at the time (context window 200K → 1M) was fixed
// separately. Mixing two variables and attributing them to one was the root of
// this detour. This test prevents it from being changed a third time.
func TestBuiltinAgentsUseSeedRunSeconds(t *testing.T) {
	// No builtin agent explicitly sets run_seconds (nil → use the seed default).
	// pentest is the sole exception: it explicitly sets 0 = unlimited (one agent walks the
	// whole pentest chain and should not be cut off by a single run's wall clock).
	for _, a := range builtinAgents {
		if a.key == "pentest" {
			if a.runSeconds == nil {
				t.Error("pentest should explicitly set run_seconds=0 (unlimited), got nil")
			} else if *a.runSeconds != 0 {
				t.Errorf("pentest run_seconds = %d, want 0", *a.runSeconds)
			}
			continue
		}
		if a.runSeconds != nil {
			t.Errorf("builtin agent %q explicitly sets run_seconds=%d -- should leave nil to use the seed default (1200), "+
				"otherwise it won't change when the seed default is adjusted", a.key, *a.runSeconds)
		}
	}
}

// The migration direction must be 3600→1200 (shorten runs), not the reverse.
//
// This locks the [direction] — the earlier 1200→3600 migration was the root of the detour, and it was a
// one-time migration: once run it was gone, leaving no way to verify afterward whether the direction was right. Extracting the
// rewrite logic into applyAgentRunSeconds lets us verify it directly in a unit test.
func TestApplyAgentRunSecondsDirection(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	// key must match CHECK (key ~ '^[a-z][a-z0-9_]*$').
	const key = "runsec_migrate_test"
	if _, err := d.Exec(`DELETE FROM agents WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO agents(key,name,description,role,builtin,enabled,run_seconds)
VALUES ($1,'t','t','assistant',false,true,3600)`, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM agents WHERE key=$1`, key) })

	// Migration direction: 3600 → 1200.
	if err := d.applyAgentRunSeconds(3600, 1200); err != nil {
		t.Fatalf("applyAgentRunSeconds: %v", err)
	}

	var got int
	if err := d.QueryRow(`SELECT run_seconds FROM agents WHERE key=$1`, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 1200 {
		t.Errorf("run_seconds = %d, want 1200 (migration direction must be 3600→1200)", got)
	}
}

// Only touch rows that "still hold the old value": instances users adjusted themselves stay unchanged.
func TestApplyAgentRunSecondsOnlyTouchesMatchingRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	rows := []struct {
		key  string
		secs int
	}{
		{"runsec_keep_a", 900},  // user-adjusted → leave alone
		{"runsec_move_b", 3600}, // old default → change to 1200
	}
	for _, r := range rows {
		if _, err := d.Exec(`DELETE FROM agents WHERE key=$1`, r.key); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`INSERT INTO agents(key,name,description,role,builtin,enabled,run_seconds)
VALUES ($1,'t','t','assistant',false,true,$2)`, r.key, r.secs); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, r := range rows {
			d.Exec(`DELETE FROM agents WHERE key=$1`, r.key)
		}
	})

	if err := d.applyAgentRunSeconds(3600, 1200); err != nil {
		t.Fatalf("applyAgentRunSeconds: %v", err)
	}

	for _, r := range rows {
		var got int
		if err := d.QueryRow(`SELECT run_seconds FROM agents WHERE key=$1`, r.key).Scan(&got); err != nil {
			t.Fatal(err)
		}
		want := r.secs
		if r.secs == 3600 {
			want = 1200
		}
		if got != want {
			t.Errorf("%s: run_seconds = %d, want %d", r.key, got, want)
		}
	}
}
