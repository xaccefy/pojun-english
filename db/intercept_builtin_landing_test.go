package db

import (
	"testing"
)

// Real-DB verification: the actual state of built-in rules **in the database** after seeding + migration.
//
// This test is direct evidence of "what the rules look like after a fresh install" — the
// classification tests above assert against the definition table in code, while this one
// asserts the **result after landing in the DB**. A mismatch means something went wrong with
// seeding or migration (e.g. misplaced parameters writing an empty string into pattern).
//
// Requires a real PG (skipped along with the other db tests when no DB is available).
func TestSeededBuiltinRulesLandInDatabase(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	rules, err := d.ListInterceptRules()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]InterceptRule{}
	for _, r := range rules {
		byName[r.Name] = r
	}

	// Every built-in rule must land in the DB, with action/timeout consistent with the definition table.
	for _, def := range builtinInterceptRules {
		got, ok := byName[def.name]
		if !ok {
			t.Errorf("built-in rule %q not in DB", def.name)
			continue
		}
		if got.Action != def.action {
			t.Errorf("rule %q landed with action=%q, want %q", def.name, got.Action, def.action)
		}
		if got.TimeoutEnabled != def.timeoutEnabled {
			t.Errorf("rule %q landed with timeout_enabled=%v, want %v",
				def.name, got.TimeoutEnabled, def.timeoutEnabled)
		}
		if got.TimeoutSeconds != def.timeoutSeconds {
			t.Errorf("rule %q landed with timeout_seconds=%d, want %d",
				def.name, got.TimeoutSeconds, def.timeoutSeconds)
		}
		if got.TimeoutAction != def.timeoutAction {
			t.Errorf("rule %q landed with timeout_action=%q, want %q",
				def.name, got.TimeoutAction, def.timeoutAction)
		}
		// pattern must not be empty either — the misplaced-parameter class of bug is exactly what writes an empty string here.
		if got.Pattern == "" {
			t.Errorf("rule %q has empty pattern after landing in DB", def.name)
		}
	}

	// All three classes — hard deny / adjudication / human confirmation — must have real entries in the DB (ask restored since v0.3.87).
	counts := map[string]int{}
	for _, r := range rules {
		for _, def := range builtinInterceptRules {
			if def.name == r.Name {
				counts[def.class]++
				break
			}
		}
	}
	for _, class := range []string{classHardDeny, classJudge, classAsk} {
		if counts[class] == 0 {
			t.Errorf("no built-in rule of class %q in the DB", class)
		}
	}
	t.Logf("Built-in rule class stats in DB: hard-deny=%d judge=%d ask=%d",
		counts[classHardDeny], counts[classJudge], counts[classAsk])
}

// Upgrade-path regression: fresh v0.3.86 install (v4 flag set, rule removed from catalog) → v0.3.87
// upgrade — the V4 seed must re-seed the "enable/disable reverse-connection receiver" rule by name (a bug found in Kali testing).
// This simulates that sequence: set flag → delete rule row → run V4 seed → assert the rule is back.
func TestListenerRuleRepairedOnUpgrade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	flag := "intercept_default_rules_v4_listener"
	if err := d.SetSetting(flag, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM intercept_rules WHERE name=$1`, "[Built-in] Start/stop reverse-connection receiver"); err != nil {
		t.Fatal(err)
	}
	if err := d.seedDefaultInterceptRulesV4(); err != nil {
		t.Fatal(err)
	}
	var action string
	err = d.QueryRow(`SELECT action FROM intercept_rules WHERE name=$1`, "[Built-in] Start/stop reverse-connection receiver").Scan(&action)
	if err != nil {
		t.Fatalf("listener rule should be re-seeded after upgrade: %v", err)
	}
	if action != "ask" {
		t.Fatalf("listener rule action=%q, want ask", action)
	}
}
