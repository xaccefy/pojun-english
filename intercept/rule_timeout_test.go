package intercept

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Rule-level timeout override (P0 fix: timeout_enabled/seconds/action used to be dead
// fields).
//
// Background: a rule's three timeout_* fields were only stored/read in CRUD
// (db/intercept.go, server/intercept.go); the verdict path intercept.judge() never read
// them — it only read the global settings (llm_judge_timeout_seconds /
// llm_judge_fail_action). So every rule's UI said 'timeout 60s / deny on timeout' while
// what actually applied was 'global 180s / route to ask on failure'. Showing users one
// thing while doing another is worse than having no field at all.
//
// Semantics (locked by this file):
//   - rule timeout_enabled=false → use global llm_judge_timeout_seconds + global
//     llm_judge_fail_action.
//   - rule timeout_enabled=true  → use the rule's own timeout_seconds + timeout_action.
//     This is the rule author's explicit declaration and outranks the global.
//
// These two groups are the regression baseline for 'dead fields': reverting to the global
// turns them red.

// judgeRuleWithTimeout goes through the 'rule matched judge' path carrying a rule-level
// timeout override.
func judgeRuleWithTimeout(t *testing.T, rt RuleTimeout, reviewer Reviewer) (Decision, bool) {
	t.Helper()
	ic := New(nil)
	if reviewer != nil {
		ic.SetReviewer(reviewer)
	}
	return ic.JudgeRuleWithTimeout(context.Background(), "Bash", json.RawMessage(`{"command":"rm -rf /tmp/x"}`), rt)
}

// When a rule explicitly declares a timeout (enabled=true), the verdict wall clock must
// use the rule's own value, not the global 180s.
func TestRuleTimeoutOverridesGlobalJudgeTimeout(t *testing.T) {
	var seen time.Duration
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		// record the ctx's remaining deadline to derive the wall clock actually in
		// effect.
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("verdict context has no deadline — the timeout cap isn't in effect")
			return Decision{Action: "allow"}, nil
		}
		seen = time.Until(deadline)
		return Decision{Action: "allow", Message: "permit"}, nil
	})

	dec, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"rm -rf /tmp/x"}`),
		RuleTimeout{Enabled: true, Seconds: 30, Action: "deny"})
	if !ok {
		t.Fatal("a rule demanding a verdict should produce one")
	}
	if dec.Action != "allow" {
		t.Fatalf("verdict action=%q want allow", dec.Action)
	}
	// allow 2s of scheduling error (overhead between context creation and sampling).
	if seen < 28*time.Second || seen > 32*time.Second {
		t.Errorf("rule-level timeout not in effect: wall clock %v, expected ~30s", seen)
	}
}

// With rule timeout_enabled=false the global config must apply (a silent rule follows
// the global).
func TestRuleTimeoutDisabledFallsBackToGlobal(t *testing.T) {
	var seen time.Duration
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("verdict context has no deadline — the global timeout isn't in effect either")
			return Decision{Action: "allow"}, nil
		}
		seen = time.Until(deadline)
		return Decision{Action: "allow"}, nil
	})

	// rule didn't enable timeout (enabled=false) → global default 180s.
	_, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"rm -rf /tmp/x"}`),
		RuleTimeout{Enabled: false, Seconds: 30, Action: "deny"})
	if !ok {
		t.Fatal("a rule demanding a verdict should produce one")
	}
	if seen < 170*time.Second || seen > 190*time.Second {
		t.Errorf("with rule timeout disabled it should fall back to the global 180s, got %v", seen)
	}
}

// The rule-level timeout_action decides the action after 'model verdict failed/timed
// out'. Hard-deny rules must 'deny on timeout' — a flaky model must not let mkfs through.
func TestRuleTimeoutActionGovernsJudgeFailure(t *testing.T) {
	// model unavailable (reviewer returns an error) → apply the 'after failure/timeout'
	// action.
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		return Decision{}, context.DeadlineExceeded
	})

	dec, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"mkfs.ext4 /dev/sda"}`),
		RuleTimeout{Enabled: true, Seconds: 5, Action: "deny"})
	if !ok {
		t.Fatal("a model failure should still yield the failure-policy action")
	}
	if dec.Action != "deny" {
		t.Fatalf("rule-level timeout_action=deny not in effect: verdict action=%q want deny", dec.Action)
	}
}

// With rule-level timeout_action=allow, a model failure permits.
func TestRuleTimeoutActionAllowGovernsJudgeFailure(t *testing.T) {
	ic := New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		return Decision{}, context.DeadlineExceeded
	})

	dec, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -X DELETE http://x/api/users/1"}`),
		RuleTimeout{Enabled: true, Seconds: 5, Action: "allow"})
	if !ok {
		t.Fatal("a model failure should still yield the failure-policy action")
	}
	if dec.Action != "allow" {
		t.Fatalf("rule-level timeout_action=allow not in effect: verdict action=%q want allow", dec.Action)
	}
}

// A rule-level timeout override must not pollute the global: the next override-free
// verdict must still use the global value.
func TestRuleTimeoutOverrideDoesNotLeakToGlobal(t *testing.T) {
	ic := New(nil)
	var seen time.Duration
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		deadline, _ := ctx.Deadline()
		seen = time.Until(deadline)
		return Decision{Action: "allow"}, nil
	})

	// first one with the rule override (30s).
	if _, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"x"}`),
		RuleTimeout{Enabled: true, Seconds: 30, Action: "deny"}); !ok {
		t.Fatal("first verdict didn't take effect")
	}
	// then one without the override — must return to the global 180s, unpolluted by the
	// previous 30s.
	if _, ok := ic.JudgeRuleWithTimeout(context.Background(), "Bash",
		json.RawMessage(`{"command":"y"}`),
		RuleTimeout{Enabled: false}); !ok {
		t.Fatal("second verdict didn't take effect")
	}
	if seen < 170*time.Second || seen > 190*time.Second {
		t.Errorf("rule-level override leaked into the global: got %v, expected ~180s", seen)
	}
}

// The fallback verdict (no rule matched) is unaffected by any rule-level override — it
// has no rule to follow and only the global applies.
//
// Note: the global judge switch defaults off, and then the fallback doesn't judge at all
// (pre-existing behavior, not introduced here). So this asserts 'no verdict' rather than
// 'which timeout' — asserting the timeout value needs a DB instance with the switch on,
// which belongs to the db package's tests.
func TestFallbackJudgeUsesGlobalTimeout(t *testing.T) {
	ic := New(nil)
	called := false
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		called = true
		return Decision{Action: "allow"}, nil
	})

	dec, ok := ic.Judge(context.Background(), "Bash", json.RawMessage(`{"command":"x"}`))
	if ok {
		t.Fatalf("with the global judge off the fallback must not judge, got action=%q", dec.Action)
	}
	if called {
		t.Error("with the global judge off the reviewer must not be called")
	}
}
