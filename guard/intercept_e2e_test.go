package guard

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/intercept"
)

// End-to-end verification that "explicitly forbidden" and "delegated to Agent for judgment" diverge on the **real call path**.
//
// This chain is: tool call → guard.applyIntercept → interceptor.Match (rule hit)
// → action=deny rejects directly / action=judge delegates to the model for a verdict → the verdict decides allow or deny.
//
// Before 2026-10-22, all built-in rules were deny, so the "model judgment" path
// was **never reached by a built-in rule** — the "explicitly forbidden vs delegated to Agent" distinction the user wanted
// didn't exist at the rule layer at all. This test is the regression baseline for that divergence.

// e2eRule describes a rule with db.InterceptRule (same shape as what's stored in the DB).
func e2eRule(id int64, name, pattern, action string, priority int, timeoutEnabled bool, timeoutSeconds int, timeoutAction string) db.InterceptRule {
	return db.InterceptRule{
		ID:             id,
		Name:           name,
		Enabled:        true,
		Priority:       priority,
		MatchTarget:    "tool_input",
		MatchType:      "regex",
		Pattern:        pattern,
		Action:         action,
		Message:        "Test rule " + name,
		TimeoutEnabled: timeoutEnabled,
		TimeoutSeconds: timeoutSeconds,
		TimeoutAction:  timeoutAction,
	}
}

// runE2E runs one full PreToolUse pass and returns whether it was blocked.
func runE2E(t *testing.T, rules []db.InterceptRule, reviewer intercept.Reviewer, cmd string) (blocked bool, judgeCalls int) {
	t.Helper()
	ic := intercept.New(nil)
	ic.SetRulesInMemory(rules)
	if reviewer != nil {
		ic.SetReviewer(reviewer)
	}
	g := NewWithInterceptor(ic)
	input, _ := json.Marshal(map[string]string{"command": cmd})
	blocked, _, _ = g.Hooks().PreToolUse(context.Background(), "Bash", input)
	return blocked, judgeCalls
}

// When an "explicitly forbidden" rule hits, it **rejects directly** and **does not call the model**.
//
// "Not calling the model" is the key: the point of a hard-deny rule is to save an LLM round-trip
// and not leave the gate open because of model flakiness (timeout, rate limiting, parse failure).
func TestE2EHardDenyBlocksWithoutCallingModel(t *testing.T) {
	judgeCalls := 0
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		judgeCalls++
		return intercept.Decision{Action: "allow", Message: "Model says allow"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[Built-in] Disk format mkfs", `\bmkfs\b`, "deny", 100, false, 60, "deny"),
	}
	blocked, _ := runE2E(t, rules, reviewer, `mkfs.ext4 /dev/sda`)
	if !blocked {
		t.Error("explicitly forbidden mkfs should be denied")
	}
	if judgeCalls != 0 {
		t.Errorf("an explicitly forbidden rule should not call the model, but it was called %d times", judgeCalls)
	}
}

// When a "delegated to Agent for judgment" rule hits, the model **must be called** and its verdict is authoritative.
//
// This is the core of the fix: before the fix, such commands were denied directly by the rule, and the model never got a chance to see them.
func TestE2EJudgeRuleDelegatesToModel(t *testing.T) {
	judgeCalls := 0
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		judgeCalls++
		return intercept.Decision{Action: "allow", Message: "[model] Test artifact, allow"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[Built-in] Recursive forced deletion rm -rf", `(?i)\brm\b.{0,80}-[a-z]*r[a-z]*f[a-z]*`, "judge", 100, true, 90, "allow"),
	}
	// Model says allow → do not block.
	blocked, _ := runE2E(t, rules, reviewer, `rm -rf /tmp/mytestdir`)
	if blocked {
		t.Error("should not block after the model verdict allows")
	}
	if judgeCalls != 1 {
		t.Errorf("a judgment rule should call the model once, actually %d times", judgeCalls)
	}

	// Model says deny → block.
	reviewer2 := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		judgeCalls++
		return intercept.Decision{Action: "deny", Message: "[model] Production data, deny"}, nil
	}
	blocked, _ = runE2E(t, rules, reviewer2, `rm -rf /var/www/html`)
	if !blocked {
		t.Error("should block after the model verdict denies")
	}
	if judgeCalls != 2 {
		t.Errorf("a judgment rule should call the model twice, actually %d times", judgeCalls)
	}
}

// A judgment rule's rule-level timeout declaration must actually reach the reviewer — when the model times out, fall back to the rule's own
// declaration (here allow), not the global default.
//
// Regression background: the timeout_* fields on a rule used to be dead (UI showed 60s/deny, but it was actually the global
// 180s/ask). What the user saw didn't match what it did.
func TestE2ERuleTimeoutReachesJudge(t *testing.T) {
	// Record the ctx deadline the reviewer sees.
	var seen time.Duration
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		deadline, ok := ctx.Deadline()
		if ok {
			seen = time.Until(deadline)
		}
		return intercept.Decision{Action: "allow"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[Built-in] Recursive forced deletion rm -rf", `(?i)\brm\b.{0,80}-[a-z]*r[a-z]*f[a-z]*`, "judge", 100, true, 45, "allow"),
	}
	runE2E(t, rules, reviewer, `rm -rf /tmp/x`)
	if seen < 43*time.Second || seen > 47*time.Second {
		t.Errorf("rule-level timeout not passed to reviewer: got %v, expected about 45s", seen)
	}
}

// When a rule declares no timeout, use the global default (180s) — it must not be affected by other rules' declarations.
func TestE2ERuleWithoutTimeoutUsesGlobal(t *testing.T) {
	var seen time.Duration
	reviewer := func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		deadline, ok := ctx.Deadline()
		if ok {
			seen = time.Until(deadline)
		}
		return intercept.Decision{Action: "allow"}, nil
	}

	rules := []db.InterceptRule{
		e2eRule(1, "[Built-in] Recursive forced deletion rm -rf", `(?i)\brm\b.{0,80}-[a-z]*r[a-z]*f[a-z]*`, "judge", 100, false, 60, "deny"),
	}
	runE2E(t, rules, reviewer, `rm -rf /tmp/x`)
	if seen < 170*time.Second || seen > 190*time.Second {
		t.Errorf("when timeout is disabled on the rule it should use the global 180s, got %v", seen)
	}
}
