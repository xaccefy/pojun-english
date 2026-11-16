package db

import (
	"regexp"
	"testing"
)

// Consistency between the built-in rule table and real routing behavior.
//
// The previous test (intercept_builtin_rules_test.go) asserts "is the classification field correct",
// this one asserts "after grouping by class, which path does each rule actually take" — turning the class from
// a declaration into verifiable behavior.
//
// How to tell: an "explicitly forbidden" hit → decidable without the model (action=deny blocks directly);
// a "judgment" hit → action=judge, delegated to the model.

// When an "explicitly forbidden" rule hits, the rule's own action must be deny — the model is
// never called on this path.
func TestHardDenyRulesResolveWithoutModel(t *testing.T) {
	for _, r := range builtinInterceptRules {
		if r.class != classHardDeny {
			continue
		}
		if r.action != "deny" {
			t.Errorf("explicitly forbidden rule %q has action=%q, the model path won't be reached (should be deny)", r.name, r.action)
		}
	}
}

// When a "judgment" rule hits, the rule's own action must be judge — the model will be called.
func TestJudgeRulesRouteToModel(t *testing.T) {
	for _, r := range builtinInterceptRules {
		if r.class != classJudge {
			continue
		}
		if r.action != "judge" {
			t.Errorf("judgment rule %q has action=%q, it won't reach the model (should be judge)", r.name, r.action)
		}
	}
}

// When a "human confirmation" rule hits it goes to ask — neither model verdict nor direct denial.
func TestAskRulesRouteToHuman(t *testing.T) {
	for _, r := range builtinInterceptRules {
		if r.class != classAsk {
			continue
		}
		if r.action != "ask" {
			t.Errorf("human confirmation rule %q has action=%q (should be ask)", r.name, r.action)
		}
	}
}

// Key behavior assertion: the same command is denied when it hits an "explicitly forbidden" rule, and goes to the model when it hits a "judgment"
// rule — exactly the "which are explicitly forbidden, which are delegated to the Agent" distinction the user wanted.
func TestSameCommandDifferentRulesDifferentPaths(t *testing.T) {
	byName := builtinRulesByName()

	// rm -rf appears in two rules: one hard-deny (Clear system critical directories), one judgment
	// (Recursive force-delete rm -rf). With the match order priority DESC, id ASC, the first hit
	// decides the path — here we verify the two rules really have different classes, i.e. **different routes**.
	hard := byName["[Built-in] Clear critical system directories"]
	judge := byName["[Built-in] Recursive forced deletion rm -rf"]
	if hard.class != classHardDeny || judge.class != classJudge {
		t.Fatalf("wrong classes for the two rm rules: clear=%s recursive=%s", hard.class, judge.class)
	}
	if hard.action != "deny" || judge.action != "judge" {
		t.Fatalf("wrong actions for the two rm rules: clear=%q recursive=%q", hard.action, judge.action)
	}

	// Both rules match rm -rf /etc/* — the route is decided by priority.
	re := regexp.MustCompile(hard.pattern)
	if !re.MatchString(`rm -rf /etc/*`) {
		t.Error("the hard-deny rule should match rm -rf /etc/*")
	}
	re2 := regexp.MustCompile(judge.pattern)
	if !re2.MatchString(`rm -rf /etc/*`) {
		t.Error("the judgment rule should match rm -rf /etc/*")
	}
	// The hard-deny one has a higher priority (100), so it hits first in the real DB → direct denial.
	if hard.priority < judge.priority {
		t.Errorf("the hard-deny rule's priority (%d) must be no lower than the judgment rule's (%d), otherwise the route is nondeterministic",
			hard.priority, judge.priority)
	}
}

// The built-in rule table must cover all classes across the three paths, and each class must be non-empty —
// a missing class means one side of "explicitly forbidden vs delegated to Agent vs human confirmation" is empty.
// (Since v0.3.87 the reverse-connection receiver has a real implementation, so the ask class has built-in rules again.)
func TestBuiltinRuleClassesAreAllPopulated(t *testing.T) {
	counts := map[string]int{}
	for _, r := range builtinInterceptRules {
		counts[r.class]++
	}
	for _, class := range []string{classHardDeny, classJudge, classAsk} {
		if counts[class] == 0 {
			t.Errorf("class %q has no built-in rules — one side of \"explicitly forbidden / delegated to Agent\" is empty", class)
		}
	}
}
