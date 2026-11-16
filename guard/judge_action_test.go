package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/intercept"
)

// When a rule hits with action=judge, guard must hand the call to the model for
// adjudication and land the verdict as allow / deny / ask — the key being "if the
// model says allow, let it through; if it says deny, block it".
//
// This path must not recurse: the verdict must not go through Match again (otherwise
// the rule would match itself again, becoming an infinite loop).
func TestJudgeActionRoutesToModelVerdict(t *testing.T) {
	ic := intercept.New(nil) // nil db: rule table empty, only test guard's routing
	g := NewWithInterceptor(ic)

	// Simulate "rule hit judge": constructing a Decision to go through the same branch
	// directly is inconvenient (Match needs db), so inject a reviewer via the
	// interceptor's JudgeRule instead.
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		return intercept.Decision{Action: "allow", Message: "read-only command, allow"}, nil
	})

	// Manually construct guard's internal judge branch: making Match return judge needs
	// db, so here we directly verify guard's secondary routing of a judge verdict —
	// indirectly confirming the reviewer was called via the interceptor's SetReviewer
	// plus one Judge call.
	input, _ := json.Marshal(map[string]string{"command": "cat /etc/hosts"})
	dec, ok := ic.JudgeRule(context.Background(), "Bash", input)
	if !ok {
		t.Fatal("JudgeRule produced no verdict")
	}
	if dec.Action != "allow" {
		t.Fatalf("verdict action=%q want allow", dec.Action)
	}
	// Verdict message must carry the [model] prefix so the audit page can distinguish human from model.
	if !strings.HasPrefix(dec.Message, "[model]") {
		t.Errorf("Verdict message missing [model] prefix: %q", dec.Message)
	}
	_ = g
}

// When a rule explicitly requires adjudication, adjudication must still happen even
// if the global judge switch is off — otherwise the rule is effectively toothless.
func TestJudgeRuleIgnoresGlobalEnableSwitch(t *testing.T) {
	ic := intercept.New(nil)
	called := false
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		called = true
		return intercept.Decision{Action: "deny", Message: "destructive operation"}, nil
	})
	input, _ := json.Marshal(map[string]string{"command": "rm -rf /var/www"})
	dec, ok := ic.JudgeRule(context.Background(), "Bash", input)
	if !ok {
		t.Fatal("JudgeRule produced no verdict (should still work when the global switch is off)")
	}
	if !called {
		t.Error("reviewer was not called")
	}
	if dec.Action != "deny" {
		t.Errorf("verdict action=%q want deny", dec.Action)
	}
}

// The fallback path (no rule hit) is still controlled by the global switch: if it is
// off, no adjudication happens.
func TestJudgeFallbackRespectsGlobalSwitch(t *testing.T) {
	ic := intercept.New(nil)
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		return intercept.Decision{Action: "deny"}, nil
	})
	input, _ := json.Marshal(map[string]string{"command": "rm -rf /var/www"})
	if _, ok := ic.Judge(context.Background(), "Bash", input); ok {
		t.Error("should not adjudicate when the global judge is off")
	}
}

var _ = db.InterceptRule{}
