package server

import "testing"

// A rule's timeout_action must validate to allow|deny.
//
// Since 2026-10-22 a rule's timeout_enabled/seconds/action **actually take effect** (the
// rule's own declaration beats the global judge config). That turned timeout_action from
// 'a string stored in the DB' into 'the real switch deciding allow-vs-deny on timeout' —
// the check `dec.TimeoutAction == "allow"` treats anything non-"allow" as deny, while the
// UI shows the garbage string. Users saw 'on timeout → <garbage>', actual behavior
// 'deny' — mismatched.
func TestValidateInterceptRuleReqTimeoutAction(t *testing.T) {
	base := interceptRuleReq{
		Name:           "test rule",
		MatchTarget:    "tool_input",
		MatchType:      "regex",
		Pattern:        "abc",
		Action:         "judge",
		Message:        "x",
		TimeoutEnabled: true,
		TimeoutSeconds: 90,
	}

	cases := []struct {
		name    string
		action  string
		wantErr bool
	}{
		{"allow is valid", "allow", false},
		{"deny is valid", "deny", false},
		{"empty is invalid", "", true},
		{"garbage is invalid", "maybe", true},
		{"wrong case is invalid", "ALLOW", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := base
			req.TimeoutAction = c.action
			err := validateInterceptRuleReq(req)
			if c.wantErr && err == nil {
				t.Errorf("timeout_action=%q should error, but passed", c.action)
			}
			if !c.wantErr && err != nil {
				t.Errorf("timeout_action=%q must not error: %v", c.action, err)
			}
		})
	}
}

// With timeouts enabled, timeout_seconds must be positive — 0 makes HandleAsk take the
// implicit '60s default' path: UI shows 0 while the real value is 60, mismatched.
func TestValidateInterceptRuleReqTimeoutSeconds(t *testing.T) {
	req := interceptRuleReq{
		Name:           "test rule",
		MatchTarget:    "tool_input",
		MatchType:      "regex",
		Pattern:        "abc",
		Action:         "judge",
		Message:        "x",
		TimeoutEnabled: true,
		TimeoutSeconds: 0,
		TimeoutAction:  "allow",
	}
	if err := validateInterceptRuleReq(req); err == nil {
		t.Error("timeout_seconds=0 with timeouts enabled should error")
	}

	// seconds=0 is allowed when timeouts are disabled (it has no effect then).
	req.TimeoutEnabled = false
	if err := validateInterceptRuleReq(req); err != nil {
		t.Errorf("must not error on seconds=0 with timeouts disabled: %v", err)
	}
}
