package intercept

import "testing"

// Layout deviations in verdict replies (half-width colons, newlines, half-width
// semicolons) must not be judged 'unparseable' — thinking models add newlines especially
// readily. Treating them all as failures sent every verdict to the fallback policy.
func TestParseVerdictToleratesFormatting(t *testing.T) {
	cases := []struct {
		name  string
		reply string
	}{
		{"standard", `{"decision":"allow","comment":"Actual action: read a file; Consequence on success: returns content; Matched rule: A5"}`},
		{"extra spaces after labels", `{"decision":"allow","comment":"Actual action:  read a file; Consequence on success:  returns content; Matched rule:  A5"}`},
		{"with newlines", `{"decision":"deny","comment":"Actual action: delete an order\nConsequence on success: record is lost\nMatched rule: D4"}`},
		{"code fence", "```json\n" + `{"decision":"ask","comment":"Actual action: delete a file; Consequence on success: lost; Matched rule: ASK"}` + "\n```"},
		{"extra fields", `{"decision":"allow","comment":"Actual action: read a file; Consequence on success: returns content; Matched rule: A5","reason":"read-only operation"}`},
		{"three sections without labels", `{"decision":"allow","comment":"read a file; returns content; Matched rule A5"}`},
	}
	for _, c := range cases {
		v := ParseVerdict(c.reply)
		if v.Action == "" {
			t.Errorf("%s: parse failed — layout deviations should be tolerated", c.name)
			continue
		}
		if v.Reason == "" {
			t.Errorf("%s: reason is empty", c.name)
		}
	}
}

// A comment missing one of the three sections must stay invalid — tolerance only fixes
// layout, never semantics.
func TestParseVerdictStillRejectsIncomplete(t *testing.T) {
	bad := []string{
		`{"decision":"allow","comment":"read a file"}`,
		`{"decision":"allow","comment":"Actual action: read a file; Consequence on success: returns content"}`,
		`{"decision":"allow","comment":"Actual action: ; Consequence on success: returns content; Matched rule: A5"}`,
		`{"decision":"maybe","comment":"Actual action: read a file; Consequence on success: returns content; Matched rule: A5"}`,
		`{"decision":"allow"}`,
		`not json at all`,
	}
	for _, b := range bad {
		if v := ParseVerdict(b); v.Action != "" {
			t.Errorf("ParseVerdict(%q) should be invalid, got action=%q", b, v.Action)
		}
	}
}

// Failure/timeout defaults assume 'nobody at the keyboard': verdict failure routes to a
// human; human timeout permits. Assert these defaults — reverting them would deadlock or
// silently fail when nobody is around.
func TestJudgeDefaultsAreHumanAbsentFriendly(t *testing.T) {
	if defaultJudgeTimeoutSecs < 60 {
		t.Errorf("verdict timeout %ds too short: thinking models won't finish", defaultJudgeTimeoutSecs)
	}
	if defaultJudgeFailAction != "ask" {
		t.Errorf("verdict failure policy=%q, should be ask (a dead model must not silently permit)", defaultJudgeFailAction)
	}
	if defaultJudgeAskTimeoutAction != "allow" {
		t.Errorf("human-approval timeout policy=%q, should be allow (don't deadlock when nobody is around)", defaultJudgeAskTimeoutAction)
	}
	if defaultJudgeAskTimeoutSecs < 120 {
		t.Errorf("human-approval timeout %ds too short for an operator to come back", defaultJudgeAskTimeoutSecs)
	}
}
