package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestMaskedValueHidesBodyButKeepsTailHint(t *testing.T) {
	const secret = "https://oapi.dingtalk.com/robot/send?access_token=abcdef123456"
	got := MaskedValue(secret)
	if strings.Contains(got, "abcdef123456") {
		t.Fatalf("masked value leaks the full credential: %q", got)
	}
	if strings.Contains(got, "oapi.dingtalk.com") {
		t.Fatalf("masked value shouldn't expose the URL body: %q", got)
	}
	// The last 6 chars must survive — that's how users recognize which bot it is.
	if !strings.HasSuffix(got, "123456") {
		t.Fatalf("should keep the last 6 chars as an ID hint: %q", got)
	}
	if !IsMasked(got) {
		t.Fatalf("masked value must be IsMasked-recognized: %q", got)
	}
}

func TestMaskedValueShortSecretGivesNoHint(t *testing.T) {
	// Revealing 6 chars of a short credential exposes most of it.
	for _, s := range []string{"abc", "abcdef", ""} {
		got := MaskedValue(s)
		if got != MaskedPrefix {
			t.Fatalf("a %d-char credential shouldn't get a tail hint, got %q", len(s), got)
		}
		if s != "" && strings.Contains(got, s) {
			t.Fatalf("masked value contains the original: %q", got)
		}
	}
}

func TestMaskConfigMasksOnlySecrets(t *testing.T) {
	cfg := map[string]any{
		"webhook": "https://example.com/hook?token=SECRETVALUE",
		"secret":  "SECtest123456",
		"port":    float64(587),
		"host":    "smtp.example.com",
	}
	masked := MaskConfig(KindDingTalk, cfg)
	for _, k := range []string{"webhook", "secret"} {
		s, _ := masked[k].(string)
		if !IsMasked(s) {
			t.Errorf("%s should be masked, got %q", k, s)
		}
	}
	// Non-credential fields must pass through, else the UI can't render.
	if masked["port"] != float64(587) {
		t.Errorf("non-credential field port shouldn't change: %v", masked["port"])
	}
}

func TestMaskConfigUnknownKindReturnsEmpty(t *testing.T) {
	// Unrecognized kind → better an empty config in the UI than echoing possibly-credential-bearing content.
	got := MaskConfig("nope", map[string]any{"webhook": "https://x/y?token=LEAK"})
	if len(got) != 0 {
		t.Fatalf("unknown channel kind should return empty config, got %v", got)
	}
}

func TestMaskConfigDoesNotMutateInput(t *testing.T) {
	// Masking is a display-layer act — it must not mutate the stored real value.
	cfg := map[string]any{"webhook": "https://example.com/hook", "secret": "SECtest123456"}
	_ = MaskConfig(KindDingTalk, cfg)
	if IsMasked(cfg["secret"].(string)) {
		t.Fatal("MaskConfig mutated its input — real credentials would get overwritten by mask values")
	}
}

func TestMergeConfigKeepsStoredOnMaskedIncoming(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET", "method": "POST"}
	// User only changed method; the browser submits mask value + new method.
	incoming := map[string]any{
		"webhook": MaskedValue("https://real/hook"),
		"secret":  MaskedValue("REALSECRET"),
		"method":  "PUT",
	}
	got := MergeConfig(stored, incoming)
	if got["webhook"] != "https://real/hook" || got["secret"] != "REALSECRET" {
		t.Fatalf("masked field should keep the stored value, got %v", got)
	}
	if got["method"] != "PUT" {
		t.Fatalf("the edited field should take effect, got %v", got["method"])
	}
}

func TestMergeConfigEmptyStringClears(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET"}
	got := MergeConfig(stored, map[string]any{"secret": ""})
	if _, ok := got["secret"]; ok {
		t.Fatalf("empty string should clear the field, got %v", got)
	}
	// Unmentioned fields kept (partial-update semantics).
	if got["webhook"] != "https://real/hook" {
		t.Fatalf("unmentioned fields should be kept, got %v", got)
	}
}

func TestMergeConfigKeepsUnmentionedStoredKeys(t *testing.T) {
	stored := map[string]any{"host": "smtp.example.com", "port": float64(587), "password": "pw"}
	got := MergeConfig(stored, map[string]any{"port": float64(465)})
	if got["host"] != "smtp.example.com" || got["password"] != "pw" {
		t.Fatalf("unmentioned field should be kept, got %v", got)
	}
	if got["port"] != float64(465) {
		t.Fatalf("mentioned fields should update, got %v", got["port"])
	}
}

// TestPrepareConfigUpdateBlocksDestinationSwap is this package's most important security
// invariant: **changing the destination must not carry the old credentials along**.
//
// These cases use attack-shaped inputs (change only the address, stay silent on
// credentials) — not 'the defense logic's happy path'. Testing only the latter stays green
// even when the defense does nothing.
func TestPrepareConfigUpdateBlocksDestinationSwap(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
		// wantMissing is the credential key expected to be named.
		wantMissing string
	}{
		{
			name: "generic webhook address swap trying to keep the Authorization header",
			kind: KindWebhook,
			stored: map[string]any{
				"url":     "https://legit.example.com/hook",
				"headers": map[string]any{"Authorization": "Bearer REAL-TOKEN"},
			},
			incoming:    map[string]any{"url": "https://attacker.tld/c"},
			wantMissing: "headers",
		},
		{
			name:        "Telegram base_url swap trying to post the Bot Token to its own endpoint",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld"},
			wantMissing: "bot_token",
		},
		{
			name:        "email SMTP-host swap trying to hand over the password",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"host": "smtp.attacker.tld"},
			wantMissing: "password",
		},
		{
			name:        "email turning TLS off still requires re-affirming the password",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "tls": false, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"tls": true},
			wantMissing: "password",
		},
		{
			// Mask value = 'reuse the old credential' — equally rejectable under an address change.
			name:        "echoed mask credential + new address",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld", "bot_token": MaskedValue("123456:REAL")},
			wantMissing: "bot_token",
		},
		{
			name:        "DingTalk webhook swap trying to keep the signing secret",
			kind:        KindDingTalk,
			stored:      map[string]any{"webhook": "https://oapi.dingtalk.com/robot/send?access_token=OLD", "secret": "REALSEC"},
			incoming:    map[string]any{"webhook": "https://attacker.tld/hook"},
			wantMissing: "secret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err == nil {
				t.Fatalf("address changed without re-affirming credentials — should be rejected; merged config %v", merged)
			}
			var target *ErrDestinationChangedWithoutCredentials
			if !errors.As(err, &target) {
				t.Fatalf("should return a dedicated error type for an actionable API hint, got %T: %v", err, err)
			}
			found := false
			for _, m := range target.Missing {
				if m == tc.wantMissing {
					found = true
				}
			}
			if !found {
				t.Fatalf("should name the missing credential key %q, got %v", tc.wantMissing, target.Missing)
			}
			// The error must tell the operator how to fix it.
			if !strings.Contains(err.Error(), tc.wantMissing) {
				t.Errorf("error should mention %q: %v", tc.wantMissing, err)
			}
		})
	}
}

// TestPrepareConfigUpdateAllowsLegitimateEdits is the counter case: legitimate edits must
// not be blocked — else the guard gets bypassed or deleted for being 'too annoying'.
func TestPrepareConfigUpdateAllowsLegitimateEdits(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
	}{
		{
			name:     "rename only (config echoed verbatim)",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "headers": map[string]any{"Authorization": "Bearer REAL"}},
			incoming: map[string]any{"url": MaskedValue("https://legit.example.com/hook")},
		},
		{
			name:     "change method only, address and credentials untouched",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "method": "POST"},
			incoming: map[string]any{"method": "PUT"},
		},
		{
			name:     "new address **and** new credentials together",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": map[string]any{"Authorization": "Bearer NEW"}},
		},
		{
			name:     "new address plus explicit 'no credential needed'",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": ""},
		},
		{
			name:     "Telegram chat_id change (not a destination)",
			kind:     KindTelegram,
			stored:   map[string]any{"bot_token": "t", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming: map[string]any{"chat_id": "-100200"},
		},
		{
			name:     "email recipients change (not a destination)",
			kind:     KindEmail,
			stored:   map[string]any{"host": "smtp.corp.com", "port": 587, "password": "PW", "from": "a@b.c", "to": []any{"x@y.z"}},
			incoming: map[string]any{"to": []any{"new@y.z"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err != nil {
				t.Fatalf("legitimate edit wrongly blocked: %v", err)
			}
			if merged == nil {
				t.Fatal("should return the merged result")
			}
		})
	}
}

// TestPrepareConfigUpdatePortTypeTolerance covers an easy misjudgment: the frontend
// submits the port as a JSON number (float64), the DB reads float64 too — but the two
// values can differ in type (int vs float64). A == compare judges 'unchanged' as 'changed',
// and a user who only renamed gets 'please re-enter the password' — false alarms kill trust
// in the guard.
func TestPrepareConfigUpdatePortTypeTolerance(t *testing.T) {
	stored := map[string]any{"host": "smtp.corp.com", "port": float64(587), "password": "PW"}
	// Same port, submitted as an int.
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 587}); err != nil {
		t.Fatalf("identical port (type differs only) must not count as an address change: %v", err)
	}
	// A genuinely changed port must be blocked.
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 25}); err == nil {
		t.Fatal("a port change should be blocked")
	}
}

// TestPrepareConfigUpdateSurvivesRepeatedSaveWithBlankDestination covers the 'optionally
// blank destination field' path: Telegram's base_url left empty means the official API.
//
// This once made the channel fail every save from the second one on:
//
//	created storing base_url:"" (the create path stores the submitted config directly,
//	no MergeConfig)
//	→ first save: MergeConfig treats "" as explicit clear and deletes the key
//	→ second save: incoming still "", stored key gone → judged 'address changed'
//	→ bot_token is an echoed mask → 400 'destination changed, re-fill credentials'
//
// The user changed nothing yet could never save again without re-pasting the Bot Token.
func TestPrepareConfigUpdateSurvivesRepeatedSaveWithBlankDestination(t *testing.T) {
	stored := map[string]any{"bot_token": "123:ABC", "chat_id": "-100", "base_url": ""}

	// The frontend buildConfig() submits a value for every defined field: credentials get the
	// mask, empty text boxes submit "". Reproduced in full here — not just 'the changed keys'.
	submit := func() map[string]any {
		return map[string]any{
			"bot_token": MaskedValue("123:ABC"),
			"chat_id":   "-100",
			"base_url":  "",
		}
	}

	// First save: rename only, config echoed verbatim.
	merged, err := PrepareConfigUpdate(KindTelegram, stored, submit())
	if err != nil {
		t.Fatalf("first save wrongly blocked: %v", err)
	}
	if _, ok := merged["base_url"]; ok {
		t.Fatal("precondition changed: empty string should be deleted by MergeConfig — this case covers exactly the 'key is gone' step")
	}

	// Second save: submission identical to last time — user changed nothing.
	merged2, err := PrepareConfigUpdate(KindTelegram, merged, submit())
	if err != nil {
		t.Fatalf("second save wrongly blocked (user changed nothing): %v", err)
	}
	// Third time, confirming it's 'fails once' → reliably saveable.
	if _, err := PrepareConfigUpdate(KindTelegram, merged2, submit()); err != nil {
		t.Fatalf("third save wrongly blocked: %v", err)
	}
	// The credential must survive — not swept away by the empty-string logic.
	if got := merged2["bot_token"]; got != "123:ABC" {
		t.Fatalf("Bot Token should keep its value, got %v", got)
	}
}

// TestPrepareConfigUpdateStillGuardsBlankDestinationChanges pairs the previous case:
// treating "" as equal to 'key absent' must **not** let a real address change slip through.
// Both directions are real credential-exfil paths — Telegram's Bot Token rides the URL path,
// so changing base_url hands the Token to the new address.
func TestPrepareConfigUpdateStillGuardsBlankDestinationChanges(t *testing.T) {
	// Direction one: from 'empty' (official address) to a self-hosted one.
	official := map[string]any{"bot_token": "123:ABC", "chat_id": "-100"}
	if _, err := PrepareConfigUpdate(KindTelegram, official, map[string]any{
		"bot_token": MaskedValue("123:ABC"),
		"base_url":  "https://tg-proxy.attacker.tld",
	}); err == nil {
		t.Fatal("official→self-hosted must demand a fresh Token entry")
	}

	// Direction two: clearing the self-hosted address (= back to official API) is also an address change.
	proxied := map[string]any{"bot_token": "123:ABC", "base_url": "https://proxy.internal/bot"}
	if _, err := PrepareConfigUpdate(KindTelegram, proxied, map[string]any{
		"bot_token": MaskedValue("123:ABC"),
		"base_url":  "",
	}); err == nil {
		t.Fatal("clearing a self-hosted address (back to official API) is also an address change — must demand a fresh Token")
	}
}

func TestDestinationKeysDeclaredForEveryKind(t *testing.T) {
	// Same as SecretKeys: a channel that forgets to declare destination keys gets no PrepareConfigUpdate protection.
	for kind, ch := range registry {
		if len(ch.DestinationKeys()) == 0 {
			t.Errorf("channel %s declares no destination keys — address-swap credential protection doesn't cover it", kind)
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("channel %s declares no credential keys", kind)
		}
	}
}

func TestSecretKeysDeclaredForEveryKind(t *testing.T) {
	// The compiler already forces every channel to implement SecretKeys; this re-checks that
	// no channel 'hands in a blank paper' on masking — an empty slice means its credentials echo
	// to the browser in plaintext.
	expect := map[string]bool{
		KindDingTalk: true, KindFeishu: true, KindWeCom: true,
		KindWebhook: true, KindTelegram: true, KindEmail: true,
	}
	for kind, ch := range registry {
		if !expect[kind] {
			t.Errorf("channel %s has no masking expectation registered in this test", kind)
			continue
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("channel %s declares no credential fields — its config echoes in plaintext", kind)
		}
	}
}

// TestPrepareConfigUpdateRejectsMaskedInContainer covers a gap the audit flagged: when a
// mask sentinel is stuffed inside a **non-string** structure (webhook.headers is an object),
// MergeConfig only recognizes 'a string with the prefix' as masked — so the literal
// "__masked__" would be stored as a real header value. Auth silently breaks, no error.
func TestPrepareConfigUpdateRejectsMaskedInContainer(t *testing.T) {
	stored := map[string]any{
		"url":     "https://legit.example.com/hook",
		"headers": map[string]any{"Authorization": "Bearer REAL"},
	}
	// A mask sentinel riding inside an object.
	incoming := map[string]any{
		"headers": map[string]any{"Authorization": MaskedPrefix},
	}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, incoming); err == nil {
		t.Fatal("a mask sentinel inside a structure should be rejected (else the literal lands in the DB)")
	}
	// A wholesale-submitted object (a real new value) is accepted as usual.
	ok := map[string]any{"headers": map[string]any{"Authorization": "Bearer NEW"}}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, ok); err != nil {
		t.Fatalf("a proper new-headers submission shouldn't be blocked: %v", err)
	}
}
