package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// singleMsg builds a one-off message whose title/summary carry `"` and `\n` on purpose —
// exactly the input where naive template interpolation produces invalid JSON.
func singleMsg() Message {
	return Message{
		Items: []Item{{
			FindingID: 42,
			Name:      `login "SQL injection" risk`,
			VulnClass: "SQL injection",
			Severity:  "high",
			Summary:   "parameter id\nnot filtered leading to injection",
			Assets:    []string{"a.example.com", "b.example.com"},
			DetailURL: "https://pojun.local/function/findings/detail?id=42",
		}},
	}
}

// batchMsg builds a digest batch.
func batchMsg(n int) Message {
	m := Message{Batch: true, WindowMinutes: 30, HomeURL: "https://pojun.local/function/findings"}
	for i := 0; i < n; i++ {
		m.Items = append(m.Items, Item{
			FindingID: int64(i + 1),
			Name:      "vuln" + itoa(i+1),
			VulnClass: "XSS",
			Severity:  "medium",
			Summary:   "reflected XSS",
			Assets:    []string{"target.example.com"},
		})
	}
	return m
}

// capturePost starts a fake receiver that hands the received body and headers to the assert func.
func capturePost(t *testing.T, respBody string, assert func(t *testing.T, body map[string]any, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("body is not valid JSON: %v\nraw: %s", err, raw)
			}
		}
		if assert != nil {
			assert(t, body, r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDingTalkSendsActionCardWhenLinkPresent(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "actionCard" {
			t.Fatalf("a deep-linked item should use actionCard, got %v", body["msgtype"])
		}
		card, _ := body["actionCard"].(map[string]any)
		if card["singleURL"] != "https://pojun.local/function/findings/detail?id=42" {
			t.Errorf("deep link lost: %v", card["singleURL"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestDingTalkFallsBackToMarkdownForBatch(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "markdown" {
			t.Fatalf("digest should send markdown, got %v", body["msgtype"])
		}
		md, _ := body["markdown"].(map[string]any)
		if !strings.Contains(md["text"].(string), "last 30 minutes") {
			t.Errorf("digest body missing the time window: %v", md["text"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, batchMsg(3)); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

// TestDingTalkBusinessErrorIsPermanent pins the 'HTTP 200 but errcode != 0' check.
// Skipping errcode records failures as successes — a trap shared by these IM platforms.
func TestDingTalkBusinessErrorIsPermanent(t *testing.T) {
	srv := capturePost(t, `{"errcode":310000,"errmsg":"keywords not in content"}`, nil)
	_, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg())
	if err == nil {
		t.Fatal("non-zero errcode should error")
	}
	if !IsPermanent(err) {
		t.Fatalf("keyword mismatch is a config error — should be permanent, got %v", err)
	}
	if !strings.Contains(err.Error(), "310000") {
		t.Errorf("error should carry the platform code, got %v", err)
	}
}

func TestWeComTruncatesCJKWithinByteLimit(t *testing.T) {
	var contentLen int
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		md, _ := body["markdown"].(map[string]any)
		content, _ := md["content"].(string)
		contentLen = len(content)
		if !utf8.ValidString(content) {
			t.Fatal("truncated body is not valid UTF-8 — WeCom would reject the whole message")
		}
	})
	// Build a digest long enough in CJK bytes to exceed 4096 bytes for sure.
	m := batchMsg(200)
	if _, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if contentLen > weComMarkdownLimit {
		t.Fatalf("body %d bytes exceeds WeCom limit %d", contentLen, weComMarkdownLimit)
	}
	if contentLen == 0 {
		t.Fatal("body is empty")
	}
}

func TestWeComRateLimitIsRetryableButKeyErrorIsPermanent(t *testing.T) {
	limited := capturePost(t, `{"errcode":45009,"errmsg":"api freq out of limit"}`, nil)
	_, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": limited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("45009 is a rolling-window rate limit — should be retriable, got %v", err)
	}

	badKey := capturePost(t, `{"errcode":93000,"errmsg":"invalid webhook url"}`, nil)
	_, err = (weComChannel{}).Send(context.Background(), map[string]any{"webhook": badKey.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("93000 is invalid key — retries won't heal, should be permanent, got %v", err)
	}
}

func TestFeishuCardStructureAndSign(t *testing.T) {
	const secret = "SECtest123"
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msg_type"] != "interactive" {
			t.Fatalf("should send an interactive card, got %v", body["msg_type"])
		}
		card, _ := body["card"].(map[string]any)
		header, _ := card["header"].(map[string]any)
		if header["template"] != "orange" {
			t.Errorf("high severity should map to orange, got %v", header["template"])
		}
		// With a secret configured, signing params must be present — else Feishu rejects with 19021.
		if body["sign"] == nil || body["timestamp"] == nil {
			t.Fatalf("signing params missing: %v", body)
		}
		// The card should carry a button whose url points at the vuln detail.
		elements, _ := card["elements"].([]any)
		foundButton := false
		for _, e := range elements {
			em, _ := e.(map[string]any)
			if em["tag"] != "action" {
				continue
			}
			actions, _ := em["actions"].([]any)
			for _, a := range actions {
				am, _ := a.(map[string]any)
				if am["url"] == "https://pojun.local/function/findings/detail?id=42" {
					foundButton = true
				}
			}
		}
		if !foundButton {
			t.Fatal("no button pointing at the vuln detail page in the card")
		}
	})
	cfg := map[string]any{"webhook": srv.URL, "secret": secret}
	if _, err := (feishuChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestFeishuWithoutSecretOmitsSign(t *testing.T) {
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["sign"] != nil || body["timestamp"] != nil {
			t.Fatalf("no secret configured — signing params must be absent: %v", body)
		}
	})
	if _, err := (feishuChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestTelegramEscapesHTMLInUntrustedContent(t *testing.T) {
	var text string
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		text, _ = body["text"].(string)
		if body["parse_mode"] != "HTML" {
			t.Fatalf("should use HTML parse mode, got %v", body["parse_mode"])
		}
	})
	m := Message{Items: []Item{{
		Severity: "high",
		// Title and summary come from the tested target / model output — untrusted.
		Name:    `<script>alert(1)</script>`,
		Summary: "a & b < c",
	}}}
	if _, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if strings.Contains(text, "<script>") {
		t.Fatalf("HTML not escaped — injection possible: %q", text)
	}
	if !strings.Contains(text, "&lt;script&gt;") {
		t.Fatalf("expected escaped entity, got %q", text)
	}
	if !strings.Contains(text, "a &amp; b") {
		t.Fatalf("& not escaped, got %q", text)
	}
}

func TestTelegramErrorClassification(t *testing.T) {
	rateLimited := capturePost(t, `{"ok":false,"error_code":429,"description":"Too Many Requests"}`, nil)
	_, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": rateLimited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 should be retriable, got %v", err)
	}

	forbidden := capturePost(t, `{"ok":false,"error_code":403,"description":"bot was blocked by the user"}`, nil)
	_, err = (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": forbidden.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("403 is a config issue — should be permanent, got %v", err)
	}
}

func TestWebhookDefaultTemplateProducesValidJSON(t *testing.T) {
	// The reason the default template exists: with quotes/newlines in a title, any naive
	// `"title": "{{.Title}}"` produces invalid JSON. {{json .}} doesn't.
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["title"] != `[🟠 High] login "SQL injection" risk` {
			t.Errorf("title not restored correctly: %v", body["title"])
		}
		items, _ := body["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("items should be 1, got %d", len(items))
		}
		it, _ := items[0].(map[string]any)
		if it["summary"] != "parameter id\nnot filtered leading to injection" {
			t.Errorf("summary not restored correctly: %v", it["summary"])
		}
		// The number must be a JSON number, not a string (json:",string" style bugs hit this).
		if _, ok := it["finding_id"].(float64); !ok {
			t.Errorf("finding_id should be a number, got %T", it["finding_id"])
		}
	})
	if _, err := (webhookChannel{}).Send(context.Background(), map[string]any{"url": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestWebhookCustomTemplateAndHeaders(t *testing.T) {
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, r *http.Request) {
		if r.Header.Get("X-Token") != "s3cret" {
			t.Errorf("custom headers lost: %v", r.Header)
		}
		if body["msg"] != "3 items" {
			t.Errorf("custom template rendered wrong: %v", body["msg"])
		}
		if body["first"] != "vuln1" {
			t.Errorf("range extraction wrong: %v", body["first"])
		}
	})
	cfg := map[string]any{
		"url":           srv.URL,
		"headers":       map[string]any{"X-Token": "s3cret"},
		"body_template": `{"msg": {{json (printf "%d items" .Count)}}, "first": {{json (index .Items 0).Name}}}`,
	}
	if _, err := (webhookChannel{}).Send(context.Background(), cfg, batchMsg(3)); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestWebhookRejectsNonJSONRenderResult(t *testing.T) {
	cfg := map[string]any{"url": "https://example.com/hook", "body_template": `not json at all`}
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("non-JSON render should be permanent (bad template — retries useless), got %v", err)
	}
}

func TestWebhookValidateCatchesBadConfigEarly(t *testing.T) {
	bad := []map[string]any{
		{},
		{"url": "file:///etc/passwd"},
		{"url": "https://example.com", "method": "DELETE"},
		{"url": "https://example.com", "body_template": `{{.Items.`},
	}
	for i, cfg := range bad {
		if err := (webhookChannel{}).Validate(cfg); err == nil {
			t.Errorf("config group %d should be rejected: %v", i, cfg)
		}
	}
}

func TestEmailMessageIsWellFormed(t *testing.T) {
	msg, err := buildEmailMessage("pojun@example.com", []string{"a@example.com", "b@example.com"}, singleMsg())
	if err != nil {
		t.Fatalf("failed to build the email: %v", err)
	}
	if !strings.HasPrefix(msg, "From: pojun@example.com\r\n") {
		t.Fatalf("From header wrong:\n%s", msg)
	}
	if !strings.Contains(msg, "To: a@example.com, b@example.com\r\n") {
		t.Fatalf("To header wrong:\n%s", msg)
	}
	// A non-ASCII subject needs RFC 2047 encoding or clients show mojibake.
	if !strings.Contains(msg, "Subject: =?utf-8?") {
		t.Fatalf("subject not RFC 2047 encoded:\n%s", msg)
	}
	if dec, err := new(mime.WordDecoder).DecodeHeader(mustExtractHeader(t, msg, "Subject")); err != nil {
		t.Fatalf("subject fails to decode: %v", err)
	} else if !strings.Contains(dec, "SQL injection") {
		t.Fatalf("decoded subject content wrong: %q", dec)
	}

	// Body is base64 — decoding must yield valid HTML.
	parts := strings.SplitN(msg, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatal("email missing header/body separator")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(parts[1]), "\r\n", ""))
	if err != nil {
		t.Fatalf("body base64 decode failed: %v", err)
	}
	html := string(decoded)
	if !strings.HasPrefix(html, "<div") {
		t.Fatalf("body is not HTML: %.80s", html)
	}
	// The title appears verbatim in text position: a double quote inside HTML text is legal —
	// no escaping needed. Asserting 'verbatim' guards against a future quote-escaping layer that
	// would render CJK quotes as &quot;.
	if !strings.Contains(html, `"SQL injection"`) {
		t.Fatalf("quotes in the title should stay verbatim in text position: %.200s", html)
	}
}

// TestEmailEscapesStructuralInjection covers the injections the email body must stop:
// vuln titles and summaries come from tested targets and model output — untrusted. Text
// position must escape & < > (else tags inject); attribute position must also escape quotes
// (else an href closes early).
func TestEmailEscapesStructuralInjection(t *testing.T) {
	m := Message{
		Items: []Item{{
			Severity:  "high",
			Name:      `<script>alert(1)</script>`,
			Summary:   "a & b > c",
			DetailURL: `https://pojun.local/x?a="onmouseover=alert(1)`,
		}},
	}
	html := htmlBody(m, 0)
	if strings.Contains(html, "<script>") {
		t.Fatalf("title not escaped — tag injection possible: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected escaped entity: %s", html)
	}
	if !strings.Contains(html, "a &amp; b &gt; c") {
		t.Fatalf("& and > not escaped: %s", html)
	}
	// The deep link is admin-configured public_base_url — fairly trusted — but attribute
	// position must still escape quotes, or a quoted address closes the href and injects an
	// event handler.
	if strings.Contains(html, `onmouseover=alert(1)">`) {
		t.Fatalf("href attribute not properly escaped: %s", html)
	}
	if !strings.Contains(html, "&quot;") {
		t.Fatalf("quotes in attribute position should be escaped: %s", html)
	}
}

func mustExtractHeader(t *testing.T, msg, name string) string {
	t.Helper()
	for _, line := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(line, name+": ") {
			return strings.TrimPrefix(line, name+": ")
		}
	}
	t.Fatalf("header %s not found", name)
	return ""
}

func TestChannelValidateReportsMissingFields(t *testing.T) {
	// Validation errors go straight to the configurer — they must say what's missing, not a
	// generic 'invalid config'.
	cases := []struct {
		kind   string
		cfg    map[string]any
		substr string
	}{
		{KindDingTalk, map[string]any{}, "webhook"},
		{KindFeishu, map[string]any{}, "webhook"},
		{KindWeCom, map[string]any{}, "webhook"},
		{KindTelegram, map[string]any{}, "bot token"},
		{KindTelegram, map[string]any{"bot_token": "t"}, "chat ID"},
		{KindEmail, map[string]any{}, "SMTP"},
		{KindEmail, map[string]any{"host": "h"}, "port"},
		{KindEmail, map[string]any{"host": "h", "port": 587, "from": "f"}, "recipient"},
	}
	for _, tc := range cases {
		ch, ok := Get(tc.kind)
		if !ok {
			t.Fatalf("channel %s not registered", tc.kind)
		}
		err := ch.Validate(tc.cfg)
		if err == nil {
			t.Errorf("%s config %v should fail validation", tc.kind, tc.cfg)
			continue
		}
		if !strings.Contains(err.Error(), tc.substr) {
			t.Errorf("%s error should mention %q, got %q", tc.kind, tc.substr, err.Error())
		}
	}
}

// TestEmailSMTPErrorClassification pins the SMTP 4xx/5xx semantic split.
// If 4xx counted as permanent, a greylisting mail server would drop every push into
// failed on first attempt — exactly where automatic retries matter most.
func TestEmailSMTPErrorClassification(t *testing.T) {
	cases := []struct {
		reply     string
		permanent bool
	}{
		{"450 4.7.1 Greylisting in action, please come back later", false},
		{"451 4.3.0 Temporary system failure", false},
		{"452 4.2.2 Mailbox full", false},
		{"550 5.1.1 User unknown", true},
		{"553 5.1.3 Bad address syntax", true},
		{"554 5.7.1 Relay access denied", true},
		// No parseable reply code → retriable: one extra try beats condemning a transient
		// fault to permanent.
		{"unexpected EOF", false},
		{"", false},
	}
	for _, tc := range cases {
		err := smtpStageError("recipient rejected", errors.New(tc.reply))
		if got := IsPermanent(err); got != tc.permanent {
			t.Errorf("reply %q: want permanent=%v got %v", tc.reply, tc.permanent, got)
		}
		// Whatever the class, the original text survives for the operator.
		if tc.reply != "" && !strings.Contains(err.Error(), tc.reply) {
			t.Errorf("reply %q's original text dropped: %v", tc.reply, err)
		}
	}
}

func TestRegistryCoversAllKinds(t *testing.T) {
	// All six channels must exist — a missing one silently disappears from the UI dropdown.
	want := []string{KindDingTalk, KindEmail, KindFeishu, KindTelegram, KindWebhook, KindWeCom}
	got := Kinds()
	if len(got) != len(want) {
		t.Fatalf("channel count should be %d, got %d: %v", len(want), len(got), got)
	}
	for _, k := range want {
		if !ValidKind(k) {
			t.Errorf("channel %s not registered", k)
		}
		if ch, ok := Get(k); !ok || ch.Kind() != k {
			t.Errorf("channel %s's Kind() doesn't match its registry key", k)
		}
	}
	if ValidKind("nope") {
		t.Error("unregistered kinds must fail validation")
	}
}

func TestPermanentErrorUnwrap(t *testing.T) {
	base := &permanentSentinel{}
	err := Permanent(base)
	if !IsPermanent(err) {
		t.Fatal("should be recognized as permanent")
	}
	if !strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("error should pass the underlying cause through: %v", err)
	}
	if Permanent(nil) != nil {
		t.Fatal("Permanent(nil) must return nil")
	}
	if IsPermanent(nil) {
		t.Fatal("nil is not a permanent failure")
	}
}

type permanentSentinel struct{}

func (*permanentSentinel) Error() string { return "sentinel" }
