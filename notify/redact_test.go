package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// This file is the invariant test: **no** error text surfacing from a channel
// implementation may carry credentials.
//
// Why a separate file: the original channel cases covered success paths and platform
// business errors only — transport-layer failures went unexamined. Yet transport errors
// (connection refused / DNS failure / timeout) are the most dangerous: the *url.Error
// returned by http.Client.Do embeds the **full URL**, and in this feature credentials live
// in URLs. The credential flowed out through four exits:
//
//	notification_deliveries.last_error  → persisted in plaintext
//	GET /api/notify/deliveries response → bypasses config masking, echoed to the browser
//	server logs                         → often exported and retained
//	the test-send endpoint's 502        → popped straight into the frontend
//
// So instead of one function, each channel here really fires a doomed request, and the
// error text is asserted free of the credential.

// credentialCases covers every 'credential-in-URL' channel shape: dingtalk/wecom in the
// query, feishu at the path tail, Telegram mid-path.
var credentialCases = []struct {
	name   string
	ch     Channel
	cfg    map[string]any
	secret string
}{
	{
		name:   "dingtalk access_token in query",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send?access_token=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "WeCom key in query",
		ch:     weComChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/cgi-bin/webhook/send?key=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "feishu hook id at path tail",
		ch:     feishuChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/open-apis/bot/v2/hook/" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "Telegram bot token mid-path",
		ch:     telegramChannel{},
		cfg:    map[string]any{"bot_token": leakProbeToken, "chat_id": "1", "base_url": "http://127.0.0.1:1"},
		secret: leakProbeToken,
	},
	{
		name:   "dingtalk signing secret",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send", "secret": leakProbeToken},
		secret: leakProbeToken,
	},
}

// leakProbeToken is a sentinel that can never be a real credential — searched for in error text.
const leakProbeToken = "LEAKPROBE0123456789abcdef"

// TestChannelErrorsNeverLeakCredentials is the core invariant.
func TestChannelErrorsNeverLeakCredentials(t *testing.T) {
	for _, tc := range credentialCases {
		t.Run(tc.name, func(t *testing.T) {
			// a doomed peer: nothing listens on 127.0.0.1:1 — the connection-refused path.
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{
				Items: []Item{{FindingID: 1, Severity: "high", Name: "leak probe"}},
			})
			if err == nil {
				t.Fatal("an unreachable address should error")
			}
			assertNoSecret(t, err.Error(), tc.secret)
		})
	}
}

// TestChannelErrorsNeverLeakCredentialsInPermanentPath covers the permanent-failure
// branch: URL validation failures, platform business errors etc. also export error text —
// equally forbidden from carrying credentials.
func TestChannelErrorsNeverLeakCredentialsInPermanentPath(t *testing.T) {
	cases := []struct {
		name string
		ch   Channel
		cfg  map[string]any
	}{
		// credential-bearing but malformed URL → hits the validateHTTPURL / url.Parse branch.
		{"dingtalk bad URL", dingTalkChannel{}, map[string]any{"webhook": "file:///" + leakProbeToken}},
		{"wecom bad URL", weComChannel{}, map[string]any{"webhook": "gopher://" + leakProbeToken}},
		{"feishu bad URL", feishuChannel{}, map[string]any{"webhook": "ftp://" + leakProbeToken + "/hook"}},
		{"Telegram API bad URL", telegramChannel{}, map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": "file://" + leakProbeToken}},
		{"generic webhook bad URL", webhookChannel{}, map[string]any{"url": "javascript:" + leakProbeToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{Items: []Item{{Severity: "high"}}})
			if err == nil {
				t.Fatal("invalid config should error")
			}
			assertNoSecret(t, err.Error(), leakProbeToken)
		})
	}
}

func assertNoSecret(t *testing.T, text, secret string) {
	t.Helper()
	if strings.Contains(text, secret) {
		t.Fatalf("error text leaks credential %q:\n    %s", secret, text)
	}
}

func TestRedactRequestTargetKeepsOnlySchemeAndHost(t *testing.T) {
	cases := map[string]string{
		"https://oapi.dingtalk.com/robot/send?access_token=S1":    "https://oapi.dingtalk.com/…",
		"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=S2": "https://qyapi.weixin.qq.com/…",
		"https://open.feishu.cn/open-apis/bot/v2/hook/S3":         "https://open.feishu.cn/…",
		"https://api.telegram.org/botS4/sendMessage":              "https://api.telegram.org/…",
		"http://10.0.0.5:8080/hook":                               "http://10.0.0.5:8080/…",
	}
	for in, want := range cases {
		got := redactRequestTarget(in)
		if got != want {
			t.Errorf("redactRequestTarget(%q) = %q, want %q", in, got, want)
		}
		// the redacted result must not retain any path/query fragment of the original URL.
		if parts := strings.SplitN(in, "://", 2); len(parts) == 2 {
			if hostAndRest := strings.SplitN(parts[1], "/", 2); len(hostAndRest) == 2 && hostAndRest[1] != "" {
				if strings.Contains(got, hostAndRest[1]) {
					t.Errorf("path/query fragment %q survives redaction: %q", hostAndRest[1], got)
				}
			}
		}
	}
	// unparseable input is never echoed back.
	for _, bad := range []string{"", "://", "not a url", "http://"} {
		if got := redactRequestTarget(bad); strings.Contains(got, bad) && bad != "" {
			t.Errorf("unparseable input %q echoed as %q", bad, got)
		}
	}
}

// TestRedactTransportErrorStripsURL targets *url.Error specifically: it is the return
// type of http.Client.Do and the first scene of the leak.
func TestRedactTransportErrorStripsURL(t *testing.T) {
	inner := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	uerr := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/bot" + leakProbeToken + "/sendMessage",
		Err: inner,
	}
	got := redactTransportError(uerr)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "api.telegram.org") {
		t.Errorf("host should be kept for diagnosis, got %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("the underlying cause should be kept for diagnosis, got %q", got)
	}
	// Op is kept too (POST vs GET matters when diagnosing).
	if !strings.Contains(got, "Post") {
		t.Errorf("operation name should be kept, got %q", got)
	}
}

// TestRedactURLsInTextHandlesFallback covers the fallback path: custom non-*url.Error
// errors (e.g. from the redirect policy) get their URLs stripped too.
func TestRedactURLsInTextHandlesFallback(t *testing.T) {
	in := fmt.Sprintf("cross-host redirect refused (a.example → http://b.example/bot%s/send)", leakProbeToken)
	got := redactURLsInText(in)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "http://b.example/…") {
		t.Errorf("the URL should be replaced by its redacted form, got %q", got)
	}
	// URL-free text passes through unchanged.
	if plain := "dial tcp: connection refused"; redactURLsInText(plain) != plain {
		t.Error("URL-free text must not be altered")
	}
}

// TestCrossHostRedirectRefused covers 'credential in URL + cross-host redirect followed
// = credential handed over'. The two httptest servers listen on different 127.0.0.1
// ports — different ports means different Hosts, a cross-host redirect.
func TestCrossHostRedirectRefused(t *testing.T) {
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/robot/send?access_token="+leakProbeToken, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": redirector.URL + "/robot/send?access_token=" + leakProbeToken},
		Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("cross-host redirect should be refused")
	}
	if hit {
		t.Fatal("redirect target was hit — the credential leaked with the redirect")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestSameHostRedirectAllowed is the counter case: same-host redirects (like a trailing
// slash) must still work, or normal workflows get blocked too.
func TestSameHostRedirectAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robot/send" {
			// same-host, same-port redirect.
			http.Redirect(w, r, "/robot/send/", http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"},
		Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("same-host redirect must not be refused: %v", err)
	}
}
