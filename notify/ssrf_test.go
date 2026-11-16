package notify

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// This file covers two related hardenings:
//   1) delivery URLs must not turn the server into a springboard for intranet / cloud-metadata hits (SSRF)
//   2) URL-validation error text must not echo credentials embedded in the URL
//
// About the test env: many cases here use httptest fakes on 127.0.0.1, which the guard
// blocks by default. TestMain enables AllowLocalTargetsEnv globally, and every SSRF case
// below explicitly clears it to assert **default-deny** behavior.

func TestMain(m *testing.M) {
	// lets ordinary cases reach the local fake receivers; SSRF cases clear it themselves.
	_ = os.Setenv(AllowLocalTargetsEnv, "1")
	os.Exit(m.Run())
}

// TestDialGuardRejectsLoopbackByDefault is the SSRF guard's core assertion: with default
// config, delivery to loopback must be refused at the **connection layer**.
func TestDialGuardRejectsLoopbackByDefault(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "") // escape hatch off = default behavior
	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("loopback delivery must not be allowed by default")
	}
	if hit {
		t.Fatal("request reached the local service — the guard did nothing")
	}
	// the error must tell the user how to opt in (a local SMTP relay is legitimate).
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("the refusal should explain how to opt in explicitly: %v", err)
	}
}

// TestDialGuardAllowsLoopbackWhenOptedIn is the counter case: explicit opt-in must work —
// else legitimate setups like a local postfix / intranet relay get blanket-killed.
func TestDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("delivery should work after explicit opt-in: %v", err)
	}
}

func TestIsBlockedDialIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1",
		"169.254.169.254", // cloud metadata endpoint — the main reason this function exists
		"169.254.1.1", "fe80::1",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
		"::ffff:127.0.0.1", // IPv4-mapped form must be normalized before judging — else it's a bypass
		"",
	}
	for _, s := range blocked {
		if !isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be rejected", s)
		}
	}
	// RFC1918 private nets are **deliberately allowed**: self-hosted Mattermost / SMTP
	// relays on the LAN are common legitimate use. This assertion pins that trade-off —
	// if someone later adds private-net blocking casually, this fails, forcing a
	// conscious decision (instead of silently killing a class of deployments).
	allowed := []string{"10.0.0.5", "172.16.3.4", "192.168.1.10", "8.8.8.8", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed (private nets are common legitimate targets)", s)
		}
	}
}

// TestValidateHTTPURLRejectsLiteralPrivateTargets covers the config-time heads-up:
// literal IPs should be refused at save, not wait for the first failed delivery.
func TestValidateHTTPURLRejectsLiteralPrivateTargets(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "")
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8080/hook",
	} {
		if err := validateHTTPURL(raw); err == nil {
			t.Errorf("%s should be rejected at config time", raw)
		}
	}
	// public and private addresses pass (private is left to the dial stage, which doesn't block).
	for _, raw := range []string{"https://oapi.dingtalk.com/robot/send", "http://10.0.0.9/hook"} {
		if err := validateHTTPURL(raw); err != nil {
			t.Errorf("%s should pass validation: %v", raw, err)
		}
	}
}

// TestValidateHTTPURLErrorNeverLeaksCredentials is the branch the audit flagged as
// missed last round.
//
// When url.Parse **fails** it returns *url.Error whose Error() contains the full raw
// URL. Last round only http.Client.Do errors were redacted — this one was missed; and the
// 'permanent-failure path' cases added then (file://, gopher://, ftp://) all parse fine
// and take the scheme branch, so all-green proved nothing about this path — a false
// guarantee.
func TestValidateHTTPURLErrorNeverLeaksCredentials(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/%zz?access_token=" + leakProbeToken,         // illegal percent-escape
		"https://a.example.com:port/x?access_token=" + leakProbeToken, // non-numeric port
		"http://[::1?access_token=" + leakProbeToken,                  // unbalanced bracket
	}
	for _, raw := range cases {
		// first confirm the input **really** makes url.Parse fail. Skip this and the case
		// could silently exercise another branch (that's how last round's false guarantee happened).
		if _, err := url.Parse(raw); err == nil {
			t.Errorf("%q should have failed parsing — else this case doesn't cover the target branch", raw)
			continue
		}
		err := validateHTTPURL(raw)
		if err == nil {
			t.Errorf("%q should fail validation", raw)
			continue
		}
		assertNoSecret(t, err.Error(), leakProbeToken)
	}
	// confirm the channel-level wrapper doesn't leak the URL either.
	t.Setenv(AllowLocalTargetsEnv, "")
	err := (dingTalkChannel{}).Validate(map[string]any{"webhook": cases[0]})
	if err == nil {
		t.Fatal("invalid URL should fail validation")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestEmailDialGuardRejectsLoopbackByDefault covers the SMTP channel's dial guard.
//
// The email channel once used a bare net.Dialer — the only gap in the whole SSRF defense:
// host set to 169.254.169.254 or 127.0.0.1 connected straight through, and when
// smtp.NewClient's handshake failed it wrapped the peer's reply line into the error, echoed
// via last_error through the delivery-history API — exactly the half-blind read primitive
// the other channels had closed; the 'refused vs timeout' timing gap even allowed port
// probing.
//
// This package's TestMain globally enables AllowLocalTargetsEnv (many cases use fake
// receivers on 127.0.0.1), so this case must clear it itself — otherwise it passes whether
// the guard exists or not, which is exactly why the gap went unnoticed by any test.
func TestEmailDialGuardRejectsLoopbackByDefault(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "") // escape hatch off = default behavior
	_, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil {
		t.Fatal("email delivery to loopback must not be allowed by default")
	}
	// the connection should never establish: the guard intercepts in the Control hook, so EHLO never goes out.
	if f.sawCommand("EHLO") || f.sawCommand("HELO") {
		t.Fatal("SMTP session was established — the guard did nothing")
	}
	// the error must tell the user how to opt in (a local postfix relay is legitimate).
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("the refusal should explain how to opt in explicitly: %v", err)
	}
}

// TestEmailDialGuardAllowsLoopbackWhenOptedIn is the paired counter case: after explicit
// opt-in delivery must work. Self-hosted intranet SMTP / local relays are very common
// deployments — the guard can't blanket-ban them.
func TestEmailDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("local SMTP should deliver after explicit opt-in: %v", err)
	}
	if !f.sawCommand("EHLO") {
		t.Fatal("no EHLO seen — the session never really established")
	}
}
