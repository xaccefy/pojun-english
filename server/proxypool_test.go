package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Bulk-import line parsing: users export from paid providers in all sorts of formats; the parser must recognize the common ones,
// and not treat comments/blank lines as entries.
func TestParseProxyLine(t *testing.T) {
	cases := []struct {
		raw      string
		wantURL  string
		wantName string
		comment  bool
	}{
		{"1.2.3.4:8080", "http://1.2.3.4:8080", "", false},
		{"http://1.2.3.4:8080", "http://1.2.3.4:8080", "", false},
		{"socks5://user:pass@5.6.7.8:1080", "socks5://user:pass@5.6.7.8:1080", "", false},
		{"1.2.3.4:8080:user:pass", "http://user:pass@1.2.3.4:8080", "", false},
		{"HK-01 | 1.2.3.4:8080", "http://1.2.3.4:8080", "HK-01", false},
		{"# comment", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		name, u, comment, err := parseProxyLine(c.raw)
		if err != nil {
			t.Errorf("parseProxyLine(%q) err=%v", c.raw, err)
			continue
		}
		if comment != c.comment {
			t.Errorf("parseProxyLine(%q) comment=%v want %v", c.raw, comment, c.comment)
		}
		if c.comment {
			continue
		}
		if u != c.wantURL {
			t.Errorf("parseProxyLine(%q) url=%q want %q", c.raw, u, c.wantURL)
		}
		if name != c.wantName {
			t.Errorf("parseProxyLine(%q) name=%q want %q", c.raw, name, c.wantName)
		}
	}
}

// Bulk import must identify invalid lines and report them line by line, instead of failing the whole batch.
func TestProxyPoolBulkReportsInvalidLines(t *testing.T) {
	m, err := NewManager(tempDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	// This case tests line parsing; socks5 has been refused by the scheme policy by default since v0.6.32, so enable it explicitly.
	oldAllow, hadAllow, _ := m.pg.GetSetting(settingProxyAllowSocks5)
	if err := m.pg.SetSetting(settingProxyAllowSocks5, "true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadAllow {
			_ = m.pg.SetSetting(settingProxyAllowSocks5, oldAllow)
		} else {
			_ = m.pg.SetSetting(settingProxyAllowSocks5, "false")
		}
	})

	body, _ := json.Marshal(map[string]any{
		"text": "# comment\n1.2.3.4:8080\nsocks5://u:p@5.6.7.8:1080\n",
		"mode": "replace",
		// This case only tests "line parsing / invalid-line reporting", so import verification is off (otherwise these fake addresses get judged unreachable and dropped).
		"verify": false,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Added   int `json:"added"`
		Invalid []struct {
			Line   int    `json:"line"`
			Reason string `json:"reason"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Added != 2 {
		t.Errorf("added=%d want 2", res.Added)
	}
	// "not a url at all" contains spaces and is not a valid host:port, so it must be judged invalid.
	bad := "not a url at all"
	body, _ = json.Marshal(map[string]any{"text": bad, "mode": "replace", "verify": false})
	req = httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(body))
	w = httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	res.Invalid = nil
	res.Added = 0
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Invalid) != 1 {
		t.Fatalf("invalid=%+v want 1 entry", res.Invalid)
	}
	if res.Invalid[0].Line != 1 {
		t.Errorf("line=%d want 1", res.Invalid[0].Line)
	}
	if res.Invalid[0].Reason == "" {
		t.Error("invalid lines must include a reason")
	}
}

// Proxy-pool connectivity check: a good proxy is judged usable, a bad one unusable.
// Use a local HTTP proxy as the "good proxy" and a local service as the probe target — no external network needed.
func TestProxyPoolCheckDistinguishesGoodAndBad(t *testing.T) {
	m, err := NewManager(tempDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	// target service
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer target.Close()
	// good proxy: forwards the request unchanged to the target
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse(target.URL)
		r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer good.Close()

	entries := []map[string]any{
		{"url": good.URL, "name": "good", "enabled": true, "weight": 1},
		{"url": "http://127.0.0.1:1", "name": "bad", "enabled": true, "weight": 1},
	}
	body, _ := json.Marshal(map[string]any{"entries": entries, "strategy": "round_robin"})
	req := httptest.NewRequest(http.MethodPut, "/api/proxypool", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.proxyPoolPut(w, req)
	if w.Code != 200 {
		t.Fatalf("put status=%d body=%s", w.Code, w.Body.String())
	}

	body, _ = json.Marshal(map[string]any{
		"target": target.URL, "break_on_fail": true, "timeout_seconds": 3,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/proxypool/check", bytes.NewReader(body))
	w = httptest.NewRecorder()
	s.proxyPoolCheck(w, req)
	if w.Code != 200 {
		t.Fatalf("check status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Results []struct {
			URL string `json:"url"`
			OK  bool   `json:"ok"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("results=%d want 2", len(res.Results))
	}
	okCount := 0
	for _, r := range res.Results {
		if r.OK {
			okCount++
		}
	}
	if okCount != 1 {
		t.Errorf("usable=%d want 1 (good proxy should pass, bad proxy should fail)", okCount)
	}
}

// Import verification (v0.6.26): unreachable proxies are not imported and get a per-line reason; usable ones are stored.
func TestProxyPoolBulkVerifiesAndDropsUnreachable(t *testing.T) {
	m, err := NewManager(tempDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer target.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer good.Close()
	// Point the probe target at the test server so the test doesn't depend on the internet.
	prevTarget, _, _ := m.pg.GetSetting(settingProxyCheckTarget)
	if err := m.pg.SetSetting(settingProxyCheckTarget, target.URL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if prevTarget == "" {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingProxyCheckTarget)
		} else {
			_ = m.pg.SetSetting(settingProxyCheckTarget, prevTarget)
		}
	})

	body, _ := json.Marshal(map[string]any{
		"text":                   good.URL + "\nhttp://127.0.0.1:1\n",
		"mode":                   "replace",
		"verify":                 true,
		"verify_timeout_seconds": 2,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Added    int  `json:"added"`
		Total    int  `json:"total"`
		Verified bool `json:"verified"`
		Rejected []struct {
			Line   int    `json:"line"`
			Reason string `json:"reason"`
		} `json:"rejected"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatalf("verified=false (verification should run) body=%s", w.Body.String())
	}
	if res.Added != 1 || res.Total != 1 {
		t.Fatalf("added=%d total=%d want 1/1 (the bad proxy should be dropped)", res.Added, res.Total)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Reason == "" {
		t.Fatalf("rejected=%+v want 1 entry with a reason", res.Rejected)
	}
	st := s.loadProxyPool()
	if len(st.Entries) != 1 || st.Entries[0].URL != good.URL {
		t.Fatalf("entries=%+v want only the good proxy left", st.Entries)
	}
}

// Master switch: off persists false, on restores it; the default (no such key) is on.
func TestProxyPoolEnableTogglePersists(t *testing.T) {
	m, err := NewManager(tempDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingProxyPoolEnabled) })

	put := func(enabled bool) map[string]any {
		body, _ := json.Marshal(map[string]any{
			"entries":  []map[string]any{{"url": "http://127.0.0.1:9", "name": "x", "enabled": true, "weight": 1}},
			"strategy": "round_robin", "enabled": enabled,
		})
		req := httptest.NewRequest(http.MethodPut, "/api/proxypool", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.proxyPoolPut(w, req)
		if w.Code != 200 {
			t.Fatalf("put status=%d body=%s", w.Code, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if got := put(false)["enabled"]; got != false {
		t.Fatalf("enabled=%v want false", got)
	}
	if st := s.loadProxyPool(); st.Enabled {
		t.Fatal("persisted enabled=true want false")
	}
	if got := put(true)["enabled"]; got != true {
		t.Fatalf("enabled=%v want true", got)
	}
}

// Vuln-intel error hints: "it broke but the page won't say why" was the original problem —
// This guarantees common errors translate into actionable advice.
func TestVulnIntelErrorHint(t *testing.T) {
	cases := []struct {
		err  string
		want string
	}{
		{"kev feed status 404: <!DOCTYPE html>", "404"},
		{"nvd api decode: context deadline exceeded", "timed out"},
		{"dial tcp: lookup www.cisa.gov: no such host", "DNS"},
		{"proxyconnect tcp: connection refused", "Proxy"},
		{"status 429: rate limit exceeded", "Rate-limited"},
	}
	for _, c := range cases {
		hint := vulnIntelErrorHint(c.err)
		if hint == "" {
			t.Errorf("vulnIntelErrorHint(%q) is empty", c.err)
			continue
		}
		if !bytes.Contains([]byte(hint), []byte(c.want)) {
			t.Errorf("vulnIntelErrorHint(%q)=%q, expected to contain %q", c.err, hint, c.want)
		}
	}
	if vulnIntelErrorHint("") != "" {
		t.Error("no advice should be given for an empty error")
	}
	_ = time.Second
}

// v0.8.0: socks5 upstreams are allowed by default (a common Clash/mihomo mixed-port exit). Only an explicit false refuses them.
func TestProxyPoolBulkAllowsSocks5ByDefault(t *testing.T) {
	m, err := NewManager(tempDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	old, had, _ := m.pg.GetSetting(settingProxyAllowSocks5)
	if err := m.pg.SetSetting(settingProxyAllowSocks5, "true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = m.pg.SetSetting(settingProxyAllowSocks5, old)
		}
	})
	body, _ := json.Marshal(map[string]any{
		"text": "socks5://u:p@5.6.7.8:1080\n", "mode": "replace", "verify": false,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Added   int `json:"added"`
		Invalid []struct {
			Reason string `json:"reason"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || len(res.Invalid) != 0 {
		t.Fatalf("socks5 should be allowed by default: added=%d invalid=%+v", res.Added, res.Invalid)
	}
}

func TestProxyPoolBulkRejectsSocks5WhenDisabled(t *testing.T) {
	m, err := NewManager(tempDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	old, had, _ := m.pg.GetSetting(settingProxyAllowSocks5)
	if err := m.pg.SetSetting(settingProxyAllowSocks5, "false"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = m.pg.SetSetting(settingProxyAllowSocks5, old)
		}
	})
	body, _ := json.Marshal(map[string]any{
		"text": "socks5://u:p@5.6.7.8:1080\n", "mode": "replace", "verify": false,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Added   int `json:"added"`
		Invalid []struct {
			Reason string `json:"reason"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Added != 0 || len(res.Invalid) != 1 {
		t.Fatalf("socks5 should be refused: added=%d invalid=%+v", res.Added, res.Invalid)
	}
	if !strings.Contains(res.Invalid[0].Reason, "socks5") {
		t.Fatalf("the refusal reason should mention socks5: %s", res.Invalid[0].Reason)
	}
}

// Saving an empty list silently wipes the whole pool: confirm_clear is mandatory, so a stale page can't wipe it by accident.
func TestProxyPoolPutRequiresConfirmToClear(t *testing.T) {
	m, err := NewManager(tempDir(t), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	seed, _ := json.Marshal(map[string]any{
		"entries":  []map[string]any{{"url": "http://127.0.0.1:9", "name": "keep", "enabled": true, "weight": 1}},
		"strategy": "round_robin",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/proxypool", bytes.NewReader(seed))
	w := httptest.NewRecorder()
	s.proxyPoolPut(w, req)
	if w.Code != 200 {
		t.Fatalf("seed status=%d body=%s", w.Code, w.Body.String())
	}

	empty, _ := json.Marshal(map[string]any{"entries": []any{}, "strategy": "round_robin"})
	req = httptest.NewRequest(http.MethodPut, "/api/proxypool", bytes.NewReader(empty))
	w = httptest.NewRecorder()
	s.proxyPoolPut(w, req)
	if w.Code != 400 {
		t.Fatalf("an unconfirmed clear should 400, got %d body=%s", w.Code, w.Body.String())
	}
	if got := len(s.loadProxyPool().Entries); got != 1 {
		t.Fatalf("after the refusal the pool should still hold 1 entry, got %d", got)
	}

	// A bulk import with mode=replace and empty text also must not clear the pool.
	bulk, _ := json.Marshal(map[string]any{"text": "   ", "mode": "replace"})
	req = httptest.NewRequest(http.MethodPost, "/api/proxypool/bulk", bytes.NewReader(bulk))
	w = httptest.NewRecorder()
	s.proxyPoolBulk(w, req)
	if w.Code != 400 {
		t.Fatalf("an empty replace import should 400, got %d body=%s", w.Code, w.Body.String())
	}
	if got := len(s.loadProxyPool().Entries); got != 1 {
		t.Fatalf("after the bulk refusal the pool should still hold 1 entry, got %d", got)
	}

	confirmed, _ := json.Marshal(map[string]any{"entries": []any{}, "strategy": "round_robin", "confirm_clear": true})
	req = httptest.NewRequest(http.MethodPut, "/api/proxypool", bytes.NewReader(confirmed))
	w = httptest.NewRecorder()
	s.proxyPoolPut(w, req)
	if w.Code != 200 {
		t.Fatalf("a confirmed clear should 200, got %d body=%s", w.Code, w.Body.String())
	}
}
