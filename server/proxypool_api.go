// Proxy-pool API: CRUD + bulk import + connectivity checks + proactive health checks.
//
// Persistence stays in settings (proxy_pool_entries JSONB + proxy_pool_strategy); the
// in-memory state is pushed atomically via Traffic.SetProxyPool. Bulk import and
// verification fix the old page's 'add one line at a time, can't see which are dead,
// can't filter' problem; health checks are a background goroutine upgrading 'circuit-
// break after 5 consecutive failures' to 'break immediately on a detected dead one'.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pgdb "github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/traffic"
	"golang.org/x/net/proxy"
)

const (
	settingProxyPoolEntries    = "proxy_pool_entries"
	settingProxyPoolStrategy   = "proxy_pool_strategy"
	settingProxyCheckTarget    = "proxypool_check_target"
	settingProxyHealthMinutes  = "proxypool_health_minutes"
	settingProxyHealthCooldown = "proxypool_health_cooldown_minutes"
)

const (
	defaultProxyCheckTarget    = "https://api.ipify.org?format=json"
	defaultProxyHealthMinutes  = 10 // 0 = disable proactive health checks
	defaultProxyHealthCooldown = 30 // cooldown for proactive circuit-breaking (minutes)
	defaultProxyCheckTimeout   = 8 * time.Second
	proxyCheckConcurrency      = 8
)

// proxyPoolState is the persisted pool config. URLs are stored in plaintext (same tier
// as LLM-config passwords — the settings table isn't exposed); output is masked.
type proxyPoolState struct {
	Entries  []traffic.PoolEntry `json:"entries"`
	Strategy string              `json:"strategy"`
}

func (s *Server) loadProxyPool() *proxyPoolState {
	return loadProxyPoolState(s.m.pg)
}
func loadProxyPoolState(pg *pgdb.DB) *proxyPoolState {
	st := proxyPoolState{Strategy: "round_robin"}
	if raw, ok, _ := pg.GetSetting(settingProxyPoolEntries); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	if v, ok, _ := pg.GetSetting(settingProxyPoolStrategy); ok && v != "" {
		st.Strategy = v
	}
	if st.Entries == nil {
		st.Entries = []traffic.PoolEntry{}
	}
	return &st
}

func (s *Server) saveProxyPool(st proxyPoolState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := s.m.pg.SetSetting(settingProxyPoolEntries, string(raw)); err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingProxyPoolStrategy, st.Strategy)
}

// proxyPoolGet returns the current config (with runtime state: circuit-break count /
// mask / latest verification).
func (s *Server) proxyPoolGet(w http.ResponseWriter, r *http.Request) {
	st := s.loadProxyPool()
	running := []traffic.PoolEntry{}
	if t := s.m.traffic; t != nil {
		running = t.ProxyPoolStatus()
	}
	s.m.proxyCheckMu.Lock()
	last := s.m.proxyCheckLast
	s.m.proxyCheckMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"entries":         st.Entries,
		"strategy":        st.Strategy,
		"running":         running,
		"capturing":       s.m.TrafficEnabled(),
		"check_target":    settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
		"health_minutes":  intSetting(s.m.pg, settingProxyHealthMinutes, defaultProxyHealthMinutes),
		"health_cooldown": intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown),
		"last_check":      last,
	})
}

// settingOr reads a string setting, defaulting on missing/empty.
func settingOr(pg *pgdb.DB, key, def string) string {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// proxyPoolPut replaces the config wholesale and hot-applies it.
func (s *Server) proxyPoolPut(w http.ResponseWriter, r *http.Request) {
	var in proxyPoolState
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.Entries == nil {
		in.Entries = []traffic.PoolEntry{}
	}
	// validate: URL parses, weight floor, name dedupe wiggle-room
	seen := map[string]bool{}
	for i := range in.Entries {
		e := &in.Entries[i]
		if _, err := traffic.ValidateProxyURL(e.URL); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if e.Weight < 1 {
			e.Weight = 1
		}
		if seen[e.URL] {
			writeErr(w, 400, "duplicate proxy URL: "+e.URL)
			return
		}
		seen[e.URL] = true
	}
	if t := s.m.traffic; t != nil {
		if err := t.SetProxyPool(in.Entries, in.Strategy); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if err := s.saveProxyPool(in); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.proxyPoolGet(w, r)
}

// --- bulk import ---

type proxyBulkInvalid struct {
	Line   int    `json:"line"`
	Raw    string `json:"raw"`
	Reason string `json:"reason"`
}

// parseProxyLine parses one proxy line. Supported shapes (common formats exported from
// paid proxy sites):
//
//	1.2.3.4:8080
//	http://1.2.3.4:8080  /  socks5://user:pass@1.2.3.4:1080
//	1.2.3.4:8080:user:pass
//	name | 1.2.3.4:8080     (name separated by a pipe, avoiding colon ambiguity with the URL)
//	lines starting with # or blank = comments
//
// a missing scheme defaults to http — socks5 must be written explicitly or it gets
// dialed as an http proxy and fails.
func parseProxyLine(raw string) (name, u string, comment bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", "", true, nil
	}
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return "", "", true, nil
	}
	if i := strings.Index(line, "|"); i >= 0 {
		name = strings.TrimSpace(line[:i])
		line = strings.TrimSpace(line[i+1:])
	}
	// host:port:user:pass (the most common paid-provider export format)
	if strings.Count(line, ":") == 3 && !strings.Contains(line, "://") {
		parts := strings.SplitN(line, ":", 4)
		if strings.Contains(parts[0], ".") && parts[1] != "" {
			u = fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
			return name, u, false, nil
		}
	}
	if !strings.Contains(line, "://") {
		line = "http://" + line
	}
	if _, err := url.Parse(line); err != nil {
		return name, line, false, err
	}
	return name, line, false, nil
}

// proxyPoolBulk bulk-imports. mode=append (default) appends, replace swaps wholesale.
// Returns per-line results so the frontend can pinpoint exactly which line failed.
func (s *Server) proxyPoolBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text     string `json:"text"`
		Mode     string `json:"mode"`
		Strategy string `json:"strategy"`
		Weight   int    `json:"weight"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Mode == "" {
		req.Mode = "append"
	}
	if req.Mode != "append" && req.Mode != "replace" {
		writeErr(w, 400, "mode must be append or replace")
		return
	}
	weight := req.Weight
	if weight < 1 {
		weight = 1
	}

	st := s.loadProxyPool()
	if req.Mode == "replace" {
		st.Entries = []traffic.PoolEntry{}
	}
	byURL := map[string]int{}
	for i, e := range st.Entries {
		byURL[e.URL] = i
	}

	var invalid []proxyBulkInvalid
	added, updated := 0, 0
	lines := strings.Split(req.Text, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		name, raw, isComment, _ := parseProxyLine(ln)
		if isComment {
			continue
		}
		norm, verr := traffic.ValidateProxyURL(raw)
		if verr != nil {
			invalid = append(invalid, proxyBulkInvalid{Line: i + 1, Raw: strings.TrimSpace(ln), Reason: verr.Error()})
			continue
		}
		if name == "" {
			name = norm.Host
		}
		key := norm.String()
		if idx, ok := byURL[key]; ok {
			st.Entries[idx].Name = name
			st.Entries[idx].Enabled = true
			if st.Entries[idx].Weight < 1 {
				st.Entries[idx].Weight = weight
			}
			updated++
			continue
		}
		st.Entries = append(st.Entries, traffic.PoolEntry{
			URL: key, Name: name, Enabled: true, Weight: weight,
		})
		byURL[key] = len(st.Entries) - 1
		added++
	}
	if req.Strategy != "" {
		st.Strategy = req.Strategy
	}
	if t := s.m.traffic; t != nil {
		if err := t.SetProxyPool(st.Entries, st.Strategy); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if err := s.saveProxyPool(*st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "added": added, "updated": updated, "invalid": invalid,
		"total": len(st.Entries),
	})
}

// --- connectivity verification ---

type proxyCheckResult struct {
	Index     int    `json:"index"`
	URL       string `json:"url"` // masked
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checked_at"`
}

// proxyPoolCheck verifies the real usability of given (or all) proxies. Results write
// back into in-memory last_ok/last_fail, and failures circuit-break immediately — the
// 'one-click keep only working' filter builds on these results.
func (s *Server) proxyPoolCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URLs        []string `json:"urls"` // empty = all enabled entries
		Target      string   `json:"target"`
		TimeoutSec  int      `json:"timeout_seconds"`
		BreakOnFail bool     `json:"break_on_fail"`
	}
	_ = decode(r, &req)
	st := s.loadProxyPool()
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = defaultProxyCheckTimeout
	}

	want := map[string]bool{}
	for _, u := range req.URLs {
		want[u] = true
	}
	selected := st.Entries
	if len(want) > 0 {
		selected = nil
		for _, e := range st.Entries {
			if want[e.URL] {
				selected = append(selected, e)
			}
		}
	}
	results := make([]proxyCheckResult, len(selected))
	sem := make(chan struct{}, proxyCheckConcurrency)
	var wg sync.WaitGroup
	for i, e := range selected {
		// masked URLs for echo only; real credentials are used solely at request time.
		masked := maskProxy(e.URL)
		wg.Add(1)
		go func(idx int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneProxy(context.Background(), idx, echo, entry.URL, target, timeout)
		}(i, e, masked)
	}
	wg.Wait()

	// write verification results back into pool state (success resets the fail streak;
	// failure circuit-breaks as needed) so the next Pick avoids the dead egress at
	// once, while the page's last_ok/last_fail refresh.
	t := s.m.traffic
	cooldown := time.Duration(intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	for i, res := range results {
		if t == nil {
			continue
		}
		raw := selected[i].URL
		if res.OK {
			t.ProxyPoolReportOK(raw)
		} else if req.BreakOnFail {
			t.ProxyPoolMarkBad(raw, cooldown)
		} else {
			t.ProxyPoolReportFail(raw)
		}
	}

	// record a 'last checked' timestamp for the UI.
	s.m.proxyCheckMu.Lock()
	s.m.proxyCheckLast = map[string]any{
		"at":       time.Now().Format(time.RFC3339),
		"target":   target,
		"count":    len(results),
		"ok_count": countOK(results),
	}
	s.m.proxyCheckMu.Unlock()

	writeJSON(w, 200, map[string]any{
		"target":  target,
		"results": results,
	})
}

func countOK(list []proxyCheckResult) int {
	n := 0
	for _, r := range list {
		if r.OK {
			n++
		}
	}
	return n
}

// s_probeAll verifies a batch of upstreams concurrently. Manual verification and the
// background health check share one probe implementation — both paths must agree on
// 'what usable means', or the page shows usable while traffic actually fails.
func s_probeAll(ctx context.Context, m *Manager, entries []traffic.PoolEntry, target string) []proxyCheckResult {
	results := make([]proxyCheckResult, len(entries))
	sem := make(chan struct{}, proxyCheckConcurrency)
	var wg sync.WaitGroup
	for i, e := range entries {
		masked := maskProxy(e.URL)
		wg.Add(1)
		go func(idx int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneProxy(ctx, idx, echo, entry.URL, target, defaultProxyCheckTimeout)
		}(i, e, masked)
	}
	wg.Wait()
	return results
}

// checkOneProxy requests target via this proxy, recording latency and egress IP.
func checkOneProxy(ctx context.Context, idx int, masked, raw, target string, timeout time.Duration) proxyCheckResult {
	res := proxyCheckResult{Index: idx, URL: masked, CheckedAt: time.Now().Format(time.RFC3339)}
	proxyURL, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	transport := &http.Transport{}
	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		// SOCKS5 dials via x/net/proxy: http.Transport only knows HTTP proxies.
		transport.Proxy = nil
		transport.DialContext = func(c context.Context, network, addr string) (net.Conn, error) {
			return socksDial(c, proxyURL, addr)
		}
	default:
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	hc := &http.Client{Timeout: timeout, Transport: transport}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, target, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	start := time.Now()
	resp, err := hc.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	res.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
	if !res.OK {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	res.ExitIP = extractIP(string(body))
	return res
}

// socksDial dials addr through a SOCKS5 proxy.
func socksDial(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth = &proxy.Auth{User: proxyURL.User.Username(), Password: pass}
	}
	dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return dialer.Dial("tcp", addr)
}

// extractIP pulls the egress IP from the probe response (left blank when absent — it
// doesn't affect the usability verdict).
func extractIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, key := range []string{`"ip"`, `"origin"`, `"query"`} {
		if i := strings.Index(s, key); i >= 0 {
			rest := s[i+len(key):]
			if j := strings.IndexAny(rest, "\"'"); j >= 0 {
				rest = rest[j+1:]
			}
			if k := strings.IndexAny(rest, "\"'} \n"); k >= 0 {
				rest = rest[:k]
			}
			if looksLikeIP(rest) {
				return rest
			}
		}
	}
	if looksLikeIP(s) {
		return s
	}
	return ""
}

func looksLikeIP(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

// maskProxy hides credentials — display-only.
func maskProxy(raw string) string {
	u, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		return raw
	}
	return u.String()
}
