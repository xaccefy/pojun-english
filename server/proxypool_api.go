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
	"log"
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
	settingProxyPoolEnabled    = "proxy_pool_enabled"
	settingProxyBreaks         = "proxy_pool_break_state" // trip state kept across restarts (URL→release unix)
	settingProxyCheckTarget    = "proxypool_check_target"
	settingProxyHealthMinutes  = "proxypool_health_minutes"
	settingProxyHealthCooldown = "proxypool_health_cooldown_minutes"
	// settingProxyAllowSocks5: whether socks5 upstreams may enter the pool. go-mitmproxy used to
	// panic by calling Close() on a nil conn when socks5 dialing failed (fixed in v1.9.4). Allowed
	// by default from v0.8.0 — SOCKS5 is a common Clash/mihomo mixed-port exit, and refusing it by
	// default makes "import Clash nodes" look entirely broken. Only an explicit false/0 turns it off.
	settingProxyAllowSocks5 = "proxypool_allow_socks5"
)

const (
	defaultProxyCheckTarget    = "https://api.ipify.org?format=json"
	defaultProxyHealthMinutes  = 10 // 0 = disable proactive health checks
	defaultProxyHealthCooldown = 30 // cooldown for proactive circuit-breaking (minutes)
	defaultProxyCheckTimeout   = 8 * time.Second
	proxyCheckConcurrency      = 8
	// Import verification: higher concurrency and a shorter per-line timeout — the import is a
	// synchronous request, so even 240 lines must return within ~1 minute.
	importVerifyConcurrency = 32
	importVerifyTimeout     = 6 * time.Second
)

// proxyPoolState is the persisted pool config. URLs are stored in plaintext (same tier
// as LLM-config passwords — the settings table isn't exposed); output is masked.
type proxyPoolState struct {
	Entries  []traffic.PoolEntry `json:"entries"`
	Strategy string              `json:"strategy"`
	Enabled  bool                `json:"enabled"` // master switch: when false the pool takes no part in exit selection
}

func (s *Server) loadProxyPool() *proxyPoolState {
	return loadProxyPoolState(s.m.pg)
}
func loadProxyPoolState(pg *pgdb.DB) *proxyPoolState {
	st := proxyPoolState{Strategy: "round_robin", Enabled: true}
	if raw, ok, _ := pg.GetSetting(settingProxyPoolEntries); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	if v, ok, _ := pg.GetSetting(settingProxyPoolStrategy); ok && v != "" {
		st.Strategy = v
	}
	// The master switch is its own key: default on when old data lacks it (before the upgrade a pool
	// was "effective as soon as it had entries").
	if v, ok, err := pg.GetSetting(settingProxyPoolEnabled); err == nil && ok {
		st.Enabled = !(v == "false" || v == "0")
	}
	if st.Entries == nil {
		st.Entries = []traffic.PoolEntry{}
	}
	return &st
}

// socks5Allowed reads the "allow socks5 upstreams" switch (true by default from v0.8.0;
// only an explicit false/0 turns it off). The socks5 dial panic was fixed in v1.9.4.
func (s *Server) socks5Allowed() bool {
	if s == nil || s.m == nil || s.m.pg == nil {
		return true
	}
	v, ok, err := s.m.pg.GetSetting(settingProxyAllowSocks5)
	if err != nil || !ok {
		return true
	}
	v = strings.TrimSpace(strings.ToLower(v))
	return !(v == "0" || v == "false" || v == "off" || v == "no")
}

// validateProxyScheme applies the scheme policy after URL validation.
func (s *Server) validateProxyScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if (strings.EqualFold(u.Scheme, "socks5") || strings.EqualFold(u.Scheme, "socks5h")) && !s.socks5Allowed() {
		return fmt.Errorf("socks5 upstreams are disabled by default in this version (older versions panicked when socks5 dialing failed, and the handshake had no timeout). Use an http(s):// proxy instead, or enable proxypool_allow_socks5 in system settings if you really need socks5")
	}
	return nil
}

// effectivePoolEntries returns the entries actually pushed to the MITM and counts those blocked by the scheme policy.
func (s *Server) effectivePoolEntries(st *proxyPoolState) ([]traffic.PoolEntry, int) {
	if st == nil {
		return nil, 0
	}
	if s.socks5Allowed() {
		return st.Entries, 0
	}
	kept := make([]traffic.PoolEntry, 0, len(st.Entries))
	blocked := 0
	for _, e := range st.Entries {
		if u, err := url.Parse(e.URL); err == nil && (strings.EqualFold(u.Scheme, "socks5") || strings.EqualFold(u.Scheme, "socks5h")) {
			blocked++
			continue
		}
		kept = append(kept, e)
	}
	return kept, blocked
}

func (s *Server) saveProxyPool(st proxyPoolState) error {
	return saveProxyPoolState(s.m.pg, st)
}

// saveProxyPoolState is the package-level form of saveProxyPool, used by Manager startup auto-detection.
func saveProxyPoolState(pg *pgdb.DB, st proxyPoolState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := pg.SetSetting(settingProxyPoolEntries, string(raw)); err != nil {
		return err
	}
	if err := pg.SetSetting(settingProxyPoolStrategy, st.Strategy); err != nil {
		return err
	}
	enabled := "true"
	if !st.Enabled {
		enabled = "false"
	}
	return pg.SetSetting(settingProxyPoolEnabled, enabled)
}

// applyProxyPool pushes the config into runtime: with the master switch off it means "empty pool" (fall back to the global proxy/direct).
func (s *Server) applyProxyPool(st proxyPoolState) error {
	t := s.m.traffic
	if t == nil {
		return nil
	}
	entries, blocked := s.effectivePoolEntries(&st)
	if blocked > 0 {
		log.Printf("[proxypool] skipped %d socks5 upstreams (disabled by default; enable proxypool_allow_socks5 to allow them)", blocked)
	}
	var err error
	if !st.Enabled {
		err = t.SetProxyPool(nil, st.Strategy)
	} else {
		err = t.SetProxyPool(entries, st.Strategy)
	}
	if err != nil {
		return err
	}
	s.refreshAgentsForEgressChange()
	return nil
}

// refreshAgentsForEgressChange rebuilds the Agent while traffic capture is off: the exit address is
// baked into the worker's HTTP_PROXY at Agent creation, so a pool change needs a re-assembly to take
// effect. With capture on the proxy address is a constant (the MITM local port) and the pool is
// chosen per request in the MITM hook, so no rebuild is needed.
func (s *Server) refreshAgentsForEgressChange() {
	if s.m == nil || s.m.TrafficEnabled() {
		return
	}
	s.cfgMu.Lock()
	cfg, on := s.llmCfg, s.llmOn
	s.cfgMu.Unlock()
	if !on {
		return
	}
	if err := s.applyLLM(cfg); err != nil {
		log.Printf("[proxypool] rebuilding the Agent after an egress change failed: %v", err)
	}
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
	eff, socks5Blocked := s.effectivePoolEntries(st)
	writeJSON(w, 200, map[string]any{
		"entries":                st.Entries,
		"strategy":               st.Strategy,
		"enabled":                st.Enabled,
		"total":                  len(st.Entries),
		"effective_total":        len(eff),
		"socks5_blocked":         socks5Blocked,
		"socks5_allowed":         s.socks5Allowed(),
		"running":                running,
		"usable":                 s.usableProxyCount(running),
		"capturing":              s.m.TrafficEnabled(),
		"check_target":           settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
		"health_minutes":         intSetting(s.m.pg, settingProxyHealthMinutes, defaultProxyHealthMinutes),
		"health_cooldown":        intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown),
		"last_check":             last,
		"strict":                 s.m.traffic != nil && s.m.traffic.StrictEgress(),
		"direct_record_fallback": s.m.traffic != nil && s.m.traffic.DirectRecordFallback(),
		// effective_proxy is the exit the Agent/Bash/WebFetch actually gets right now (credentials
		// masked), so you can confirm "no direct fallback after configuring a proxy"; empty = direct.
		"effective_proxy": maskProxyURL(s.m.ProxyAddr()),
	})
}

// maskProxyURL masks the username/password in a proxy address for status-API echo.
func maskProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("***")
	return u.String()
}

// usableProxyCount counts entries not currently tripped (break_remaining==0 in running).
func (s *Server) usableProxyCount(running []traffic.PoolEntry) int {
	n := 0
	for _, e := range running {
		if e.BreakRemaining == 0 {
			n++
		}
	}
	return n
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
	// Enabled is a pointer to tell "absent" from "explicit false": old clients that omit it keep the current value.
	var in struct {
		Entries  []traffic.PoolEntry `json:"entries"`
		Strategy string              `json:"strategy"`
		Enabled  *bool               `json:"enabled"`
		Strict   *bool               `json:"strict"`
		// ConfirmClear explicitly confirms "clear a non-empty pool". With a stale page (failed GET /
		// old tab) a mistaken save with entries=[] silently wipes the pool, so the caller must confirm.
		ConfirmClear bool `json:"confirm_clear"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.Entries == nil {
		in.Entries = []traffic.PoolEntry{}
	}
	st := proxyPoolState{Entries: in.Entries, Strategy: in.Strategy, Enabled: true}
	prev := s.loadProxyPool()
	if len(st.Entries) == 0 && len(prev.Entries) > 0 && !in.ConfirmClear {
		writeErr(w, 400, "clearing the proxy pool needs confirm_clear=true (stops a stale page from wiping it); to merely disable, pass enabled=false")
		return
	}
	if st.Strategy == "" {
		st.Strategy = prev.Strategy
	}
	if in.Enabled != nil {
		st.Enabled = *in.Enabled
	} else {
		st.Enabled = prev.Enabled
	}
	// validate: URL parses, weight floor, name dedupe wiggle-room
	seen := map[string]bool{}
	for i := range st.Entries {
		e := &st.Entries[i]
		if _, err := traffic.ValidateProxyURL(e.URL); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := s.validateProxyScheme(e.URL); err != nil {
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
	if err := s.applyProxyPool(st); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.saveProxyPool(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// The strict-egress switch is independent of the pool entries: when explicitly passed it is persisted and applied at once (the page's "save and hot-apply").
	if in.Strict != nil && s.m.traffic != nil {
		val := "true"
		if !*in.Strict {
			val = "false"
		}
		if err := s.m.pg.SetSetting(settingEgressStrict, val); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		s.m.traffic.SetStrictEgress(*in.Strict)
		// The strict switch changes ProxyAddr (possibly to the sentinel address); the Agent's
		// HTTP_PROXY is fixed at Agent creation, so it needs a rebuild to take effect at once.
		s.refreshAgentsForEgressChange()
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
	if strings.HasPrefix(strings.ToLower(line), "socks://") {
		line = "socks5://" + line[len("socks://"):]
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
// verify is on by default: each line is requested through that proxy against check_target, and lines
// that don't connect are **not imported**, with a per-line reason (the user's ask: "on import, the
// broken ones just don't get imported"). If check_target itself is unreachable directly
// (intranet/firewalled), verification is skipped and the response warns — a broken check environment
// never discards the whole batch. Returns per-line results so the frontend can pinpoint exactly which
// line failed.
func (s *Server) proxyPoolBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text             string `json:"text"`
		Mode             string `json:"mode"`
		Strategy         string `json:"strategy"`
		Weight           int    `json:"weight"`
		Verify           *bool  `json:"verify"`
		VerifyTimeoutSec int    `json:"verify_timeout_seconds"`
		Enabled          *bool  `json:"enabled"`
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
	if req.Enabled != nil {
		st.Enabled = *req.Enabled
	}
	byURL := map[string]int{}
	for i, e := range st.Entries {
		byURL[e.URL] = i
	}

	var invalid []proxyBulkInvalid
	added, updated := 0, 0
	// incoming records every entry parsed out of this text (new + existing). Both paths are verified:
	// a new one that doesn't connect is dropped; an existing one that doesn't connect is disabled (user
	// data isn't deleted, but it no longer takes part in exit selection).
	type incomingEntry struct {
		line  int
		entry traffic.PoolEntry
		isNew bool
	}
	var incoming []incomingEntry
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
		if serr := s.validateProxyScheme(norm.String()); serr != nil {
			invalid = append(invalid, proxyBulkInvalid{Line: i + 1, Raw: strings.TrimSpace(ln), Reason: serr.Error()})
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
			incoming = append(incoming, incomingEntry{line: i + 1, entry: st.Entries[idx], isNew: false})
			continue
		}
		e := traffic.PoolEntry{URL: key, Name: name, Enabled: true, Weight: weight}
		st.Entries = append(st.Entries, e)
		byURL[key] = len(st.Entries) - 1
		added++
		incoming = append(incoming, incomingEntry{line: i + 1, entry: e, isNew: true})
	}

	if req.Mode == "replace" && strings.TrimSpace(req.Text) == "" {
		// Replace mode + empty text: the existing pool must never be wiped. All-invalid lines still take
		// the normal path and return per-line reasons (no entry is added then either, so no accidental wipe).
		writeErr(w, 400, "the replace import text is empty — rejected (the existing pool is not cleared)")
		return
	}

	// --- import verification ---
	verify := true
	if req.Verify != nil {
		verify = *req.Verify
	}
	var rejected []proxyBulkInvalid
	var verifiedOK []string
	verifySkipped, verifyNote := false, ""
	disabled := 0
	if verify && len(incoming) > 0 {
		target := settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
		timeout := time.Duration(req.VerifyTimeoutSec) * time.Second
		if timeout <= 0 || timeout > 30*time.Second {
			timeout = importVerifyTimeout
		}
		if !targetReachableDirect(target, 4*time.Second) {
			// The verification environment itself is unusable: rather import everything than kill the batch.
			verifySkipped = true
			verifyNote = "check target " + target + " is unreachable directly, so connectivity verification was skipped this time (change proxypool_check_target in settings)"
		} else {
			entries := make([]traffic.PoolEntry, len(incoming))
			for i, f := range incoming {
				entries[i] = f.entry
			}
			results := probeProxies(context.Background(), entries, target, timeout, importVerifyConcurrency)
			dropNew := map[string]bool{}
			disableExisting := map[string]bool{}
			for i, res := range results {
				if res.OK {
					verifiedOK = append(verifiedOK, incoming[i].entry.URL)
					continue
				}
				if incoming[i].isNew {
					dropNew[incoming[i].entry.URL] = true
				} else {
					disableExisting[incoming[i].entry.URL] = true
				}
				reason := res.Error
				if !incoming[i].isNew {
					reason = "disabled (unreachable): " + reason
					disabled++
				}
				rejected = append(rejected, proxyBulkInvalid{
					Line:   incoming[i].line,
					Raw:    maskProxy(incoming[i].entry.URL),
					Reason: reason,
				})
			}
			if len(dropNew) > 0 || len(disableExisting) > 0 {
				kept := st.Entries[:0]
				for _, e := range st.Entries {
					if dropNew[e.URL] {
						continue
					}
					if disableExisting[e.URL] {
						e.Enabled = false
					}
					kept = append(kept, e)
				}
				st.Entries = kept
				added -= len(dropNew)
				if added < 0 {
					added = 0
				}
			}
		}
	}

	if req.Strategy != "" {
		st.Strategy = req.Strategy
	}
	if err := s.applyProxyPool(*st); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// Entries that verified OK must clear their old trip: applyProxyPool inherits breakOpen from the
	// old entry by URL, and without clearing here the page would show "check passed but 0 available".
	if len(verifiedOK) > 0 && s.m != nil && s.m.traffic != nil {
		for _, u := range verifiedOK {
			s.m.traffic.ProxyPoolClearBreak(u)
		}
		s.m.persistProxyBreaks()
	}
	if err := s.saveProxyPool(*st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := map[string]any{
		"ok": true, "added": added, "updated": updated, "invalid": invalid,
		"rejected": rejected, "disabled": disabled, "total": len(st.Entries),
		"verified": verify && !verifySkipped,
	}
	if verifySkipped {
		out["verify_skipped"] = verifyNote
	}
	writeJSON(w, 200, out)
}

// targetReachableDirect reports whether the check target is reachable "directly from this host" — when
// it isn't, verification is meaningless (every proxy errors), so it must be skipped rather than
// condemning the whole batch.
func targetReachableDirect(target string, timeout time.Duration) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	hc := &http.Client{Timeout: timeout}
	resp, err := hc.Get(target)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// probeProxies verifies a batch of proxies at the given concurrency/timeout (import verification only: higher concurrency than manual checks).
func probeProxies(ctx context.Context, entries []traffic.PoolEntry, target string, timeout time.Duration, concurrency int) []proxyCheckResult {
	if concurrency < 1 {
		concurrency = importVerifyConcurrency
	}
	results := make([]proxyCheckResult, len(entries))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, e := range entries {
		masked := maskProxy(e.URL)
		wg.Add(1)
		go func(idx int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneProxy(ctx, idx, echo, entry.URL, target, timeout)
		}(i, e, masked)
	}
	wg.Wait()
	return results
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
	type pick struct {
		index int // index into the full entries: the frontend's checkbox/delete invalidation relies on it, so not a subset index
		entry traffic.PoolEntry
	}
	selected := make([]pick, 0, len(st.Entries))
	for i, e := range st.Entries {
		if len(want) > 0 && !want[e.URL] {
			continue
		}
		selected = append(selected, pick{index: i, entry: e})
	}
	results := make([]proxyCheckResult, len(selected))
	sem := make(chan struct{}, proxyCheckConcurrency)
	var wg sync.WaitGroup
	for i, sel := range selected {
		// masked URLs for echo only; real credentials are used solely at request time.
		masked := maskProxy(sel.entry.URL)
		wg.Add(1)
		go func(slot int, fullIndex int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[slot] = checkOneProxy(context.Background(), fullIndex, echo, entry.URL, target, timeout)
		}(i, sel.index, sel.entry, masked)
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
		raw := selected[i].entry.URL
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
	s.m.persistProxyBreaks() // manual verification also persists, so dead proxies stay skipped after a restart

	writeJSON(w, 200, map[string]any{
		"target":        target,
		"entries_total": len(st.Entries),
		"results":       results,
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

// maskProxy hides credentials — display-only (username kept, password replaced with ****).
func maskProxy(raw string) string {
	u, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		if _, has := u.User.Password(); has {
			u.User = url.UserPassword(u.User.Username(), "****")
		}
	}
	return u.String()
}
