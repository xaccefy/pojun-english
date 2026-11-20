// Proxy-pool proactive health checks and agent-side tools.
//
// Passive circuit-breaking waits for '5 consecutive failures', but a proxy that's
// already dead just slows requests down for 5 more tries. This adds a background sweep:
// every N minutes, verify all enabled upstreams concurrently and break dead ones
// immediately.
//
// Agents get two tools: proxy_status (see pool state) and proxy_report (report 'this
// target is rate-limited/unreachable from this egress' so the platform switches). Agents
// don't need to know which proxy each command used — egress selection is always the
// platform's per-policy job; agents only report 'this egress doesn't work for me'.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/traffic"
)

// StartProxyPoolHealthCheck launches the background probe loop. It is a no-op
// when the interval is 0 (health check disabled).
func (m *Manager) StartProxyPoolHealthCheck() {
	if m == nil || m.pg == nil {
		return
	}
	interval := time.Duration(intSetting(m.pg, settingProxyHealthMinutes, defaultProxyHealthMinutes)) * time.Minute
	if interval <= 0 {
		log.Printf("[proxypool] proactive health checks disabled (proxypool_health_minutes=0)")
		return
	}
	go func() {
		// startup delay: avoid the traffic spike right after boot and give
		// hostd/traffic proxies time to come up.
		time.Sleep(90 * time.Second)
		for {
			m.RunProxyPoolHealthCheck()
			time.Sleep(interval)
		}
	}()
}

// RunProxyPoolHealthCheck probes every enabled upstream once and melts down the
// dead ones. Safe to call from the API (manual "check all") as well.
func (m *Manager) RunProxyPoolHealthCheck() {
	if m == nil || m.traffic == nil || m.pg == nil {
		return
	}
	if !m.proxyCheckInFlight.CompareAndSwap(false, true) {
		return // a round is already running
	}
	defer m.proxyCheckInFlight.Store(false)

	st := loadProxyPoolState(m.pg)
	if !st.Enabled {
		return // master switch off: skip pointless probing
	}
	enabled := make([]traffic.PoolEntry, 0, len(st.Entries))
	for _, e := range st.Entries {
		if e.Enabled {
			enabled = append(enabled, e)
		}
	}
	if len(enabled) == 0 {
		return
	}
	target := settingOr(m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
	cooldown := time.Duration(intSetting(m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	results := s_probeAll(ctx, m, enabled, target)
	dead := 0
	for i, res := range results {
		raw := enabled[i].URL
		if res.OK {
			m.traffic.ProxyPoolReportOK(raw)
			continue
		}
		dead++
		m.traffic.ProxyPoolMarkBad(raw, cooldown)
	}
	if dead > 0 {
		log.Printf("[proxypool] health check: %d/%d upstreams unavailable, circuit-broken", dead, len(enabled))
		// Auto-restart a dead local mihomo process (only when the failing exit is loopback): mihomo is a
		// local core the platform manages itself and has no systemd supervision; without auto-recovery the
		// recording proxy's whole exit stays dead for a long time (measured on task 21: 6 hours, no traffic).
		if dead == len(enabled) && m.mihomo != nil {
			for _, e := range enabled {
				u, err := url.Parse(e.URL)
				if err != nil || u.Hostname() != "127.0.0.1" {
					continue
				}
				port, _ := strconv.Atoi(u.Port())
				if st, rerr := m.mihomo.RestartFromConfig(ctx, port); rerr != nil {
					log.Printf("[proxypool] auto-restart of mihomo failed: %v", rerr)
				} else if st.Running {
					log.Printf("[proxypool] mihomo auto-restarted (port %d); the next health round re-verifies", st.Port)
				}
				break
			}
		}
	}
	// Non-empty pool but 0 available: must warn explicitly. Under strict egress requests fail fast
	// (no real-IP leak); only non-strict mode falls back to direct/global proxy — the wording must
	// differ or it misleads the worker.
	if n := m.traffic.ProxyPoolAvailable(); n == 0 && len(enabled) > 0 {
		if m.traffic.StrictEgress() && m.traffic.ProxyPoolConfigured() {
			log.Printf("[proxypool] warning: all %d upstreams in the pool are unavailable and strict egress blocks direct — target requests fail fast (real IP not exposed); restore an upstream or disable strict egress for now", len(enabled))
		} else {
			log.Printf("[proxypool] warning: all %d upstreams in the pool are unavailable; task egress has fallen back to direct/global proxy (real IP exposed)", len(enabled))
		}
	}
	// the page's 'last checked' timestamp shares the same snapshot as manual
	// verification.
	m.proxyCheckMu.Lock()
	m.proxyCheckLast = map[string]any{
		"at":       time.Now().Format(time.RFC3339),
		"target":   target,
		"count":    len(results),
		"ok_count": countOK(results),
		"auto":     true,
	}
	m.proxyCheckMu.Unlock()
	// Persist the trip results: the next restart still skips these dead proxies.
	m.persistProxyBreaks()
}

// restoreProxyBreaks restores the trip state saved by the last process: without it, every exit
// already judged dead becomes "available" again after a restart and tasks burn another round of
// timeouts (measured on production: 231 of 240 dead proxies).
func (m *Manager) restoreProxyBreaks() {
	if m == nil || m.traffic == nil || m.pg == nil {
		return
	}
	raw, ok, err := m.pg.GetSetting(settingProxyBreaks)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return
	}
	state := map[string]int64{}
	if json.Unmarshal([]byte(raw), &state) != nil {
		return
	}
	if n := m.traffic.RestoreProxyBreaks(state); n > 0 {
		log.Printf("[proxypool] restored the trip state of %d exits (dead proxies stay dead across restarts)", n)
	}
}

// persistProxyBreaks writes the current unexpired trip state back to settings, keeping it across restarts.
func (m *Manager) persistProxyBreaks() {
	if m == nil || m.traffic == nil || m.pg == nil {
		return
	}
	state := m.traffic.SnapshotProxyBreaks()
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	if err := m.pg.SetSetting(settingProxyBreaks, string(raw)); err != nil {
		log.Printf("[proxypool] failed to persist the trip state: %v", err)
	}
}

// proxyTools returns the proxy-pool tools for agents. With capture off the pool isn't
// in effect; the tools say so explicitly instead of erroring — agents need to know
// 'direct/global proxy is in use right now'.
func (s *Server) proxyTools() []actool.CoreTool {
	proxyStatus := actool.Build(actool.Spec{
		Name:        "proxy_status",
		Description: "Check the current egress proxy pool: strategy, per-upstream availability / remaining circuit-break time / last success-failure timestamps, and whether it's in effect. Look here first when judging whether 'target unreachable' is an egress problem.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.proxyStatusResult()
		},
	})
	proxyReport := actool.Build(actool.Spec{
		Name: "proxy_report",
		Description: "Report 'the current egress doesn't work for this target' (rate-limited / unreachable / blocked) — the platform breaks that egress immediately and switches." +
			"target is the host you just accessed (port optional). Only call this when it's confirmed an egress problem — the target refusing service doesn't count.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "the target host just accessed (port optional, e.g. 10.10.0.5:8080)"},
				"reason": map[string]any{"type": "string", "description": "reason (rate-limited/timeout/connection refused etc.) for auditing"},
			},
			"required": []any{"target"},
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.proxyReportResult(in)
		},
	})
	return []actool.CoreTool{proxyStatus, proxyReport}
}

func (s *Server) proxyStatusResult() (actool.Result, error) {
	if s.m == nil || s.m.traffic == nil {
		return actool.Errorf("proxy pool not initialized"), nil
	}
	st := s.loadProxyPool()
	available := 0
	if s.m.traffic != nil {
		available = s.m.traffic.ProxyPoolAvailable()
	}
	eff, socks5Blocked := s.effectivePoolEntries(st)
	out := map[string]any{
		"enabled":        st.Enabled,
		"strategy":       st.Strategy,
		"total":          len(st.Entries),
		"usable":         available,
		"effective":      len(eff),
		"socks5_blocked": socks5Blocked,
		"capturing":      s.m.TrafficEnabled(),
		"global_proxy":   s.m.GlobalProxy() != "",
		"upstreams":      s.m.traffic.ProxyPoolStatus(),
		"health_check":   settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
	}
	if socks5Blocked > 0 {
		out["socks5_note"] = fmt.Sprintf("%d socks5 upstreams are inactive due to the default policy (older versions panicked when socks5 dialing failed). Enable proxypool_allow_socks5 in settings to use them.", socks5Blocked)
	}
	switch {
	case len(st.Entries) == 0:
		out["note"] = "proxy pool empty: traffic leaves from this host directly (or via the 'global egress proxy'). Configure egress rotation under System → Proxy pool."
	case !st.Enabled:
		out["note"] = "the proxy pool is disabled by its master switch: egress falls back to the global proxy/direct."
	case available == 0:
		if s.m.traffic != nil && s.m.traffic.StrictEgress() && s.m.traffic.ProxyPoolConfigured() {
			out["note"] = "every upstream in the pool is currently tripped and strict egress blocks direct: target requests fail fast (real IP not exposed). Restore an upstream or disable strict egress before continuing."
		} else {
			out["note"] = "every upstream in the pool is currently tripped: egress has fallen back to direct/global proxy (real IP exposed). Verify connectivity before continuing."
		}
	case !s.m.TrafficEnabled():
		out["note"] = "proxy pool enabled with traffic capture off: the Agent's Bash/WebFetch gets a pool exit injected directly, one upstream pinned per worker, no traffic records."
	}
	return jsonResult(out)
}

func (s *Server) proxyReportResult(in json.RawMessage) (actool.Result, error) {
	var a struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(in, &a)
	target := strings.TrimSpace(a.Target)
	if target == "" {
		return actool.Errorf("target is required"), nil
	}
	if s.m == nil || s.m.traffic == nil {
		return actool.Errorf("proxy pool not initialized"), nil
	}
	cooldown := time.Duration(intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	broken := s.m.traffic.ProxyPoolReportBad(target, cooldown)
	if broken == "" {
		return jsonResult(map[string]any{
			"ok":   false,
			"note": "this target didn't go through the proxy pool (direct or global egress proxy) — no egress to switch.",
		})
	}
	return jsonResult(map[string]any{
		"ok":              true,
		"broken_upstream": broken,
		"cooldown_min":    int(cooldown / time.Minute),
		"note":            "egress circuit-broken; later requests switch to other upstreams automatically — if it's still unreachable, it's the target side.",
	})
}
