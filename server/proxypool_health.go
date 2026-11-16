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
	"log"
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
	out := map[string]any{
		"strategy":     st.Strategy,
		"total":        len(st.Entries),
		"capturing":    s.m.TrafficEnabled(),
		"global_proxy": s.m.GlobalProxy() != "",
		"upstreams":    s.m.traffic.ProxyPoolStatus(),
		"health_check": settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
	}
	if len(st.Entries) == 0 {
		out["note"] = "proxy pool empty: traffic leaves from this host directly (or via the 'global egress proxy'). Configure egress rotation under System → Proxy pool."
	} else if !s.m.TrafficEnabled() {
		out["note"] = "proxy pool configured but [traffic capture is off] so the pool isn't in effect — worker target traffic only rotates egress through the capture proxy."
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
