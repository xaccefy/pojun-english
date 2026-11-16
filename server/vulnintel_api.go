// Vuln-intelligence API: status & config, manual sync, connectivity diagnostics.
//
// The status page used to be read-only: just counts plus an 'OK / has errors' badge,
// with failure causes buried in badge titles — no config entry, no manual retry. This
// upgrades it to 'configurable, testable, fixable' — config reads/writes via settings,
// sync and template update share one pass (mutually exclusive), and connectivity
// diagnostics probe each source through the current proxy, returning actionable
// fix suggestions.
package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	pgdb "github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/traffic"
	"github.com/chu0119/pojun/vulnintel"
)

// intel config (redacted outward: key/token return only a set boolean and the tail).
type vulnintelConfigDTO struct {
	Enabled        bool   `json:"enabled"`
	NvdAPIKey      string `json:"nvd_api_key"` // for writes; masked on reads
	NvdKeySet      bool   `json:"nvd_key_set"`
	GitHubToken    string `json:"github_token"` // for writes; masked on reads
	GitHubSet      bool   `json:"github_token_set"`
	Proxy          string `json:"proxy"`
	PocEnabled     bool   `json:"poc_enabled"`
	BackfillDays   int    `json:"backfill_days"`
	MaxRuntimeMin  int    `json:"max_runtime_minutes"`
	MaintenanceURL string `json:"maintenance_proxy"` // read-only echo: fallback used under 'follow maintenance proxy'
}

func (s *Server) vulnintelConfigForWrite() vulnintelConfigDTO {
	pg := s.m.pg
	return vulnintelConfigDTO{
		Enabled:        pg.GetBool(settingVulnIntelOn, true),
		NvdAPIKey:      strings.TrimSpace(settingString(pg, settingNvdApiKey)),
		GitHubToken:    strings.TrimSpace(settingString(pg, settingVulnIntelGitHubToken)),
		Proxy:          strings.TrimSpace(settingString(pg, settingVulnIntelProxy)),
		PocEnabled:     pg.GetBool(settingVulnIntelPocEnabled, false),
		BackfillDays:   intSetting(pg, settingVulnIntelBackfillDays, 0),
		MaxRuntimeMin:  intSetting(pg, settingVulnIntelMaxRuntimeMin, defaultVulnIntelMaxRuntimeMin),
		MaintenanceURL: s.m.maintenanceProxy(),
	}
}

// vulnintelStatus reads status. Beyond the store's verbatim sources/counts it adds:
// redacted config, human-readable advice per source error, running state, and nuclei
// template-tree status.
func (s *Server) vulnintelStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	m := s.m
	if m == nil || m.vulnintel == nil {
		writeErr(w, 503, "vuln-intel store not initialized")
		return
	}
	st := m.vulnintel.StatusSnapshot(r.Context())
	st["enabled"] = pg.GetBool(settingVulnIntelOn, true)
	st["nuclei_templates_dir"] = m.nucleiDir

	// per-source error diagnosis, keeping last_error verbatim (frontend can expand it).
	if raw, ok := st["sources"].([]vulnintel.SyncState); ok {
		rows := make([]map[string]any, 0, len(raw))
		for _, src := range raw {
			rows = append(rows, map[string]any{
				"source":       src.Source,
				"last_sync_at": src.LastSyncAt,
				"cursor":       src.Cursor,
				"total_synced": src.TotalSynced,
				"last_error":   src.LastError,
				"enabled":      src.Enabled,
				"error_hint":   vulnIntelErrorHint(src.LastError),
				"ok":           src.LastError == "" && src.LastSyncAt != nil,
			})
		}
		st["sources"] = rows
	}

	cfg := s.vulnintelConfigForWrite()
	// the read path returns masks only — plaintext never enters a response body.
	cfg.NvdAPIKey = maskSecret(cfg.NvdAPIKey)
	cfg.GitHubToken = maskSecret(cfg.GitHubToken)
	cfg.NvdKeySet = settingString(pg, settingNvdApiKey) != ""
	cfg.GitHubSet = settingString(pg, settingVulnIntelGitHubToken) != ""
	st["config"] = cfg
	running, startedAt := m.VulnIntelSyncState()
	st["sync_running"] = running
	st["sync_started_at"] = startedAt
	st["sync_phase"] = m.SyncPhase()
	st["next_tick_hint"] = "scheduled sync runs every 6 hours (first round ~90s after boot)"
	st["nuclei"] = nucleiTemplatesStatus(m.nucleiDir)
	writeJSON(w, 200, st)
}

// maskSecret masks a credential: empty string returned as-is (UI shows 'not
// configured'); non-empty keeps only the length and tail.
func maskSecret(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) <= 4 {
		return "****"
	}
	return "••••••••" + v[len(v)-4:]
}

// nucleiTemplateStats reports the local template tree at a glance: whether cloned,
// yaml template count, last git update time. Lets the user tell 'templates unusable' =
// never pulled vs pulled but stale.
type nucleiTemplatesDTO struct {
	Dir       string `json:"dir"`
	Exists    bool   `json:"exists"`
	IsGit     bool   `json:"is_git"`
	Templates int    `json:"templates"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Hint      string `json:"hint"`
}

func nucleiTemplatesStatus(dir string) nucleiTemplatesDTO {
	out := nucleiTemplatesDTO{Dir: dir}
	if dir == "" {
		out.Hint = "template directory not configured"
		return out
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		out.Hint = "template tree not cloned yet — use 'Sync now' above to fetch it (check the sync log for proxy issues on failure)"
		return out
	}
	out.Exists = true
	_, err = os.Stat(filepath.Join(dir, ".git"))
	out.IsGit = err == nil
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") {
			out.Templates++
		}
		return nil
	})
	if out.IsGit {
		if fi, err := os.Stat(filepath.Join(dir, ".git", "FETCH_HEAD")); err == nil {
			out.UpdatedAt = fi.ModTime().Format(time.RFC3339)
		} else if fi, err := os.Stat(filepath.Join(dir, ".git", "index")); err == nil {
			out.UpdatedAt = fi.ModTime().Format(time.RFC3339)
		}
	}
	if out.Templates == 0 {
		out.Hint = "directory exists but has no yaml templates — the clone was incomplete or interrupted; delete it and hit 'Sync now' again"
	} else {
		out.Hint = fmt.Sprintf("ready: %d templates", out.Templates)
	}
	return out
}

// vulnintelSaveConfig saves config. An empty string for key/token means 'keep
// unchanged'; "-" clears it.
func (s *Server) vulnintelSaveConfig(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Enabled       *bool   `json:"enabled"`
		NvdAPIKey     *string `json:"nvd_api_key"`
		GitHubToken   *string `json:"github_token"`
		Proxy         *string `json:"proxy"`
		PocEnabled    *bool   `json:"poc_enabled"`
		BackfillDays  *int    `json:"backfill_days"`
		MaxRuntimeMin *int    `json:"max_runtime_minutes"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Enabled != nil {
		if err := pg.SetBool(settingVulnIntelOn, *req.Enabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	// credentials: omitted field = unchanged; "-" = clear; anything else = overwrite.
	setSecret := func(key string, val *string) error {
		if val == nil {
			return nil
		}
		v := strings.TrimSpace(*val)
		if v == "-" {
			return pg.SetSetting(key, "")
		}
		if v == "" {
			return nil // empty = keep current value, so clearing an input box doesn't drop credentials
		}
		return pg.SetSetting(key, v)
	}
	if err := setSecret(settingNvdApiKey, req.NvdAPIKey); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := setSecret(settingVulnIntelGitHubToken, req.GitHubToken); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if req.Proxy != nil {
		p := strings.TrimSpace(*req.Proxy)
		if p != "" {
			if _, err := traffic.ValidateProxyURL(p); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
		}
		if err := pg.SetSetting(settingVulnIntelProxy, p); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.PocEnabled != nil {
		if err := pg.SetBool(settingVulnIntelPocEnabled, *req.PocEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.BackfillDays != nil {
		d := *req.BackfillDays
		if d < 0 {
			d = 0
		}
		if err := pg.SetSetting(settingVulnIntelBackfillDays, fmt.Sprintf("%d", d)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.MaxRuntimeMin != nil {
		mn := *req.MaxRuntimeMin
		if mn < 5 {
			mn = 5
		}
		if err := pg.SetSetting(settingVulnIntelMaxRuntimeMin, fmt.Sprintf("%d", mn)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// vulnintelSyncNow manually triggers a sync round (with asset linkage and template
// tree).
func (s *Server) vulnintelSyncNow(w http.ResponseWriter, r *http.Request) {
	if pg := s.pg(w); pg == nil {
		return
	}
	if !s.m.SyncVulnIntelNow() {
		writeErr(w, 409, "a sync round is already running (use 'Abort' before starting another)")
		return
	}
	writeJSON(w, 200, map[string]any{"accepted": true})
}

// vulnintelSyncCancel aborts the current sync round (v0.3.96: before this a round
// could run 45 minutes uninterruptible — users could only wait when it wedged).
// Cooperative cancellation: ctx threads through NVD/GHSA requests and the nuclei git
// subprocess.
func (s *Server) vulnintelSyncCancel(w http.ResponseWriter, r *http.Request) {
	if pg := s.pg(w); pg == nil {
		return
	}
	if !s.m.CancelVulnIntelSync() {
		writeErr(w, 409, "no sync round is currently running")
		return
	}
	writeJSON(w, 200, map[string]any{"cancelling": true})
}

// --- connectivity diagnostics ---

type probeResult struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	OK        bool   `json:"ok"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
	ProxyUsed string `json:"proxy_used,omitempty"`
}

// vulnintelProbe really probes each source once, answering 'is the source down, the
// proxy dead, or the network broken'. 10s per item so one slow source can't stall the
// whole check.
func (s *Server) vulnintelProbe(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Proxy *string `json:"proxy"`
	}
	_ = decode(r, &req)
	proxy := s.m.vulnIntelProxy()
	if req.Proxy != nil && strings.TrimSpace(*req.Proxy) != "" {
		proxy = strings.TrimSpace(*req.Proxy)
	}
	client, err := vulnintel.NewNvdClient("", proxy)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// heartbeat is far cheaper than a full feed — connectivity is enough, no full
	// download needed.
	checks := []struct{ source, target string }{
		{"nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"},
		{"kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
		{"github", "https://api.github.com/rate_limit"},
		// GHSA's real endpoint: the advisories API is anonymously readable. Probe it,
		// not api.github.com root — root being reachable says nothing about advisories.
		{"ghsa", "https://api.github.com/advisories?per_page=1"},
	}
	results := make([]probeResult, 0, len(checks)+1)
	for _, c := range checks {
		results = append(results, probeURL(r.Context(), client.HTTP, c.source, c.target, proxy))
	}
	// template tree: test one real fetch locally — closer to the real update path than
	// a bare ls-remote.
	tplTarget := "https://github.com/projectdiscovery/nuclei-templates.git/info/refs?service=git-upload-pack"
	results = append(results, probeURL(r.Context(), client.HTTP, "nuclei_templates", tplTarget, proxy))

	writeJSON(w, 200, map[string]any{
		"proxy":     proxy,
		"effective": proxy == "",
		"results":   results,
	})
}

func probeURL(ctx context.Context, hc *http.Client, source, target, proxy string) probeResult {
	res := probeResult{Source: source, Target: target, ProxyUsed: proxy}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, target, nil)
	if err != nil {
		res.Error = err.Error()
		res.Hint = vulnIntelErrorHint(res.Error)
		return res
	}
	start := time.Now()
	resp, err := hc.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Hint = vulnIntelErrorHint(res.Error)
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	res.Status = resp.StatusCode
	res.OK = resp.StatusCode == http.StatusOK
	if !res.OK {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	res.Hint = vulnIntelErrorHint(res.Error)
	return res
}

// vulnIntelErrorHint translates a low-level error into actionable advice.
// It's the only explanation users get for sync failures — verbosity is fine if it ends
// with a next action.
func vulnIntelErrorHint(err string) string {
	e := strings.ToLower(err)
	switch {
	case err == "":
		return ""
	case strings.Contains(e, "proxyconnect") || strings.Contains(e, "socks") ||
		strings.Contains(e, "proxy is unreachable"):
		return "Proxy unreachable: check the proxy address/port, or clear 'Sync proxy' to fall back to the install proxy in system settings."
	case strings.Contains(e, "no such host") || strings.Contains(e, "dial tcp: lookup"):
		return "DNS resolution failed: this domain can't be resolved directly (common for cisa.gov / github.com). Configure a working egress proxy."
	case strings.Contains(e, "context deadline") || strings.Contains(e, "client.timeout"):
		return "Request timed out: slow network or dead proxy node. Try another proxy, or raise the per-round cap so retries get more time."
	case strings.Contains(e, "status 401"):
		return "401 unauthorized: the API key/token is invalid or expired — enter a fresh one."
	case strings.Contains(e, "status 403"):
		return "403 refused: usually the source's rate limit (NVD anonymous is only 5 req/30s). Add an NVD API key or switch proxies."
	case strings.Contains(e, "status 404"):
		return "404: the source path changed, or the proxy returned a block page. Use 'Test connectivity' above to find the failing hop."
	case strings.Contains(e, "429") || strings.Contains(e, "rate limit"):
		return "Rate-limited: retried automatically later (the cursor resumes), or add an NVD API key / GitHub token for higher quota."
	case strings.Contains(e, "x509") || strings.Contains(e, "tls"):
		return "TLS certificate verification failed: the proxy is probably doing MITM. Use a recording proxy with a CA installed, or switch to a plain http proxy."
	case strings.Contains(e, "i/o timeout"):
		return "Connection timed out: switch proxies or retry later."
	default:
		return "See the full error; run 'Test connectivity' first to distinguish network/proxy issues from source-side ones."
	}
}

// egressHint / egressPortMap read the connect-back config (settings; read failures
// treated as empty).
func egressHint(pg *pgdb.DB) string {
	v, _, _ := pg.GetSetting("egress_hint")
	return strings.TrimSpace(v)
}

func egressPortMap(pg *pgdb.DB) string {
	v, _, _ := pg.GetSetting("egress_port_map")
	return strings.TrimSpace(v)
}
