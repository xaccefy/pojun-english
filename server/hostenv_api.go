// Host-environment API: health check + one-click install.
//
// 'One-click install' actually lives in the privileged helper pojun-hostd (see the hostd
// package) — the main service is confined by NoNewPrivileges + ProtectSystem=strict and
// cannot elevate, so it forwards requests over a Unix socket. This file is that
// forwarding layer plus the frontend contract.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chu0119/pojun/hostd"
	"github.com/chu0119/pojun/hosttools"
	"github.com/chu0119/pojun/proxyprobe"
	"github.com/chu0119/pojun/selfupdate"
)

// default socket path, matching the hostd unit's -socket flag; env-overridable.
const defaultHostdSocket = "/run/pojun/hostd.sock"

func hostdSocket() string {
	if p := strings.TrimSpace(os.Getenv("POJUN_HOSTD_SOCKET")); p != "" {
		return p
	}
	return defaultHostdSocket
}

// hostdClient only reaches the helper over a Unix socket — no TCP surface at all.
func hostdClient() *http.Client {
	sock := hostdSocket()
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

// hostdProbe checks whether the helper is online, returning (online, reason). The
// reason explains to the frontend why install is unavailable.
func (s *Server) hostdProbe(ctx context.Context) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://hostd/healthz", nil)
	if err != nil {
		return false, err.Error()
	}
	resp, err := hostdClient().Do(req)
	if err != nil {
		return false, "host helper not running (pojun-hostd not installed, or this is a Docker deployment)"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "host helper responded abnormally: HTTP " + resp.Status
	}
	return true, ""
}

// installProxy reads the 'install-time egress proxy' setting, used by host-tool installs and
// program updates — maintenance requests. Unrelated to runtime target/LLM proxies: it only affects
// apt/curl/GitHub downloads.
//
// Env var POJUN_INSTALL_PROXY is the fallback: Docker form has no config.json —
// install.sh can only inject via compose. The DB setting wins (page-editable); the env
// var only applies when no setting exists.
func (s *Server) installProxy() string {
	if s.m != nil && s.m.pg != nil {
		v, _, _ := s.m.pg.GetSetting(settingInstallProxy)
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return strings.TrimSpace(os.Getenv("POJUN_INSTALL_PROXY"))
}

// maintenanceProxy picks the proxy for maintenance egress (checking/downloading updates,
// upgrading the host helper).
//
// Prefers the 'install proxy' — it exists for 'pulling things from GitHub'; old
// deployments without it fall back to the global proxy, keeping behavior unchanged.
// They differ semantically: the global proxy hides the source IP for **target traffic**;
// using it for update pulls was just history's only option.
func (s *Server) maintenanceProxy() string {
	if p := s.installProxy(); p != "" {
		return p
	}
	if s.m == nil {
		return ""
	}
	return s.m.GlobalProxy()
}

const settingHostInstallSources = "host_install_sources"

func (s *Server) hostInstallSources() (hostd.InstallSources, error) {
	var sources hostd.InstallSources
	if s.m == nil || s.m.pg == nil {
		return sources, nil
	}
	raw, ok, err := s.m.pg.GetSetting(settingHostInstallSources)
	if err != nil || !ok || raw == "" {
		return sources, err
	}
	if err := json.Unmarshal([]byte(raw), &sources); err != nil {
		return sources, err
	}
	return sources, sources.Validate()
}

func (s *Server) hostenvSaveSources(w http.ResponseWriter, r *http.Request) {
	var sources hostd.InstallSources
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&sources); err != nil {
		writeErr(w, http.StatusBadRequest, "bad install-source setting format")
		return
	}
	if err := sources.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "setting store unavailable")
		return
	}
	raw, _ := json.Marshal(sources)
	if err := s.m.pg.SetSetting(settingHostInstallSources, string(raw)); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save the install-source setting")
		return
	}
	writeJSON(w, http.StatusOK, sources)
}

// hostenvStatus is the health page's main entry: tool list + whether one-click install
// is supported.
func (s *Server) hostenvStatus(w http.ResponseWriter, r *http.Request) {
	sources, err := s.hostInstallSources()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read the install-source setting")
		return
	}
	info, present := s.hostdInfo(r.Context())
	ver := info.Version
	reason := ""
	if !present {
		reason = "host helper not running (pojun-hostd not installed, or this is a Docker deployment)"
	}
	writeJSON(w, 200, map[string]any{
		"tools":       hosttools.Inventory(),
		"deploy_mode": deployMode(),
		"installer": map[string]any{
			"available": present,
			"reason":    reason,
			"version":   ver,
			// old helpers (pre-0.3.22) neither report a version nor have /self-upgrade —
			// they can't re-dress themselves; ops must rerun install.sh once to bootstrap,
			// then they follow the main program's upgrades automatically.
			"upgrade_required":  present && ver == "",
			"socket":            hostdSocket(),
			"proxy":             s.installProxy(), // echo the current install proxy; editable in the frontend
			"sources":           sources,
			"sources_supported": info.InstallSources,
		},
	})
}

// hostenvInstall requests one tool install, forwarded to the helper.
func (s *Server) hostenvInstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		writeErr(w, 400, "missing tool id")
		return
	}
	// the whitelist is gated here first (the helper re-checks too), avoiding pointless
	// cross-process calls.
	tool, ok := hosttools.Lookup(req.ID)
	if !ok {
		writeErr(w, 400, "unknown tool: "+req.ID)
		return
	}
	sources, err := s.hostInstallSources()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read the install-source setting")
		return
	}
	body, code, err := s.forwardHostInstall(r.Context(), tool, s.installProxy(), sources)
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func (s *Server) forwardHostInstall(ctx context.Context, tool hosttools.Tool, proxy string, sources hostd.InstallSources) ([]byte, int, error) {
	path := "/jobs"
	if tool.Kind == hosttools.KindApt && sources.APT != "" || tool.Kind == hosttools.KindPip && sources.PyPI != "" {
		path = "/jobs/with-sources"
	}
	payload, _ := json.Marshal(map[string]any{
		"tool_id": tool.ID,
		"proxy":   proxy,
		"sources": sources,
	})
	body, code, err := s.hostdCall(ctx, http.MethodPost, path, payload)
	if err == nil && code == http.StatusNotFound && path == "/jobs/with-sources" {
		return []byte(`{"error":"this host-helper version doesn't support install-source options; upgrade the helper or restore the system default sources"}`), http.StatusConflict, nil
	}
	return body, code, err
}

// hostenvInstallBatch launches a batch install — the 'install all' backend.
//
// The helper's task model queues naturally (exec semaphore capacity 1, further tasks
// wait in queued), so this just forwards N single-tool installs **in order**: no new
// helper protocol, no parallel installs (parallel apt runs lock-clash). One tool's
// launch failure (already installed / not one-clickable / helper busy) doesn't affect
// the rest — per-tool ok/skip results come back for the frontend.
func (s *Server) hostenvInstallBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "missing tool id list")
		return
	}
	if len(req.IDs) > 100 {
		writeErr(w, 400, "at most 100 tools per call")
		return
	}
	proxy := s.installProxy()
	sources, err := s.hostInstallSources()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read the install-source setting")
		return
	}
	type jobOK struct {
		JobID  string `json:"job_id"`
		ToolID string `json:"tool_id"`
	}
	type skip struct {
		ToolID string `json:"tool_id"`
		Reason string `json:"reason"`
	}
	var started []jobOK
	var skipped []skip
	seen := map[string]bool{}
	for _, id := range req.IDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue // blank and duplicate entries are silently skipped
		}
		seen[id] = true
		tool, ok := hosttools.Lookup(id)
		if !ok {
			skipped = append(skipped, skip{ToolID: id, Reason: "unknown tool"})
			continue
		}
		body, code, err := s.forwardHostInstall(r.Context(), tool, proxy, sources)
		if err != nil {
			// helper wholly unavailable: the rest would fail the same way.
			writeErr(w, 503, err.Error())
			return
		}
		if code/100 != 2 {
			// helper explicitly refused (installed / KindManual / illegal proxy) — record
			// the reason and continue.
			skipped = append(skipped, skip{ToolID: id, Reason: strings.TrimSpace(string(body))})
			continue
		}
		var j struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(body, &j) != nil || j.ID == "" {
			skipped = append(skipped, skip{ToolID: id, Reason: "helper response lacked a task id"})
			continue
		}
		started = append(started, jobOK{JobID: j.ID, ToolID: id})
	}
	writeJSON(w, 200, map[string]any{
		"started": started,
		"skipped": skipped,
	})
}

// hostenvProxyCheck tests whether a proxy actually works.
//
// Users want 'changeable anytime' — proxies die, so an edit must be verifiable right
// away rather than discovered at install time. With no proxy passed, tests the currently
// effective one.
//
// Same verdict criteria as install.sh at install time (both go through the proxyprobe
// package): if both say 'up', it really is the same link.
func (s *Server) hostenvProxyCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxy string `json:"proxy"`
		// UseCurrent = true tests the currently effective proxy (ignores body proxy).
		UseCurrent bool `json:"use_current"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	raw := strings.TrimSpace(req.Proxy)
	if req.UseCurrent || raw == "" {
		raw = s.installProxy()
	}
	raw = proxyprobe.Normalize(raw)

	clean, err := proxyprobe.Validate(raw)
	if err != nil {
		writeJSON(w, 400, map[string]any{
			"ok":    false,
			"proxy": raw,
			"error": err.Error(),
			"hint":  "expected format: http://host:port, https://host:port, socks5://host:port or socks5h://host:port (optional user:pass@)",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res := proxyprobe.Probe(ctx, clean, "", "https://api.ipify.org?format=json")

	// 200 with ok:false means 'tested, unreachable' — not an API error; the frontend must
	// tell them apart.
	writeJSON(w, 200, res)
}

// hostenvJob queries install-task progress (polled by the frontend).
func (s *Server) hostenvJob(w http.ResponseWriter, r *http.Request) {
	body, code, err := s.hostdCall(r.Context(), http.MethodGet, "/jobs/"+r.PathValue("id"), nil)
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// hostenvCancel cancels an install task.
func (s *Server) hostenvCancel(w http.ResponseWriter, r *http.Request) {
	body, code, err := s.hostdCall(r.Context(), http.MethodPost, "/jobs/"+r.PathValue("id")+"/cancel", nil)
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// hostdCall forwards a request to the helper, returning status code and body verbatim.
func (s *Server) hostdCall(ctx context.Context, method, path string, payload []byte) ([]byte, int, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://hostd"+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hostdClient().Do(req)
	if err != nil {
		return nil, 0, errConnectHostd(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}

type hostdUnavailable struct{ msg string }

func (e hostdUnavailable) Error() string { return e.msg }

func errConnectHostd(err error) error {
	return hostdUnavailable{"host helper unavailable (pojun-hostd not installed, or this is a Docker deployment): " + err.Error()}
}

// hostdVersion queries the helper's version.
//
// present=false means the helper is absent (Docker deploy / not installed / not
// running). version="" with present=true means the helper answers but can't report a
// version — `/version` was added in 0.3.22, so such a helper is necessarily older and
// **lacks /self-upgrade**: it can't re-dress itself; ops must rerun install.sh once to
// bootstrap.
func (s *Server) hostdVersion(ctx context.Context) (version string, present bool) {
	info, present := s.hostdInfo(ctx)
	return info.Version, present
}

type hostdInfo struct {
	Version        string `json:"version"`
	InstallSources bool   `json:"install_sources"`
}

func (s *Server) hostdInfo(ctx context.Context) (hostdInfo, bool) {
	if body, code, err := s.hostdCall(ctx, http.MethodGet, "/version", nil); err == nil && code == http.StatusOK {
		var info hostdInfo
		if json.Unmarshal(body, &info) == nil {
			info.Version = strings.TrimSpace(info.Version)
			if info.Version != "" || info.InstallSources {
				return info, true
			}
		}
	}
	// fall back to /healthz: old versions have it but not /version. An answer means the
	// helper is there.
	_, code, err := s.hostdCall(ctx, http.MethodGet, "/healthz", nil)
	return hostdInfo{}, err == nil && code == http.StatusOK
}

// StartHostdReconcile aligns the helper's version with the main program's in the
// background.
//
// Why: the pojun-hostd helper lives in root-owned /usr/local/bin, which the main service
// can't write under ProtectSystem=strict — so **the helper can only upgrade itself**.
// After every self-upgrade restart, the main program detects a version lag here and asks
// the helper to re-dress itself; the helper downloads the official Release and verifies
// SHA256SUMS — the main program only influences 'which released version to install'.
func (s *Server) StartHostdReconcile() {
	go func() {
		// wait for the main service and helper to stabilize — don't fight the startup.
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		for attempt := 1; attempt <= 5; attempt++ {
			if s.reconcileHostdOnce() {
				return
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
		log.Printf("[hostd] version reconcile gave up (helper unreachable)")
	}()
}

// reconcileHostdOnce performs one version-alignment pass. true = no more retries needed.
func (s *Server) reconcileHostdOnce() bool {
	want := strings.TrimSpace(BuildVersion)
	// dev / git-describe builds (suffixed) don't participate, so a dev build can't
	// overwrite a released helper.
	if _, ok := selfupdate.CompareVersions(want, want); !ok {
		return true
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	got, present := s.hostdVersion(ctx)
	if !present {
		return false // helper not up yet — retry later
	}
	if got == want {
		return true
	}
	if got == "" {
		// old helpers neither report versions nor have /self-upgrade — they can't
		// re-dress themselves. This is a one-time bootstrap window: rerun install.sh once
		// to swap in a self-upgrading helper, then every release follows automatically.
		log.Printf("[hostd] helper too old (no version report / self-upgrade) — rerun install.sh once to bootstrap")
		return true
	}
	// Audit B9: no automatic downgrade when the helper is newer than the main program — after a manual
	// main-program rollback the reconcile loop would drag the helper back too, silently reverting a known
	// fix. The hostd side also refuses downgrade requests.
	if cmp, comparable := selfupdate.CompareVersions(got, want); comparable && cmp > 0 {
		log.Printf("[hostd] helper version %s is higher than main %s, skipping the automatic downgrade (rerun install.sh to align)", got, want)
		return true
	}
	log.Printf("[hostd] version mismatch (helper %s / main %s), requesting self-upgrade", got, want)

	payload, _ := json.Marshal(map[string]string{
		"tag":   want,
		"proxy": s.maintenanceProxy(),
	})
	body, code, err := s.hostdCall(ctx, http.MethodPost, "/self-upgrade", payload)
	if err != nil {
		log.Printf("[hostd] self-upgrade request failed: %v", err)
		return false
	}
	if code/100 != 2 {
		log.Printf("[hostd] self-upgrade request refused (HTTP %d): %s", code, strings.TrimSpace(string(body)))
		return true // refused (illegal version / already upgrading) — retrying is pointless
	}
	log.Printf("[hostd] requested upgrade to %s; the helper will restart itself", want)
	return true
}
