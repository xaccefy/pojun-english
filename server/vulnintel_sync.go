// Runtime config, manual triggering, and concurrency control for vuln-intel sync.
//
// The timed loop (runVulnIntelSync) and the page's 'sync now' share one pass: only one
// round at a time, so two goroutines can't write vuln_sync_state concurrently or race
// NVD rate limits.
package server

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/vulnintel"
)

// vuln-intel configurable settings.
const (
	settingVulnIntelGitHubToken   = "vulnintel_github_token"
	settingVulnIntelPocEnabled    = "vulnintel_poc_enabled"
	settingVulnIntelBackfillDays  = "vulnintel_backfill_days"
	settingVulnIntelMaxRuntimeMin = "vulnintel_max_runtime_minutes"
	// dedicated egress proxy for sync. empty = the maintenance egress fallback chain
	// (install proxy → global → search proxy).
	settingVulnIntelProxy = "vulnintel_proxy"
)

const (
	defaultVulnIntelMaxRuntimeMin = 30
	defaultVulnIntelInterval      = 6 * time.Hour
)

// errVulnSyncRunning means a sync round is already running; callers treat it as
// 'accepted / try later'.
var errVulnSyncRunning = errors.New("vulnintel sync already running")

// vulnIntelProxy resolves the egress proxy for intel sync: the dedicated proxy first,
// then the maintenance chain (install proxy → global → search proxy) — the same egress
// as update pulls and tool installs.
func (m *Manager) vulnIntelProxy() string {
	if m == nil || m.pg == nil {
		return ""
	}
	if v, _, _ := m.pg.GetSetting(settingVulnIntelProxy); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return m.maintenanceProxy()
}

// vulnIntelConfig assembles the full sync config from settings. Every field is
// read fresh so a change in the UI applies on the next pass without a restart.
func (m *Manager) vulnIntelConfig() vulnintel.Config {
	cfg := vulnintel.Config{
		PocEnabled:   m.pg.GetBool(settingVulnIntelPocEnabled, false),
		BackfillDays: intSetting(m.pg, settingVulnIntelBackfillDays, 0),
	}
	cfg.ProxyURL = m.vulnIntelProxy()
	cfg.NvdAPIKey = strings.TrimSpace(settingString(m.pg, settingNvdApiKey))
	if cfg.NvdAPIKey == "" {
		cfg.NvdAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}
	cfg.GitHubToken = strings.TrimSpace(settingString(m.pg, settingVulnIntelGitHubToken))
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if mins := intSetting(m.pg, settingVulnIntelMaxRuntimeMin, defaultVulnIntelMaxRuntimeMin); mins > 0 {
		cfg.MaxRuntime = time.Duration(mins) * time.Minute
	}
	return cfg
}

// SyncVulnIntelNow starts one pass in the background (manual trigger). Returns
// false when a pass is already running. The enabled switch is intentionally
// ignored: clicking "sync now" means sync now.
func (m *Manager) SyncVulnIntelNow() bool {
	if m == nil || m.vulnintel == nil {
		return false
	}
	if !m.vulnSyncMu.TryLock() {
		return false
	}
	m.vulnSyncRunning.Store(true)
	m.vulnSyncStartedAt.Store(time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	m.storeSyncCancel(cancel)
	go func() {
		defer m.vulnSyncMu.Unlock()
		defer m.vulnSyncRunning.Store(false)
		defer m.clearSyncCancel()
		if err := m.vulnIntelPassLocked(ctx); err != nil {
			log.Printf("[vulnintel] manual sync did not complete fully: %v", err)
		}
	}()
	return true
}

// storeSyncCancel / clearSyncCancel / CancelVulnIntelSync / SyncPhase:
// the 'interruptible sync' trio (v0.3.96). Before this, a round could run 45 minutes
// with no interruption path — when stuck, the user could neither stop it nor start a new
// round (TryLock refused), just wait: the UI showed 'syncing' forever.
func (m *Manager) storeSyncCancel(cancel context.CancelFunc) {
	m.vulnSyncCancel.Store(cancel)
}

func (m *Manager) clearSyncCancel() {
	m.vulnSyncCancel.Store(context.CancelFunc(func() {}))
}

// CancelVulnIntelSync interrupts the running round (if any). false = no round running.
// Cancellation is cooperative: ctx reaches vulnintel.Run / EnsureTemplates'
// exec.CommandContext, the subprocess (git/curl) dies, the round exits with a 'cancelled'
// error, and defers reset the lock and state.
func (m *Manager) CancelVulnIntelSync() bool {
	if !m.vulnSyncRunning.Load() {
		return false
	}
	if cancel, ok := m.vulnSyncCancel.Load().(context.CancelFunc); ok {
		cancel()
		log.Printf("[vulnintel] interruption requested — the running round will be cancelled")
		return true
	}
	return false
}

// SetVulnSyncPhase updates the current round's phase label (shown on the status page).
// f = "vuln-intel sync running (CVE/KEV/GHSA/PoC)" etc.
func (m *Manager) SetVulnSyncPhase(f string) {
	if m == nil {
		return
	}
	m.vulnSyncPhase.Store(f)
}

// SyncPhase returns the current phase label (empty = not running or unset).
func (m *Manager) SyncPhase() string {
	if m == nil {
		return ""
	}
	if v, ok := m.vulnSyncPhase.Load().(string); ok {
		return v
	}
	return ""
}

// VulnIntelSyncState reports whether a pass is running and when it started
// (unix seconds, 0 = never). Used by the status API.
func (m *Manager) VulnIntelSyncState() (running bool, startedAt int64) {
	if m == nil {
		return false, 0
	}
	return m.vulnSyncRunning.Load(), m.vulnSyncStartedAt.Load()
}

// runVulnIntelPass is the scheduled-loop entry: it takes the same lock, so a
// manual trigger and the timer can never overlap.
func (m *Manager) runVulnIntelPass(ctx context.Context) error {
	if !m.vulnSyncMu.TryLock() {
		return errVulnSyncRunning
	}
	defer m.vulnSyncMu.Unlock()
	m.vulnSyncRunning.Store(true)
	m.vulnSyncStartedAt.Store(time.Now().Unix())
	runCtx, runCancel := context.WithCancel(ctx)
	m.storeSyncCancel(runCancel)
	defer m.vulnSyncRunning.Store(false)
	defer m.clearSyncCancel()
	return m.vulnIntelPassLocked(runCtx)
}

// ── recent-critical fast lane ─────────────────────────────────────────────
//
// The main sync walks lastModifiedDate windows (≤120 days) — a cursor advances window by
// window and one MaxRuntime can't cover it. That structure suits 'completing the
// historical catalog' but is wrong for 'just-disclosed vulns': a CRITICAL published
// yesterday waits for the main cursor to crawl to its window before landing.
//
// The fast lane pulls small publishedDate windows and keeps only CVSS≥9.0 or CISA KEV,
// compressing 'just-disclosed criticals' to tens of minutes into the DB. It **shares the
// vuln_cves table** with the main sync (agents query one DB) but has an **independent
// cursor** and **independent lock** (a main round is 30 min — neither should stall the
// other).
//
// The 2026-10-22 verification used two real targets: CVE-2026-109618 / CVE-2026-109619
// (PHP CRITICAL RCE disclosed the previous day) — the main sync hadn't crawled to that
// window and their NVD version ranges were empty ('version TBD', marked by
// vulnintel.VersionRangeUndetermined).

const (
	// settingVulnIntelFastLaneOn is the fast lane's own switch.
	settingVulnIntelFastLaneOn = "vulnintel_fast_lane_enabled"
	// settingVulnIntelFastLaneMinutes is the fast lane's poll interval (minutes).
	settingVulnIntelFastLaneMinutes = "vulnintel_fast_lane_interval_minutes"
	// settingVulnIntelFastLaneWindowDays is the fast lane's lookback window (days).
	settingVulnIntelFastLaneWindowDays = "vulnintel_fast_lane_window_days"
	// settingVulnIntelGhsaCursor is the GHSA sync cursor (the latest updated time reached).
	settingVulnIntelGhsaCursor = "vulnintel_ghsa_cursor"
)

// vulnintelSourceGhsa is GHSA's source name in vuln_sync_state.
const vulnintelSourceGhsa = "ghsa"

const (
	// defaultVulnIntelGhsaMaxPages is GHSA's max pages per round.
	//
	// 3 pages × 100 = 300 per round — plenty at 30-minute rounds: GHSA's value is filling
	// version ranges, not completing history (history is the NVD main sync's job).
	defaultVulnIntelGhsaMaxPages = 3
)

const (
	// defaultVulnIntelFastLaneInterval is the fast lane's default poll interval.
	//
	// 30 minutes: a 7-day window pulls in 17s measured, so the interval mainly decides
	// 'how fast it lands'. 15min gains little (NVD's indexing latency on new records is
	// hours); 1h is too slow ('just-disclosed' value lives within hours).
	defaultVulnIntelFastLaneInterval = 30 * time.Minute
	// defaultVulnIntelFastLaneWindowDays is the fast lane's default lookback window.
	//
	// the floor is backed by vulnintel.fastLaneMinWindowDays (1–3-day windows timed out
	// in testing).
	defaultVulnIntelFastLaneWindowDays = 7
	// defaultVulnIntelFastLaneMaxRuntime is the fast lane's per-round wall-clock cap.
	//
	// shorter than the main sync: the fast lane's value is timeliness — it shouldn't eat a
	// whole round's budget.
	defaultVulnIntelFastLaneMaxRuntime = 5 * time.Minute
)

// fastLaneEnabled reports whether the recent-critical fast lane is on.
//
// follows the master switch (vulnintel_enabled): if intel sync is off entirely, the fast
// lane needn't run either. A separate switch exists for 'turn off the fast lane to watch
// the main sync's behavior' scenarios.
func (m *Manager) fastLaneEnabled() bool {
	if m == nil || m.pg == nil {
		return false
	}
	if !m.pg.GetBool(settingVulnIntelOn, true) {
		return false
	}
	return m.pg.GetBool(settingVulnIntelFastLaneOn, true)
}

// fastLaneConfig assembles the fast-lane config.
func (m *Manager) fastLaneConfig() vulnintel.FastLaneConfig {
	cfg := vulnintel.FastLaneConfig{
		ProxyURL:  m.vulnIntelProxy(),
		NvdAPIKey: strings.TrimSpace(settingString(m.pg, settingNvdApiKey)),
		WindowDays: intSetting(m.pg, settingVulnIntelFastLaneWindowDays,
			defaultVulnIntelFastLaneWindowDays),
		MaxRuntime: defaultVulnIntelFastLaneMaxRuntime,
	}
	if cfg.NvdAPIKey == "" {
		cfg.NvdAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}
	// the page delay must be derived from API-key presence, not guessed.
	//
	// NVD anonymous access is ~5 req/30s (~6.5s/req); with a key it's 50 req/30s
	// (0.7s/req). The fast lane used to hardcode 1s — guaranteed 429 without a key
	// (first real run on 2026-10-22 hit it: 'nvd rate limited', not one page pulled).
	//
	// the derivation is shared with the main sync (vulnintel's pageDelayFor) so two
	// copies of the rate numbers can't drift.
	cfg.PageDelay = vulnintel.PageDelayFor(cfg.NvdAPIKey)
	return cfg
}

// runVulnIntelFastLane drives the recent-critical fast lane.
//
// own goroutine, own lock: a main round runs up to 30 minutes and the fast lane must
// keep landing newly disclosed criticals during it. Both share vuln_cves; upserts are
// idempotent, so pulling the same record twice is fine.
func (m *Manager) runVulnIntelFastLane() {
	// the start delay must **far exceed** the main sync's 90s offset.
	//
	// Originally only +30s — main at 90s, fast lane at 120s, both hitting NVD where
	// anonymous access is 5 req/30s (**shared quota**). First real run: the fast lane got
	// 'nvd rate limited' on page 0 — not one page pulled.
	//
	// offset to 7 minutes: by the time the fast lane starts, the main round (max 30min)
	// is mostly done — no quota fight.
	time.Sleep(7 * time.Minute)
	for {
		if m.fastLaneEnabled() {
			m.fastLaneOnce()
		}
		interval := defaultVulnIntelFastLaneInterval
		if m.pg != nil {
			if mins := intSetting(m.pg, settingVulnIntelFastLaneMinutes, 0); mins > 0 {
				interval = time.Duration(mins) * time.Minute
			}
		}
		time.Sleep(interval)
	}
}

// fastLaneOnce runs one fast-lane pass: pull → store → link assets.
//
// like the main sync, the fast lane runs asset linking after a pull — otherwise new
// vulns land in the DB but tasks see no hint, and 'just-disclosed' stays shelved.
func (m *Manager) fastLaneOnce() {
	if m == nil || m.vulnintel == nil {
		return
	}
	// own lock: fast-lane rounds must not overlap either (same window pulled twice).
	if !m.vulnFastLaneMu.TryLock() {
		return
	}
	defer m.vulnFastLaneMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), defaultVulnIntelFastLaneMaxRuntime+time.Minute)
	defer cancel()

	res, err := vulnintel.RunFastLane(ctx, m.vulnintel, m.fastLaneConfig())
	if err != nil {
		log.Printf("[vulnintel] fast lane round failed: %v", err)
		return
	}
	if res.Stored > 0 {
		log.Printf("[vulnintel] fast lane: scanned %d, stored %d (of which %d version-TBD), cursor %s",
			res.Scanned, res.Stored, res.VersionUndetermined, res.Cursor)
		// new vulns landed → run asset linking now so affected tasks see it.
		m.linkVulnIntelAssets()
	}
	if res.Truncated {
		log.Printf("[vulnintel] fast lane round incomplete (page/time cap), cursor %s retained", res.Cursor)
	}

	// GHSA fills in version ranges (second source).
	//
	// Why: NVD often leaves version ranges empty on newly disclosed CVEs (the two PHP
	// CVEs were `cpe:2.3:a:php:php:*:*`), leaving only 'version TBD' — a stopgap, not a
	// solution. GHSA requires version ranges, which fills the gap.
	//
	// It lives in the fast lane, not the main sync: GHSA's value is 'timely version
	// ranges', and the fast lane is exactly 'newly disclosed first'.
	m.syncGhsaVersions(ctx)
}

// syncGhsaVersions runs one GHSA round to fill version ranges.
//
// reuses the existing GitHub token (settingVulnIntelGitHubToken) — same credentials, no
// new config. An empty token also works (GHSA public advisories are anonymously readable,
// with looser limits).
//
// failures don't affect the main flow: GHSA is only a supplementary source — its outage
// shouldn't take NVD sync down too.
func (m *Manager) syncGhsaVersions(ctx context.Context) {
	if m == nil || m.vulnintel == nil {
		return
	}
	token := strings.TrimSpace(settingString(m.pg, settingVulnIntelGitHubToken))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	client, err := vulnintel.NewGhsaClient(token, m.vulnIntelProxy())
	if err != nil {
		log.Printf("[vulnintel] GHSA client init failed: %v", err)
		return
	}
	// cursor: last sync time. First round uses '7 days ago' — GHSA's updated_at ordering
	// plus a since filter is incremental; the first round doesn't chase history (history
	// completion is the NVD main sync's job).
	since := time.Now().Add(-7 * 24 * time.Hour)
	if v := strings.TrimSpace(settingString(m.pg, settingVulnIntelGhsaCursor)); v != "" {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil {
			since = t
		}
	}
	res, err := m.vulnintel.SyncGhsa(ctx, client, since, defaultVulnIntelGhsaMaxPages)
	if err != nil {
		log.Printf("[vulnintel] GHSA sync failed: %v", err)
		m.recordGhsaState(ctx, since, 0, err)
		return
	}
	if res.Upserted > 0 || res.Merged > 0 {
		log.Printf("[vulnintel] GHSA: pulled %d, added %d, filled version ranges on %d",
			res.Fetched, res.Upserted, res.Merged)
	}
	if len(res.Errors) > 0 {
		log.Printf("[vulnintel] GHSA round: %d errors (first: %s)", len(res.Errors), res.Errors[0])
	}
	// record the cursor: this round's latest updated.
	latest := m.latestGhsaUpdated(ctx)
	if latest.After(since) {
		_ = m.pg.SetSetting(settingVulnIntelGhsaCursor, latest.UTC().Format(time.RFC3339))
		since = latest
	}
	m.recordGhsaState(ctx, since, int64(res.Upserted+res.Merged), nil)
}

// recordGhsaState records GHSA's sync state (the status page shows per-source).
//
// on failure the error goes into last_error — the status page turns it into
// human-readable advice.
func (m *Manager) recordGhsaState(ctx context.Context, cursor time.Time, total int64, syncErr error) {
	if m == nil || m.pg == nil {
		return
	}
	st, err := m.vulnintel.GetSyncState(ctx, vulnintelSourceGhsa)
	if err != nil {
		return
	}
	st.Source = vulnintelSourceGhsa
	st.Enabled = true
	st.Cursor = cursor.UTC().Format(time.RFC3339)
	st.TotalSynced += total
	if syncErr != nil {
		st.LastError = syncErr.Error()
	} else {
		st.LastError = ""
	}
	_ = m.vulnintel.SaveSyncState(ctx, st)
}

// latestGhsaUpdated looks up the most recently synced GHSA entry's updated time.
func (m *Manager) latestGhsaUpdated(ctx context.Context) time.Time {
	if m == nil || m.pg == nil {
		return time.Time{}
	}
	var v string
	err := m.pg.QueryRowContext(ctx, `SELECT COALESCE(MAX(modified_at)::text,'') FROM vuln_cves WHERE source='ghsa'`).Scan(&v)
	if err != nil || v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// vulnIntelPassLocked is one full pass: CVE/KEV/PoC sync → asset linking →
// nuclei template tree. The caller holds vulnSyncMu.
func (m *Manager) vulnIntelPassLocked(ctx context.Context) error {
	cfg := m.vulnIntelConfig()
	m.SetVulnSyncPhase("vuln-intel sync running (CVE / KEV / GHSA / PoC)")
	err := vulnintel.Run(ctx, m.vulnintel, cfg)
	if ctx.Err() != nil {
		m.SetVulnSyncPhase("interrupted")
		log.Printf("[vulnintel] round interrupted (progress retained — can be restarted)")
		return ctx.Err()
	}
	if err != nil {
		log.Printf("[vulnintel] round did not complete fully: %v (cursor retained, next round continues)", err)
	}
	// asset linking: freshly synced CVEs get reverse-matched against service asset
	// fingerprints; affected tasks get hints. Runs even when the round didn't fully
	// finish — KEV stubs and upserted records are already queryable.
	m.SetVulnSyncPhase("asset fingerprint linking")
	m.linkVulnIntelAssets()
	m.SetVulnSyncPhase("nuclei template tree update")
	m.refreshNucleiTemplates(cfg.ProxyURL)
	m.SetVulnSyncPhase("")
	return nil
}

// refreshNucleiTemplates keeps the local template tree moving. It is deliberately
// called outside the "enabled" gate: scan_with_nuclei is an independent feature
// and the tree must not rot when intel sync is switched off. Caller owns
// vulnSyncMu.
func (m *Manager) refreshNucleiTemplates(proxyURL string) {
	// 15 minutes: nuclei-templates depth-1 is ~100-200MB and a 5-minute timeout through a
	// slow proxy is guaranteed — a timeout-killed clone leaves a half-baked directory, the
	// root cause of the Kali '0 templates' incident (v0.3.96).
	tplCtx, tplCancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer tplCancel()
	if err := vulnintel.EnsureTemplates(tplCtx, m.nucleiDir, proxyURL); err != nil {
		log.Printf("[vulnintel] nuclei template tree update failed: %v", err)
	}
}

// intSetting reads an integer setting with a default.
func intSetting(pg interface {
	GetSetting(string) (string, bool, error)
}, key string, def int) int {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func settingString(pg interface {
	GetSetting(string) (string, bool, error)
}, key string) string {
	v, _, _ := pg.GetSetting(key)
	return v
}
