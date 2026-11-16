package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/chu0119/pojun/selfupdate"
)

// HTTP surface for one-click page updates. The real download/verify/swap logic lives in
// the selfupdate package — this file only owns the auth boundary, concurrency
// exclusion, progress broadcast, and telling main 'time to exit'.
//
// This process doesn't restart itself: after staging the new version it exits with
// selfupdate.ExitRestart and the guardian script (start.sh / start.bat; ENTRYPOINT in
// Docker) re-launches it.

// restartCh closes when an upgrade is staged or a rollback finished; main exits with
// ExitRestart on it.
var (
	restartOnce sync.Once
	restartCh   = make(chan struct{})
)

// RestartRequested returns a channel that closes on 'please exit and let the guardian
// re-launch me'.
func RestartRequested() <-chan struct{} { return restartCh }

func requestRestart() { restartOnce.Do(func() { close(restartCh) }) }

// bootState is this boot's selfupdate.Bootstrap verdict (upgrade succeeded / just
// rolled back / staged file discarded), injected by main so /api/update/check can
// honestly tell the frontend how the last upgrade ended.
var (
	bootStateMu sync.Mutex
	bootState   selfupdate.State
)

// SetBootUpdateState is called once by main at startup.
func SetBootUpdateState(st selfupdate.State) {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	bootState = st
}

func bootUpdateState() selfupdate.State {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	return bootState
}

// releaseCache caches GitHub's latest-release query.
//
// The topbar's 'new version' badge queries once per full page load, and unauthenticated
// GitHub API is 60 req/IP/hour — without a cache, a few tabs or page refreshes burn the
// quota and the real update check can't get through. An explicit user 'check for
// updates' can bypass via force.
type releaseCache struct {
	mu  sync.Mutex
	rel *selfupdate.Release
	err error
	at  time.Time
	// fetch is the data getter — an injection point kept for tests; nil means the real
	// GitHub query.
	fetch func(context.Context, *http.Client) (*selfupdate.Release, error)
}

const (
	releaseTTL = 30 * time.Minute
	// failures are cached briefly too — otherwise every page load burns a full timeout
	// while GitHub is unreachable; but the TTL stays short so recovery is quick.
	releaseErrTTL = 2 * time.Minute
	// query timeout. NewClient's 30-minute timeout is for downloading whole packages —
	// a version check can't wait that long.
	releaseTimeout = 20 * time.Second
)

var relCache = &releaseCache{}

// get returns the latest release; cache hits never touch the network.
//
// The lock is held for the whole fetch: concurrent requests queue for the same query's
// result instead of each hitting GitHub (right after page load, when many tabs check
// together, is exactly when rate limits bite).
func (c *releaseCache) get(ctx context.Context, client *http.Client, force bool) (*selfupdate.Release, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !force {
		ttl := releaseTTL
		if c.err != nil {
			ttl = releaseErrTTL
		}
		if !c.at.IsZero() && time.Since(c.at) < ttl {
			return c.rel, c.err
		}
	}

	fetch := c.fetch
	if fetch == nil {
		fetch = selfupdate.FetchLatest
	}
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	rel, err := fetch(ctx, client)
	// a cancelled request (user closed the tab) says nothing about GitHub — don't cache
	// it, or the next visitor gets a baffling 'cancelled' error.
	if err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return c.rel, err
	}
	c.rel, c.err, c.at = rel, err, time.Now()
	return rel, err
}

// updateProgress is one progress entry pushed to the frontend.
type updateProgress struct {
	Phase   selfupdate.Phase `json:"phase"`
	Percent int              `json:"percent"` // meaningful only during download; -1 elsewhere
	Message string           `json:"message"`
	Version string           `json:"version,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// updateHub holds one upgrade's progress and broadcasts it to SSE subscribers.
//
// running doubles as the mutex: POST /api/update/apply during an upgrade gets a flat
// 409 — two goroutines must never write the same pojun.new.
type updateHub struct {
	mu      sync.Mutex
	running bool
	cur     updateProgress
	subs    map[chan updateProgress]struct{}
}

var updHub = &updateHub{
	cur:  updateProgress{Phase: selfupdate.PhaseIdle, Percent: -1},
	subs: map[chan updateProgress]struct{}{},
}

// begin claims upgrade rights; false if one is already running.
func (h *updateHub) begin(version string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return false
	}
	h.running = true
	h.cur = updateProgress{Phase: selfupdate.PhaseDownload, Percent: 0, Message: "preparing…", Version: version}
	h.fanout(h.cur)
	return true
}

// finish ends an upgrade. err nil = staged successfully, awaiting restart.
func (h *updateHub) finish(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	if err != nil {
		h.cur = updateProgress{Phase: selfupdate.PhaseFailed, Percent: -1, Message: "update failed", Error: err.Error(), Version: h.cur.Version}
	} else {
		h.cur = updateProgress{Phase: selfupdate.PhaseStaged, Percent: 100, Message: "new version staged — restarting…", Version: h.cur.Version}
	}
	h.fanout(h.cur)
}

func (h *updateHub) publish(ph selfupdate.Phase, pct int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = updateProgress{Phase: ph, Percent: pct, Message: msg, Version: h.cur.Version}
	h.fanout(h.cur)
}

// fanout must be called holding h.mu. Subscriber channels are buffered and drop when
// full — progress is disposable ephemera; a stuck SSE connection must never block the
// upgrade itself.
func (h *updateHub) fanout(p updateProgress) {
	for ch := range h.subs {
		select {
		case ch <- p:
		default:
		}
	}
}

func (h *updateHub) snapshot() (updateProgress, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur, h.running
}

func (h *updateHub) subscribe() (<-chan updateProgress, func()) {
	ch := make(chan updateProgress, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// updateCheck queries GitHub's latest release and compares against the current
// version.
//
// The frontend also hits api.github.com directly (GitHub CORS is *), but **this
// endpoint is authoritative**: the backend does the download, so only its reachability
// matters. 'browser can connect, server can't' is common (server behind intranet, or
// the proxy is browser-only) — an update there is doomed anyway; better to fail
// honestly at check time.
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion
	mode := "binary"
	if selfupdate.InDocker() {
		mode = "docker"
	}
	boot := bootUpdateState()
	out := map[string]any{
		"current":     current,
		"mode":        mode,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"has_backup":  selfupdate.HasBackup(),
		"repo":        selfupdate.Repo,
		"boot_notice": boot.Detail,
		"rolled_back": boot.RolledBack,
	}

	// the topbar badge uses the cache (default); 'check for updates' sends force=1 for
	// a fresh fetch.
	force := r.URL.Query().Get("force") != ""
	client := selfupdate.NewClient(s.maintenanceProxy())
	rel, err := relCache.get(r.Context(), client, force)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}

	latest := rel.TagName
	out["latest"] = latest
	out["notes"] = rel.Body
	out["html_url"] = rel.HTMLURL
	if !rel.PublishedAt.IsZero() {
		out["published_at"] = rel.PublishedAt.Format(time.RFC3339)
	}

	asset := selfupdate.AssetName(latest, runtime.GOOS, runtime.GOARCH)
	out["asset"] = asset
	if a, ok := rel.FindAsset(asset); ok {
		out["asset_available"] = true
		out["size"] = a.Size
	} else {
		out["asset_available"] = false
	}

	cmp, comparable := selfupdate.CompareVersions(current, latest)
	out["comparable"] = comparable
	out["has_update"] = comparable && cmp < 0
	if !comparable {
		// dev builds (dev / git-describe suffixes) have no comparable version. Allowing
		// an update would just clobber the binary being debugged — so none is offered.
		out["reason"] = fmt.Sprintf("current version %q is not a released build — one-click update disabled", current)
	}
	writeJSON(w, 200, out)
}

// updateApply downloads and stages the new version, then exits so the guardian script
// restarts it.
//
// Returns 202 immediately; the real work runs on a background goroutine — a whole
// package download can take minutes and would be cut by reverse-proxy timeouts if tied
// to the request. Progress streams on /api/update/stream.
func (s *Server) updateApply(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion

	// go through the cache: ensure what's installed is exactly the version the user saw
	// and confirmed in the UI.
	client := selfupdate.NewClient(s.maintenanceProxy())
	rel, err := relCache.get(r.Context(), client, false)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	cmp, comparable := selfupdate.CompareVersions(current, rel.TagName)
	if !comparable {
		writeErr(w, 400, fmt.Sprintf("current version %q is not a released build — one-click update disabled", current))
		return
	}
	if cmp >= 0 {
		writeErr(w, 400, fmt.Sprintf("already on the latest version %s", current))
		return
	}
	if !updHub.begin(rel.TagName) {
		writeErr(w, 409, "an update is already in progress")
		return
	}

	go func() {
		// deliberately s.ctx, not the request ctx: once the HTTP response returns the
		// request is done — a download tied to it would cancel instantly.
		err := selfupdate.Stage(s.ctx, client, rel, current, func(ph selfupdate.Phase, pct int, msg string) {
			updHub.publish(ph, pct, msg)
		})
		updHub.finish(err)
		if err != nil {
			log.Printf("[update] update failed: %v", err)
			return
		}
		log.Printf("[update] %s -> %s staged; exiting to finish the swap", current, rel.TagName)
		// leave a beat to push the final progress entry before triggering exit.
		time.Sleep(1500 * time.Millisecond)
		requestRestart()
	}()

	writeJSON(w, 202, map[string]any{"ok": true, "target": rel.TagName})
}

// updateRollback actively returns to the previous version (the pojun.old backed up
// before the swap).
func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request) {
	if _, running := updHub.snapshot(); running {
		writeErr(w, 409, "an update is in progress — rollback unavailable")
		return
	}
	if err := selfupdate.Rollback(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	log.Printf("[update] manually rolled back to the previous version; exiting to complete the switch")
	writeJSON(w, 202, map[string]any{"ok": true})
	go func() {
		time.Sleep(500 * time.Millisecond)
		requestRestart()
	}()
}

// updateStream pushes update progress over SSE.
func (s *Server) updateStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := updHub.subscribe()
	defer unsub()

	send := func(p updateProgress) {
		b, _ := json.Marshal(p)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	// send current state first so a refreshed page sees the in-flight upgrade
	// immediately.
	cur, _ := updHub.snapshot()
	send(cur)

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			send(p)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
