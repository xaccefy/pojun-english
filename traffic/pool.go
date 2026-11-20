package traffic

// Proxy pool: per-request rotation across multiple upstream egresses. The entry point is
// go-mitmproxy's per-request upstream hook (SetUpstreamProxy's signature supports it
// naturally); the selector picks an available proxy per the strategy inside that hook.
// A failed request (RequestError) counts a failure for that upstream, and consecutive
// failures trip it.
//
// Relationship to global_proxy: when the pool is non-empty it takes precedence (the
// global proxy is ignored), and when the pool is empty we fall back to the single global
// proxy / direct connection — zero migration cost for existing users.
// The trip semantics follow the same idea as llmpool: N consecutive failures enter a
// cooling-off window, and attempts resume automatically once it expires.

import (
	"fmt"
	"hash/fnv"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PoolEntry is one upstream proxy in the pool.
type PoolEntry struct {
	URL      string `json:"url"`      // http/https/socks5, may contain user:pass (masked on output)
	Name     string `json:"name"`     // display name
	Enabled  bool   `json:"enabled"`  // manual switch
	Weight   int    `json:"weight"`   // rotation weight (effective for round_robin, >=1)
	Failures int    `json:"failures"` // consecutive-failure count (within the trip window)
	LastOK   string `json:"last_ok,omitempty"`
	LastFail string `json:"last_fail,omitempty"`
	// BreakRemaining is the remaining seconds of this upstream's current trip (0 = not
	// tripped). Active health checks and manual verification both read/write
	// last_ok/last_fail/break, and the page uses them to filter out dead proxies.
	BreakRemaining int `json:"break_remaining,omitempty"`
}

// selector holds the pool's in-memory state and strategy. Persistence lives on the server
// side (settings+json); this only handles selection.
type selector struct {
	mu       sync.Mutex
	entries  []*poolUpstream // enabled entries
	strategy string          // round_robin / sticky_host / sticky_host_random / random
	rr       atomic.Uint64   // rotation cursor (shared by round_robin/random)
	// hostPick records sticky_host_random's "target → chosen upstream" binding, so the same
	// target keeps egressing through the same exit for a whole session (like a real user)
	// without re-rolling the dice for every host.
	// It stores URL strings rather than pointers: a full pool reload swaps the entry
	// pointers, while the strings still match.
	hostPick sync.Map
}

type poolUpstream struct {
	raw       *url.URL
	name      string
	weight    int
	failures  atomic.Int64
	lastFail  atomic.Int64 // unix
	lastOK    atomic.Int64 // unix
	breakOpen atomic.Int64 // trip expiry time (unix; 0 = not tripped)
}

const (
	breakAfterFails = 5                // N consecutive failures → tripped
	breakCooldown   = 10 * time.Minute // cooling-off window
)

// SetPool atomically replaces the whole pool (the server pushes the full set after every
// CRUD).
func (s *selector) SetPool(items []PoolEntry, strategy string) error {
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	switch strategy {
	case "", "round_robin", "sticky_host", "sticky_host_random", "random":
	default:
		return fmt.Errorf("unknown strategy %q (round_robin/sticky_host/sticky_host_random/random)", strategy)
	}
	ups := make([]*poolUpstream, 0, len(items))
	for _, it := range items {
		if !it.Enabled {
			continue
		}
		u, err := ValidateProxyURL(it.URL)
		if err != nil {
			continue // already validated on the server side; skip bad entries as a second line of defense
		}
		w := it.Weight
		if w < 1 {
			w = 1
		}
		nu := &poolUpstream{raw: u, name: it.Name, weight: w}
		// When the whole pool is pushed again, inherit the old entry's trip state (matched by
		// URL) so saving does not reset every trip.
		for _, prev := range s.entries {
			if prev.raw.String() == nu.raw.String() {
				nu.failures.Store(prev.failures.Load())
				nu.breakOpen.Store(prev.breakOpen.Load())
			}
		}
		ups = append(ups, nu)
	}
	s.mu.Lock()
	s.entries = ups
	s.strategy = strategy
	s.mu.Unlock()
	return nil
}

// Pick chooses an upstream for one target request. An empty pool or an all-tripped pool
// returns nil (direct connection, falling back to the global logic).
// host is the target "host:port"; the sticky_host strategy hashes it stably.
func (s *selector) Pick(host string) *url.URL {
	s.mu.Lock()
	entries := s.entries
	strategy := s.strategy
	s.mu.Unlock()
	if len(entries) == 0 {
		return nil
	}
	now := time.Now().Unix()
	available := make([]*poolUpstream, 0, len(entries))
	for _, e := range entries {
		if bo := e.breakOpen.Load(); bo != 0 && now < bo {
			continue // tripped
		}
		available = append(available, e)
	}
	if len(available) == 0 {
		return nil
	}
	switch strategy {
	case "sticky_host":
		h := fnv.New32a()
		_, _ = h.Write([]byte(host))
		return available[h.Sum32()%uint32(len(available))].raw
	case "sticky_host_random":
		// The first time a target is seen, pin a random upstream and keep it afterwards —
		// getting both "same target uses the same exit" and "different targets spread across
		// exits randomly". When the pinned one gets tripped, it is re-pinned automatically.
		if raw, ok := s.hostPick.Load(host); ok {
			if u := findUpstream(available, raw.(string)); u != nil {
				return u.raw
			}
		}
		u := available[s.rr.Add(1)%uint64(len(available))]
		s.hostPick.Store(host, u.raw.String())
		return u.raw
	case "random":
		return available[s.rr.Add(1)%uint64(len(available))].raw
	default: // round_robin, expanded by weight (higher weight appears more often)
		total := 0
		for _, e := range available {
			total += e.weight
		}
		n := s.rr.Add(1) - 1
		idx := n % uint64(total)
		for _, e := range available {
			if idx < uint64(e.weight) {
				return e.raw
			}
			idx -= uint64(e.weight)
		}
		return available[0].raw
	}
}

// ReportResult reports one upstream proxy result: a success resets the count and clears any
// trip; a failure counts and trips the upstream for breakCooldown at the threshold.
func (s *selector) ReportResult(proxyRaw string, ok bool) {
	if proxyRaw == "" {
		return
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	for _, e := range entries {
		if e.raw.String() != proxyRaw {
			continue
		}
		now := time.Now().Unix()
		if ok {
			e.failures.Store(0)
			e.breakOpen.Store(0) // one success clears the trip
			e.lastOK.Store(now)
			return
		}
		e.lastFail.Store(now)
		if n := e.failures.Add(1); n >= breakAfterFails {
			e.breakOpen.Store(time.Now().Add(breakCooldown).Unix())
			e.failures.Store(0)
		}
		return
	}
}

// MarkBad trips an upstream for the cooldown immediately (used by active health checks /
// Agent reports). Passive tripping waits for 5 consecutive failures, and retrying a proxy
// already known to be dead 5 more times only slows requests down for nothing — so an
// active determination cools it down at once. Returns the masked URL of the tripped
// upstream, empty string if not found.
func (s *selector) MarkBad(proxyRaw string, cooldown time.Duration) string {
	if proxyRaw == "" {
		return ""
	}
	if cooldown <= 0 {
		cooldown = breakCooldown
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	for _, e := range entries {
		if e.raw.String() != proxyRaw {
			continue
		}
		e.breakOpen.Store(time.Now().Add(cooldown).Unix())
		e.lastFail.Store(time.Now().Unix())
		e.failures.Store(0)
		// The pinning is invalidated too; sticky_host_random picks a different exit next time.
		s.hostPick.Range(func(k, v any) bool {
			if raw, _ := v.(string); raw == proxyRaw {
				s.hostPick.Delete(k)
			}
			return true
		})
		return maskURL(e.raw)
	}
	return ""
}

// BreakRemaining returns the remaining seconds of this upstream's current trip (0 = not
// tripped / not in the pool).
func (s *selector) BreakRemaining(proxyRaw string) int {
	if proxyRaw == "" {
		return 0
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	for _, e := range entries {
		if e.raw.String() != proxyRaw {
			continue
		}
		rest := int(e.breakOpen.Load() - time.Now().Unix())
		if rest < 0 {
			return 0
		}
		return rest
	}
	return 0
}

// Status exports the pool state (for the UI; URLs have credentials masked).
func (s *selector) Status() []PoolEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	out := make([]PoolEntry, 0, len(s.entries))
	for _, e := range s.entries {
		item := PoolEntry{
			URL:      maskURL(e.raw),
			Name:     e.name,
			Enabled:  true,
			Weight:   e.weight,
			Failures: int(e.failures.Load()),
		}
		if bo := e.breakOpen.Load(); bo > now {
			item.BreakRemaining = int(bo - now)
		}
		if t := e.lastOK.Load(); t > 0 {
			item.LastOK = time.Unix(t, 0).Format(time.RFC3339)
		}
		if t := e.lastFail.Load(); t > 0 {
			item.LastFail = time.Unix(t, 0).Format(time.RFC3339)
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// maskURL hides user:pass (the user is kept, the password becomes ****).
func maskURL(u *url.URL) string {
	c := *u
	if c.User != nil {
		if _, hasPass := c.User.Password(); hasPass {
			c.User = url.UserPassword(c.User.Username(), "****")
		}
	}
	return c.String()
}

// SetProxyPool atomically replaces the proxy pool (Traffic facade).
func (t *Traffic) SetProxyPool(items []PoolEntry, strategy string) error {
	sel := &selector{}
	if err := sel.SetPool(items, strategy); err != nil {
		return err
	}
	if len(items) == 0 {
		t.pool.Store(nil) // emptying the pool = fall back to the global proxy / direct connection
		return nil
	}
	t.pool.Store(sel)
	return nil
}

// ProxyPoolStatus exports the pool entries (masked URLs + trip counters) for the UI.
func (t *Traffic) ProxyPoolStatus() []PoolEntry {
	if pool := t.pool.Load(); pool != nil {
		return pool.Status()
	}
	return []PoolEntry{}
}

// ProxyPoolReportOK reports one success (resets the consecutive failures, records the
// time).
func (t *Traffic) ProxyPoolReportOK(proxyRaw string) {
	pool := t.pool.Load()
	if pool == nil {
		return
	}
	pool.ReportResult(proxyRaw, true)
}

// ProxyPoolReportFail reports one failure (only counts it; no immediate trip — the passive
// path trips at 5).
func (t *Traffic) ProxyPoolReportFail(proxyRaw string) {
	pool := t.pool.Load()
	if pool == nil {
		return
	}
	pool.ReportResult(proxyRaw, false)
}

// ProxyPoolMarkBad trips an upstream for the cooldown immediately (used by active health
// checks / failed manual verification). Returns the masked URL of the tripped upstream,
// empty string if it is not in the pool.
func (t *Traffic) ProxyPoolMarkBad(proxyRaw string, cooldown time.Duration) string {
	pool := t.pool.Load()
	if pool == nil {
		return ""
	}
	return pool.MarkBad(proxyRaw, cooldown)
}

// ProxyPoolReportBad lets the caller (the Agent) trip "the exit a target is currently
// using" immediately. target may be a full host:port — the MITM side records the most
// recently selected upstream per host, so the requester does not need to know which proxy
// was actually used. Returns the masked URL of the tripped upstream; an empty string means
// the pool is empty / that target never went through a pool upstream (e.g. direct
// connection or a single global proxy).
func (t *Traffic) ProxyPoolReportBad(target string, cooldown time.Duration) string {
	pool := t.pool.Load()
	if pool == nil {
		return ""
	}
	raw, ok := t.lastPick.Load(hostOnly(target))
	if !ok {
		return ""
	}
	u, _ := raw.(string)
	return pool.MarkBad(u, cooldown)
}

// Available returns the number of upstreams not currently tripped.
func (s *selector) Available() int {
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	now := time.Now().Unix()
	n := 0
	for _, e := range entries {
		if bo := e.breakOpen.Load(); bo != 0 && now < bo {
			continue
		}
		n++
	}
	return n
}

// SnapshotBreaks exports the not-yet-expired trip state (unmasked raw URL → release time unix).
// A process restart rebuilds the selector; without persisting, every exit already judged dead
// becomes "available" again and tasks burn another round of timeouts — measured on production,
// 231 of 240 dead proxies all came back to life after a restart.
func (s *selector) SnapshotBreaks() map[string]int64 {
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	now := time.Now().Unix()
	out := map[string]int64{}
	for _, e := range entries {
		if bo := e.breakOpen.Load(); bo > now {
			out[e.raw.String()] = bo
		}
	}
	return out
}

// RestoreBreaks applies persisted trip state (only entries still within their window count).
func (s *selector) RestoreBreaks(state map[string]int64) int {
	if len(state) == 0 {
		return 0
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	now := time.Now().Unix()
	n := 0
	for _, e := range entries {
		until, ok := state[e.raw.String()]
		if !ok || until <= now {
			continue
		}
		e.breakOpen.Store(until)
		if e.lastFail.Load() == 0 {
			e.lastFail.Store(now)
		}
		n++
	}
	return n
}

// findUpstream finds an entry by its original URL among a set of candidates (the pinning
// is reconciled by URL string, so it survives a pool reload).
func findUpstream(list []*poolUpstream, raw string) *poolUpstream {
	for _, e := range list {
		if e.raw.String() == raw {
			return e
		}
	}
	return nil
}

// ClearBreak clears an upstream's trip/failure state (called after an import or manual
// liveness check passes). Without the reset, "the check says it works but the page still shows
// 0 available" — the old trip state is inherited on the next pool push.
func (s *selector) ClearBreak(proxyRaw string) bool {
	if proxyRaw == "" {
		return false
	}
	s.mu.Lock()
	entries := s.entries
	s.mu.Unlock()
	for _, e := range entries {
		if e.raw.String() != proxyRaw {
			continue
		}
		e.failures.Store(0)
		e.breakOpen.Store(0)
		return true
	}
	return false
}

// MarkBad trips an upstream for the cooldown immediately (used by active health checks / Agent
// reports). Passive tripping waits for 5 consecutive failures, and retrying a proxy already known
// to be dead 5 more times only slows requests down for nothing — so an active determination cools
// it down at once. Returns the masked URL of the tripped upstream, empty string if not found.

// ProxyPoolClearBreak clears an upstream's trip state (called after an import or manual liveness
// check succeeds). Returns whether the entry was found; false when the pool is empty.
func (t *Traffic) ProxyPoolClearBreak(proxyRaw string) bool {
	pool := t.pool.Load()
	if pool == nil {
		return false
	}
	return pool.ClearBreak(proxyRaw)
}

// ProxyPoolMarkBad trips an upstream for the cooldown immediately (used by active health checks /
// on a failed manual verification). Returns the masked URL of the tripped upstream, empty string if
// it isn't in the pool.

// An empty host is treated as one "virtual target" per policy; sticky_host_random therefore pins
// the whole machine to a single exit, matching the "one exit per task" intuition.
func (t *Traffic) ProxyPoolPick(host string) string {
	pool := t.pool.Load()
	if pool == nil {
		return ""
	}
	if u := pool.Pick(host); u != nil {
		return u.String()
	}
	return ""
}

// ProxyPoolAvailable returns the number of upstreams not currently tripped (the UI shows "N/M available").
func (t *Traffic) ProxyPoolAvailable() int {
	pool := t.pool.Load()
	if pool == nil {
		return 0
	}
	return pool.Available()
}

// SnapshotProxyBreaks exports unexpired trip state (for the server to persist across restarts).
func (t *Traffic) SnapshotProxyBreaks() map[string]int64 {
	pool := t.pool.Load()
	if pool == nil {
		return nil
	}
	return pool.SnapshotBreaks()
}

// RestoreProxyBreaks applies persisted trip state and returns the number of entries restored.
func (t *Traffic) RestoreProxyBreaks(state map[string]int64) int {
	pool := t.pool.Load()
	if pool == nil {
		return 0
	}
	return pool.RestoreBreaks(state)
}

// strictBlockProxy is the sentinel address returned under "strict egress" when the pool is fully
// tripped: 127.0.0.1:1 always fails to connect, so the request errors out fast instead of going
// direct and leaking the real IP.
const strictBlockProxy = "http://127.0.0.1:1"

// SetStrictEgress toggles strict egress: with a pool configured but no usable upstream, both MITM
// and Agent fail rather than falling back to a direct connection. Injected by the server from the
// egress_strict_proxy setting.
func (t *Traffic) SetStrictEgress(on bool) { t.strictEgress.Store(on) }

// SetDirectRecordFallback enables "direct dial but still record" when strict
// egress is on and every pool upstream is broken. Operators opt in explicitly;
// it trades real-IP exposure for continuous traffic evidence.
func (t *Traffic) SetDirectRecordFallback(on bool) { t.directRecordFallback.Store(on) }

// DirectRecordFallback reports the current fallback switch.
func (t *Traffic) DirectRecordFallback() bool { return t.directRecordFallback.Load() }

// StrictEgress returns the current strict-egress switch state.
func (t *Traffic) StrictEgress() bool { return t.strictEgress.Load() }

// ProxyPoolConfigured reports whether the pool has any enabled entry (a fully tripped pool still counts as configured).
func (t *Traffic) ProxyPoolConfigured() bool {
	pool := t.pool.Load()
	if pool == nil {
		return false
	}
	return pool.Configured()
}

// Configured reports whether the selector holds at least one enabled entry.
func (s *selector) Configured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries) > 0
}
