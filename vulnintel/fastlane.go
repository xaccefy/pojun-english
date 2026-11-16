package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// "Recent Critical Fast Lane": specifically gets newly disclosed critical vulnerabilities into the intelligence database as quickly as possible.
//
// ## Why it's needed
//
// The main sync uses NVD's lastModifiedDate window (≤120 days), advancing the cursor by window, and can't finish in one
// MaxRuntime. That structure is right for "backfilling the historical catalog" but wrong for "vulnerabilities that just broke" — a CRITICAL disclosed yesterday has to wait for the main sync's cursor to crawl to its window
// before it enters the database.
//
// Real-world testing on 2026-10-22 confirmed this and exposed a second problem:
//
//	CVE-2026-109618 (disclosed 2026-10-21, CRITICAL, PHP → RCE)
//	CVE-2026-109619 (disclosed 2026-10-21, CRITICAL, PHP → RCE)
//
// Both were disclosed **yesterday**, NVD already has full records (description, reference links, GHSA advisory,
// and Wiz's analysis blog are all there), but: the main sync hasn't crawled to that window → not in the database; and their
// **affected version ranges are empty** (cpe:2.3:a:php:php:*:*:*:*:*:*:*:*:*) — NVD hasn't
// filled them in, meaning even if synced, we can't determine whether the target PHP version is affected.
//
// The fast lane solves two things:
//  1. **Timeliness**: pull "just-disclosed" records in small publishedDate windows, keep only CVSS≥9.0 or
//     CISA KEV, into the database within tens of minutes;
//  2. **Version-undetermined visibility**: when the version range is missing, it **must not be judged as "unaffected"** — explicitly mark
//     it "version undetermined" so the model knows this component is worth trying (see VersionRangeUndetermined).
//
// ## Relationship with the main sync
//
// - **Shares the vuln_cves table**: the agent queries the same database, no second query entry point needed.
// - **Independent cursor** (fastLaneSyncSource ≠ "nvd"): the fast lane advances the publishedDate
//   cursor and must not advance the main sync's lastModified cursor.
// - **Window overlap** (fastLaneOverlapHours): NVD's indexing of new records is delayed; without overlap
//   records will be missed.
// - **Pagination cap**: if a single run can't finish, continue next run (cursor advances by window), don't force it.

const (
	// fastLaneSyncSource is the fast lane's cursor key (stored in vuln_sync_state.source).
	//
	// Must be a distinct value: the main sync uses "nvd" for the lastModified cursor; the two have different semantics
	// (one is "when it was modified", the other is "when it was published"), sharing one cursor
	// would scramble the progress of one of the chains.
	fastLaneSyncSource = "nvd_fastlane"

	// fastLaneMinWindowDays is the lower bound of the fast lane window (days).
	//
	// 7 isn't arbitrary: real-world testing (2026-10-22, via proxy) showed **1–3 day publishedDate windows
	// time out** (NVD is still indexing freshly published records, queries are slow), while a 7-day window fetched 24513 records
	// in 17 seconds. Smaller window → can't pull; larger window → slow and redundant data.
	fastLaneMinWindowDays = 7

	// fastLaneOverlapHours is the overlap in hours between consecutive run windows.
	//
	// NVD has indexing delay for freshly published records — a just-disclosed CVE may not yet be
	// findable on the first pull. 24 hours of overlap is the value NVD's own lastModified incremental window uses in testing,
	// here we take its lower bound of 12 hours: missing one CRITICAL costs far more than pulling a bit extra.
	fastLaneOverlapHours = 12

	// fastLanePageSize is the number of records per fast lane page.
	//
	// Tested: on the publishedDate dimension a single page of 2000 times out (60s client timeout),
	// 1000 is more stable. The main sync uses 2000 because it works on lastModified windows with a different data distribution.
	fastLanePageSize = 1000

	// fastLaneMaxPagesPerRun is the maximum number of pages per run.
	//
	// The cap exists to "not take up the whole run": the fast lane's value is timeliness, it shouldn't compete with the main sync for
	// time budget. If it can't finish, leave the cursor for the next run.
	fastLaneMaxPagesPerRun = 20
)

// VersionRangeUndetermined determines whether a CVE's affected version range is "undetermined".
//
// Observation (tested 2026-10-22): for newly disclosed CVEs, NVD often only gives
// `cpe:2.3:a:php:php:*:*:*:*:*:*:*:*` — the version field is `*`, and there are no
// versionStart/versionEnd fields. In this case it **cannot** be judged as "target version unaffected".
//
// Two forms that count as "determined":
//  1. the version field in criteria is a concrete version (fixed-version products, e.g. 1.2.3);
//  2. Ranges has explicit start/end boundaries (e.g. 2.4.49 ~ <2.4.50).
func VersionRangeUndetermined(c CVE) bool {
	// Has a structured range → determined.
	for _, r := range c.Ranges {
		if r.StartIncluding != "" || r.StartExcluding != "" ||
			r.EndIncluding != "" || r.EndExcluding != "" {
			return false
		}
	}
	// A non-* version field in criteria → determined (fixed version).
	for _, crit := range c.Criteria {
		if cpeVersionPinned(crit) {
			return false
		}
	}
	// No criteria at all → affected range also unknown.
	if len(c.Criteria) == 0 {
		return true
	}
	return true
}

// cpeVersionPinned determines whether a CPE's version field is a concrete version (not * or -).
func cpeVersionPinned(criteria string) bool {
	if !strings.HasPrefix(criteria, "cpe:2.3:") {
		return false
	}
	parts := splitUnescapedColons(criteria)
	// cpe:2.3:<part>:<vendor>:<product>:<version>:...
	// After splitting: parts[0]=cpe, [1]=2.3, [2]=part, [3]=vendor, [4]=product,
	// [5]=version (consistent with cpeVendorProduct's index convention).
	if len(parts) < 6 {
		return false
	}
	v := parts[5]
	return v != "" && v != "*" && v != "-"
}

// VersionUndeterminedNote is the hint text for the "version undetermined" case.
//
// The wording is critical: it must make clear "**does not mean unaffected**". Otherwise the model will read
// "version range unknown" as "version not in the affected range" and skip it — which is exactly where newly disclosed CVEs are most often lost.
func VersionUndeterminedNote() string {
	return "Affected version range undetermined (NVD has not filled it in): this does not mean the target version is unaffected, " +
		"treat it as 'this component has a recent critical vulnerability' — check the vendor advisory (the GHSA/" +
		"security advisory in refs) to confirm the affected and fixed versions, then decide whether to verify."
}

// FastLaneConfig is the fast lane's configuration.
type FastLaneConfig struct {
	// ProxyURL is the outbound proxy (empty = direct connection).
	ProxyURL string
	// NvdAPIKey raises the NVD rate limit quota (optional).
	NvdAPIKey string
	// WindowDays is the lookback window (days). Values below fastLaneMinWindowDays are raised to the lower bound.
	WindowDays int
	// MaxRuntime is the per-run wall-clock upper limit.
	MaxRuntime time.Duration
	// PageDelay is the inter-page delay (NVD anonymous access rate limit is about 5 requests/30s).
	PageDelay time.Duration
}

// FastLaneResult is the result of one fast lane run.
type FastLaneResult struct {
	// Scanned is the number of records scanned this run (all pulled back, not just those stored).
	Scanned int
	// Stored is the number of records stored this run (those passing the critical check).
	Stored int
	// KEVStored is the number of those that are CISA KEV.
	KEVStored int
	// VersionUndetermined is the number of stored records that are "version undetermined".
	VersionUndetermined int
	// Cursor is the cursor at the end of this run (next run continues from here).
	Cursor string
	// Truncated being true means this run didn't finish due to the page/time limit (cursor preserved).
	Truncated bool
}

// RunFastLane pulls recently-published critical CVEs and stores them.
//
// Flow: page through small publishedDate windows → filter for critical → store (reusing UpsertCVE,
// using the same table and same set of CPE indexes) → advance cursor.
//
// Only two differences from the main sync: query dimension (publishedDate vs lastModifiedDate) and
// filtering (critical only vs all). **No new tables, no new agent tool entry points** — the agent side
// still queries the same database, just with one more "recent critical" query.
func RunFastLane(ctx context.Context, st *Store, cfg FastLaneConfig) (FastLaneResult, error) {
	var res FastLaneResult
	client, err := NewNvdClient(cfg.NvdAPIKey, cfg.ProxyURL)
	if err != nil {
		return res, err
	}
	state, err := st.GetSyncState(ctx, fastLaneSyncSource)
	if err != nil {
		return res, err
	}

	now := time.Now()
	windowDays := cfg.WindowDays
	if windowDays < fastLaneMinWindowDays {
		windowDays = fastLaneMinWindowDays
	}
	// The cursor is "where we last pulled to". No cursor → start from windowDays ago; has cursor → go back
	// overlap hours from the cursor (overlap, to avoid missing records due to NVD indexing delay).
	from := now.AddDate(0, 0, -windowDays)
	if state.Cursor != "" {
		if t, e := time.Parse(time.RFC3339, state.Cursor); e == nil {
			from = t.Add(-time.Duration(fastLaneOverlapHours) * time.Hour)
		}
	}

	deadline := time.Now().Add(cfg.MaxRuntime)
	pages := 0
	for winStart := from; winStart.Before(now); {
		winEnd := winStart.AddDate(0, 0, windowDays)
		if winEnd.After(now) {
			winEnd = now
		}
		startIndex := 0
		for {
			if pages >= fastLaneMaxPagesPerRun {
				res.Truncated = true
				break
			}
			if !deadline.IsZero() && time.Now().After(deadline) {
				res.Truncated = true
				break
			}
			page, err := client.FetchPublished(ctx, startIndex, fastLanePageSize, winStart, winEnd)
			if err != nil {
				// A window that can't be pulled (occasional NVD-side timeout) isn't a failure: keep the cursor, retry next run.
				log.Printf("[vulnintel] fast lane window %s page %d failed: %v",
					winStart.Format("2006-01-02"), startIndex, err)
				break
			}
			if len(page.Vulnerabilities) == 0 {
				break
			}
			pages++
			for _, w := range page.Vulnerabilities {
				res.Scanned++
				c, ok := ToCVE(w)
				if !ok {
					continue
				}
				score, _, _ := pickScore(w.CVE.Metrics)
				// Don't check the KEV flag this round (KEV has its own sync source), only look at the score.
				if !isRecentCritical(score, false) {
					continue
				}
				if err := st.UpsertCVE(ctx, c); err != nil {
					log.Printf("[vulnintel] fast lane store %s failed: %v", c.ID, err)
					continue
				}
				res.Stored++
				// "Version undetermined" is judged by **combining two sources**: NVD not filling the range doesn't count as undetermined
				// if GHSA has already filled it in (HasVersionRange checks the actual state after storage,
				// including what GHSA added), then this record's version range is known.
				//
				// Looking only at NVD's VersionRangeUndetermined(c) would count vulnerabilities where "GHSA has already
				// filled in the range" as undetermined — that's exactly the problem M10 is meant to fix.
				if VersionRangeUndetermined(c) && !st.HasVersionRange(ctx, c.ID) {
					res.VersionUndetermined++
				}
			}
			startIndex += fastLanePageSize
			if startIndex >= page.TotalResults {
				break
			}
			// Don't wait for the inter-page delay here — the **shared rate-limit gate** in NvdClient.fetch already
			// controls it centrally (main sync and fast lane share the quota, see ratelimit.go). Waiting again
			// here would halve the rate.
		}
		if res.Truncated {
			break
		}
		// Window done → advance cursor to the end of the window.
		state.Cursor = winEnd.UTC().Format(time.RFC3339)
		state.TotalSynced += int64(res.Stored)
		state.LastError = ""
		if err := st.SaveSyncState(ctx, state); err != nil {
			return res, err
		}
		res.Cursor = state.Cursor
		winStart = winEnd
	}
	if res.Cursor == "" {
		res.Cursor = state.Cursor
	}
	if res.Truncated {
		// Not finished: leave the cursor at the current window start, next run continues from there (with overlap).
		state.Cursor = from.UTC().Format(time.RFC3339)
		state.LastError = "fast lane did not finish this run (page or time limit), cursor preserved"
		if err := st.SaveSyncState(ctx, state); err != nil {
			return res, err
		}
		res.Cursor = state.Cursor
	}
	return res, nil
}

// RecentCriticalHits is the query result for "recent critical vulnerabilities".
type RecentCriticalHits struct {
	CVEID    string  `json:"cve_id"`
	Severity string  `json:"severity"`
	Score    float64 `json:"cvss_score"`
	KEV      bool    `json:"kev"`
	Title    string  `json:"title"`
	// Published is an ISO date string.
	Published string `json:"published"`
	// VersionUndetermined being true means NVD hasn't filled in the affected version range yet.
	VersionUndetermined bool `json:"version_undetermined"`
	// Products is the affected products (in vendor/product form).
	Products []string `json:"products"`
}

// SearchRecentCritical returns recently published critical CVEs.
//
// The difference from SearchVulns: SearchVulns queries by **component** (product name → CVE), this one queries by
// **time** (recently disclosed criticals), so when a worker "just scanned a PHP asset" it can
// directly ask "what criticals has PHP had recently" without first needing to know which CVE numbers to look up.
//
// days limits the lookback days (default 7, 0 = use default). limit caps at 100.
func (s *Store) SearchRecentCritical(ctx context.Context, days, limit int) ([]RecentCriticalHits, error) {
	if days <= 0 {
		days = 7
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, c.severity, COALESCE(c.cvss_score,0), c.kev,
       COALESCE(c.published_at::text,''), COALESCE(c.title,''),
       COALESCE(c.cpe_criteria::text,'[]')
  FROM vuln_cves c
 WHERE c.published_at > now() - ($1 || ' days')::interval
   AND (c.kev = true OR COALESCE(c.cvss_score,0) >= $2)
 ORDER BY c.kev DESC, c.cvss_score DESC NULLS LAST, c.published_at DESC
 LIMIT $3`, fmt.Sprint(days), recentCriticalScoreThreshold, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecentCriticalHits{}
	for rows.Next() {
		var h RecentCriticalHits
		var criteria string
		if err := rows.Scan(&h.CVEID, &h.Severity, &h.Score, &h.KEV,
			&h.Published, &h.Title, &criteria); err != nil {
			return nil, err
		}
		h.Products = productsFromCriteria(criteria)
		h.VersionUndetermined = len(h.Products) > 0 && allCriteriaUnpinned(criteria)
		out = append(out, h)
	}
	return out, rows.Err()
}

// productsFromCriteria extracts vendor/product form from the cpe_criteria JSON array.
func productsFromCriteria(criteriaJSON string) []string {
	var crits []string
	if err := json.Unmarshal([]byte(criteriaJSON), &crits); err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range crits {
		v, p, ok := cpeVendorProduct(c)
		if !ok || p == "" {
			continue
		}
		key := p
		if v != "" {
			key = v + "/" + p
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// allCriteriaUnpinned determines whether the version fields in the criteria array are all * (version undetermined).
func allCriteriaUnpinned(criteriaJSON string) bool {
	var crits []string
	if err := json.Unmarshal([]byte(criteriaJSON), &crits); err != nil {
		return true
	}
	if len(crits) == 0 {
		return true
	}
	for _, c := range crits {
		if cpeVersionPinned(c) {
			return false
		}
	}
	return true
}
