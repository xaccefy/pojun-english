// Package vulnintel maintains periodically synced public vulnerability intelligence (NVD /
// CISA KEV) so the agent can look up known vulnerabilities and ready-made exploits right
// after identifying a target component, instead of relying on the model to improvise every
// time. All data comes from public sources; sync egress goes through the global egress proxy.
// The table structure is in db/schema.sql: vuln_cves / vuln_cpe_products / vuln_pocs /
// vuln_sync_state.
package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// Store provides writing (the synchronizer) and querying (agent tools) of vulnerability
// intelligence.
type Store struct {
	db *db.DB
}

// New wraps an opened database. Tables live in db/schema.sql and are created
// by the idempotent startup migration, so there is no separate Ensure here.
func New(d *db.DB) *Store { return &Store{db: d} }

// CVE is the smallest record written by one sync.
type CVE struct {
	ID          string
	Title       string
	Description string
	Severity    string // CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN
	Score       *float64
	Vector      string
	Published   time.Time
	Modified    time.Time
	Criteria    []string // the raw cpe:2.3:... string (including the version range syntax)
	Refs        []string
	Ranges      []CPERange // structured version ranges (versionStart/End fields) for exact version matching
	Cwes        []string   // weakness identifiers (NVD weaknesses / GHSA cwes), used for skill linkage
}

// CPERange is the version range of one cpeMatch (empty string = that bound does not exist).
type CPERange struct {
	Criteria       string
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

// UpsertCVE writes one record: the row itself plus a rebuilt (vendor, product)
// inverted index. KEV columns are owned by the KEV sync and are NOT touched.
func (s *Store) UpsertCVE(ctx context.Context, c CVE) error {
	if c.ID == "" {
		return fmt.Errorf("vulnintel: empty cve id")
	}
	criteria := marshalJSONB(c.Criteria)
	refs := marshalJSONB(c.Refs)
	cwes := marshalTextArray(c.Cwes)
	rangesByCriteria := map[string]CPERange{}
	for _, r := range c.Ranges {
		rangesByCriteria[r.Criteria] = r
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cves
		(cve_id, source, title, description, severity, cvss_score, cvss_vector,
		 published_at, modified_at, cpe_criteria, refs, cwes, synced_at)
		VALUES ($1,'nvd',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::text[],now())
		ON CONFLICT (cve_id) DO UPDATE SET
		  title=EXCLUDED.title, description=EXCLUDED.description,
		  severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score,
		  cvss_vector=EXCLUDED.cvss_vector, published_at=EXCLUDED.published_at,
		  modified_at=EXCLUDED.modified_at, cpe_criteria=EXCLUDED.cpe_criteria,
		  refs=EXCLUDED.refs,
		  -- cwes exists in both sources: merge and deduplicate (NVD weaknesses and GHSA cwes
		  -- may classify the same CVE complementarily, and a later write must not erase an
		  -- earlier one).
		  cwes=(SELECT ARRAY(SELECT DISTINCT unnest(vuln_cves.cwes || EXCLUDED.cwes))),
		  synced_at=now()`,
		c.ID, c.Title, c.Description, c.Severity, c.Score, c.Vector,
		nullTime(c.Published), nullTime(c.Modified), criteria, refs, cwes); err != nil {
		return fmt.Errorf("upsert vuln_cves %s: %w", c.ID, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM vuln_cpe_products WHERE cve_id=$1`, c.ID); err != nil {
		return fmt.Errorf("clear cpe index %s: %w", c.ID, err)
	}
	seen := map[string]bool{}
	for _, cr := range c.Criteria {
		vendor, product, ok := cpeVendorProduct(cr)
		if !ok {
			continue
		}
		// Several cpeMatch ranges for the same (cve,vendor,product) are unioned: each bound field
		// collects every non-empty value, and a query matches when any bound hits.
		key := vendor + "\x00" + product
		if seen[key] {
			// Row already exists: merge the range fields (different cpeMatch entries may give
			// different ranges).
			s.mergeRange(ctx, c.ID, vendor, product, rangesByCriteria[cr])
			continue
		}
		seen[key] = true
		r := rangesByCriteria[cr]
		if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cpe_products
			(cve_id, vendor, product, version_start_incl, version_start_excl, version_end_incl, version_end_excl)
			VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''))
			ON CONFLICT (cve_id, vendor, product) DO UPDATE SET
			  version_start_incl = COALESCE(vuln_cpe_products.version_start_incl, NULLIF($4,'')),
			  version_start_excl = COALESCE(vuln_cpe_products.version_start_excl, NULLIF($5,'')),
			  version_end_incl   = COALESCE(vuln_cpe_products.version_end_incl,   NULLIF($6,'')),
			  version_end_excl   = COALESCE(vuln_cpe_products.version_end_excl,   NULLIF($7,''))`,
			c.ID, vendor, product, r.StartIncluding, r.StartExcluding, r.EndIncluding, r.EndExcluding); err != nil {
			return fmt.Errorf("index cpe %s: %w", c.ID, err)
		}
	}
	return nil
}

// MarkKEV sets the in-the-wild exploitation flag. Rows unknown to the NVD sync
// (KEV moves faster than NVD sometimes) get a stub row so the flag is visible.
func (s *Store) MarkKEV(ctx context.Context, cveID string, added time.Time) error {
	tag := "KEV: " + added.Format("2006-01-02")
	res, err := s.db.ExecContext(ctx, `UPDATE vuln_cves SET kev=true, kev_date_added=$2 WHERE cve_id=$1`, cveID, nullTime(added))
	if err != nil {
		return fmt.Errorf("mark kev %s: %w", cveID, err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO vuln_cves (cve_id, source, title, severity, kev, kev_date_added)
		VALUES ($1,'kev',$2,'UNKNOWN',true,$3) ON CONFLICT (cve_id) DO UPDATE SET kev=true, kev_date_added=$3`,
		cveID, tag, nullTime(added))
	if err != nil {
		return fmt.Errorf("insert kev stub %s: %w", cveID, err)
	}
	return nil
}

// VulnHit is one search_vulns result (detail fields are deliberately trimmed so the LLM sees
// the summary first).
type VulnHit struct {
	CVEID     string   `json:"cve_id"`
	Severity  string   `json:"severity"`
	Score     *float64 `json:"cvss_score,omitempty"`
	KEV       bool     `json:"kev"`
	Published string   `json:"published,omitempty"`
	Title     string   `json:"title"`
	// The (vendor, product) pair that matched; the LLM uses it to confirm the search terms
	// really line up with the target component.
	Matched []string `json:"matched,omitempty"`
	// Set when version is non-empty and appears in some criteria's version field — a coarse
	// filter signal; whether the version truly falls inside the affected range is for the LLM to
	// judge together with the criteria.
	VersionSeen bool `json:"version_seen_in_criteria"`
	// VersionInRange is tri-state: nil = undeterminable (no structured range); true/false = the
	// structured-range verdict (true when any cpeMatch range hits).
	VersionInRange *bool `json:"version_in_range,omitempty"`
	// Source is where this record came from: nvd / ghsa.
	//
	// Why it is labeled: GHSA version ranges are **mandatory** (NVD often leaves them empty), so
	// the two sides may judge the same CVE differently — the model needs to know "which source
	// supplied this range" in order to weigh it.
	Source string `json:"source,omitempty"`
	// Cwes holds weakness identifiers (CWE-79 and the like). get_vuln/search_vulns hand it to
	// the model, and the CWE→skill mapping injected by the server at assembly time uses it to
	// suggest the matching methodology skill.
	Cwes []string `json:"cwes,omitempty"`
}

// SearchVulns looks up known vulnerabilities by component name (optionally vendor-qualified).
// product matches the CPE product segment (case-insensitive, with % wildcards passed to
// ILIKE); KEV first, then score.
func (s *Store) SearchVulns(ctx context.Context, vendor, product, version string, limit int) ([]VulnHit, error) {
	product = strings.TrimSpace(product)
	if product == "" {
		return nil, fmt.Errorf("product is required")
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	pattern := strings.ToLower(product)
	if !strings.ContainsAny(pattern, "%_") {
		pattern = "%" + pattern + "%"
	}
	// Fixed placeholders: optional filters are always passed (empty = no filter).
	// Conditionally appended $N breaks PostgreSQL when the numbers skip a slot.
	args := []any{pattern, strings.TrimSpace(vendor), strings.TrimSpace(version), limit}
	rows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, c.severity, c.cvss_score, c.kev, COALESCE(c.published_at::text,''),
       COALESCE(c.title,''), c.kev_date_added IS NOT NULL AS kev_row,
       COALESCE(array_to_json(c.cwes)::text,'[]'),
       COALESCE((
         SELECT string_agg(DISTINCT p.vendor || '/' || p.product, ', ')
         FROM vuln_cpe_products p WHERE p.cve_id = c.cve_id AND p.product ILIKE $1
       ), '') AS matched,
       MIN(p.product) AS hit_product,
       c.source
FROM vuln_cves c
JOIN vuln_cpe_products p ON p.cve_id = c.cve_id AND p.product ILIKE $1
                        AND ($2 = '' OR p.vendor ILIKE '%' || $2 || '%')
GROUP BY c.id
ORDER BY c.kev DESC,
         (CASE WHEN $3 <> '' AND c.cpe_criteria::text LIKE '%' || $3 || '%' THEN 1 ELSE 0 END) DESC,
         c.cvss_score DESC NULLS LAST, c.published_at DESC
LIMIT $4`, args...)
	if err != nil {
		return nil, fmt.Errorf("search vulns: %w", err)
	}
	defer rows.Close()
	version = strings.TrimSpace(version)
	out := []VulnHit{}
	for rows.Next() {
		var h VulnHit
		var kevRow bool
		var matched, hitProduct, cwesJSON string
		if err := rows.Scan(&h.CVEID, &h.Severity, &h.Score, &h.KEV, &h.Published, &h.Title, &kevRow, &cwesJSON, &matched, &hitProduct, &h.Source); err != nil {
			return nil, err
		}
		h.Cwes = unmarshalStringArray([]byte(cwesJSON))
		if kevRow {
			h.KEV = true
		}
		if matched != "" {
			h.Matched = strings.Split(matched, ", ")
		}
		if version != "" && s.criteriaContains(ctx, h.CVEID, version) {
			h.VersionSeen = true
		}
		if version != "" {
			if in, comparable := s.VersionInRange(ctx, h.CVEID, hitProduct, version); comparable {
				h.VersionInRange = &in
			}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// criteriaContains reads the stored criteria array and reports whether the
// version string appears as an exact CPE field. Deliberately exact-token
// semantics (e.g. "2.4.49" matching the version slot) — precision filtering is
// the LLM's job on the returned criteria; this only boosts ordering.
func (s *Store) criteriaContains(ctx context.Context, cveID, version string) bool {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT cpe_criteria FROM vuln_cves WHERE cve_id=$1`, cveID).Scan(&raw); err != nil || len(raw) == 0 {
		return false
	}
	var items []string
	if json.Unmarshal(raw, &items) != nil {
		return false
	}
	for _, it := range items {
		for _, part := range strings.Split(it, ":") {
			if part == version {
				return true
			}
		}
	}
	return false
}

// VulnDetail is the get_vuln return: full description, score and the raw criteria/refs.
type VulnDetail struct {
	CVEID       string   `json:"cve_id"`
	Severity    string   `json:"severity"`
	Score       *float64 `json:"cvss_score,omitempty"`
	Vector      string   `json:"cvss_vector,omitempty"`
	KEV         bool     `json:"kev"`
	Published   string   `json:"published,omitempty"`
	Modified    string   `json:"modified,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Criteria    []string `json:"cpe_criteria,omitempty"`
	Refs        []string `json:"references,omitempty"`
	// Source is where the data came from: nvd / ghsa.
	Source string `json:"source,omitempty"`
	// Cwes holds weakness identifiers (CWE-79 and the like) — the agent side uses them to
	// suggest the matching methodology skill.
	Cwes []string `json:"cwes,omitempty"`
	// VersionRanges holds the structured affected version ranges (one per component).
	//
	// Why it is listed separately: in cpe_criteria, NVD supplies CPE strings (the model would
	// have to parse the versionEndExcluding syntax itself) and GHSA supplies
	// "ghsa:composer/xxx < 3.10.0" — either way the model would have to parse it again. Here the
	// ranges are given **already normalized**: VersionInRange true means that component is
	// affected.
	VersionRanges []VulnVersionRange `json:"version_ranges,omitempty"`
}

// VulnVersionRange is one normalized affected version range.
type VulnVersionRange struct {
	// Vendor / Product identify the component.
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	// StartIncluding / StartExcluding / EndIncluding / EndExcluding are the bounds (empty string =
	// that bound does not exist). The semantics match NVD's cpeMatch range fields.
	StartIncluding string `json:"start_including,omitempty"`
	StartExcluding string `json:"start_excluding,omitempty"`
	EndIncluding   string `json:"end_including,omitempty"`
	EndExcluding   string `json:"end_excluding,omitempty"`
	// Source is where this range came from (nvd / ghsa) — the same CVE may have ranges from both
	// sides.
	Source string `json:"source,omitempty"`
	// Raw is the original range text (for display).
	Raw string `json:"raw,omitempty"`
}

// HasVersionRange reports whether the database already holds a **structured version range** for
// this CVE.
//
// Difference from VersionRangeUndetermined: that one only looks at the NVD information carried
// by the CVE record, while this one checks the **actual state after persistence** — ranges
// contributed by GHSA count too.
//
// Purpose: the fast lane must use this (the merged verdict) when tallying "version
// undetermined", rather than looking at NVD alone.
func (s *Store) HasVersionRange(ctx context.Context, cveID string) bool {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM vuln_cpe_products
		WHERE cve_id=$1
		  AND (version_start_incl IS NOT NULL OR version_start_excl IS NOT NULL
		    OR version_end_incl IS NOT NULL OR version_end_excl IS NOT NULL)
		LIMIT 1`, strings.ToUpper(strings.TrimSpace(cveID))).Scan(&n)
	return err == nil && n > 0
}

// GetVuln returns the full record for one CVE (nil, nil when absent).
func (s *Store) GetVuln(ctx context.Context, cveID string) (*VulnDetail, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	var d VulnDetail
	var criteria, refs, cwes []byte
	var pub, mod *time.Time
	err := s.db.QueryRowContext(ctx, `SELECT cve_id, severity, cvss_score, COALESCE(cvss_vector,''),
		kev, published_at, modified_at, title, description, cpe_criteria, refs, source,
		COALESCE(array_to_json(cwes)::text,'[]')
		FROM vuln_cves WHERE cve_id=$1`, cveID).
		Scan(&d.CVEID, &d.Severity, &d.Score, &d.Vector, &d.KEV, &pub, &mod, &d.Title, &d.Description, &criteria, &refs, &d.Source, &cwes)
	if err == nil {
		if pub != nil {
			d.Published = pub.UTC().Format(time.RFC3339)
		}
		if mod != nil {
			d.Modified = mod.UTC().Format(time.RFC3339)
		}
		d.Criteria = unmarshalStringArray(criteria)
		d.Refs = unmarshalStringArray(refs)
		d.Cwes = unmarshalStringArray(cwes)
		d.VersionRanges = s.versionRanges(ctx, cveID)
		return &d, nil
	}
	if !isNoRows(err) {
		return nil, fmt.Errorf("get vuln %s: %w", cveID, err)
	}
	// KEV stub rows may live in vuln_pocs-adjacent state before NVD catches up;
	// currently there is nothing else to read, so report absence plainly.
	return nil, nil
}

// versionRanges reads a CVE's structured version ranges (normalized).
func (s *Store) versionRanges(ctx context.Context, cveID string) []VulnVersionRange {
	rows, err := s.db.QueryContext(ctx, `SELECT vendor, product,
		COALESCE(version_start_incl,''), COALESCE(version_start_excl,''),
		COALESCE(version_end_incl,''), COALESCE(version_end_excl,'')
		FROM vuln_cpe_products WHERE cve_id=$1
		ORDER BY vendor, product`, cveID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []VulnVersionRange{}
	for rows.Next() {
		var r VulnVersionRange
		if err := rows.Scan(&r.Vendor, &r.Product, &r.StartIncluding, &r.StartExcluding,
			&r.EndIncluding, &r.EndExcluding); err != nil {
			continue
		}
		if r.StartIncluding == "" && r.StartExcluding == "" &&
			r.EndIncluding == "" && r.EndExcluding == "" {
			continue // index row without ranges (only the product matched)
		}
		r.Raw = r.StartIncluding
		if r.StartExcluding != "" {
			r.Raw = r.StartExcluding
		}
		if r.EndIncluding != "" {
			r.Raw = ">=" + r.StartIncluding + ", <=" + r.EndIncluding
		}
		if r.EndExcluding != "" {
			r.Raw = "<" + r.EndExcluding
		}
		out = append(out, r)
	}
	return out
}

// SyncState mirrors one vuln_sync_state row.
type SyncState struct {
	Source      string     `json:"source"`
	LastSyncAt  *time.Time `json:"last_sync_at,omitempty"`
	Cursor      string     `json:"cursor"`
	TotalSynced int64      `json:"total_synced"`
	LastError   string     `json:"last_error"`
	Enabled     bool       `json:"enabled"`
	// PageCursor stores the paging progress inside a window ("<window start>|<startIndex>"), so
	// an interrupted window resumes from the page where it stopped instead of rerunning the
	// whole window.
	PageCursor string `json:"page_cursor"`
}

// GetSyncState returns the row for source, zero-value (enabled=true mirrors the
// column default) when absent — callers decide their own enabled semantics.
func (s *Store) GetSyncState(ctx context.Context, source string) (SyncState, error) {
	st := SyncState{Source: source, Enabled: true}
	// to_char forces ISO-8601 on the way out; the ::text cast would return
	// Postgres's own "2024-05-06 07:08:09+00" which nothing here parses.
	var lastSync string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(to_char(last_sync_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),''), cursor, total_synced, last_error, enabled, page_cursor
		FROM vuln_sync_state WHERE source=$1`, source).
		Scan(&lastSync, &st.Cursor, &st.TotalSynced, &st.LastError, &st.Enabled, &st.PageCursor)
	if err != nil {
		if isNoRows(err) {
			return st, nil
		}
		return st, err
	}
	if t, e := time.Parse(time.RFC3339, lastSync); e == nil {
		st.LastSyncAt = &t
	}
	return st, nil
}

// SaveSyncState upserts the watermark row.
func (s *Store) SaveSyncState(ctx context.Context, st SyncState) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vuln_sync_state (source, last_sync_at, cursor, total_synced, last_error, enabled, page_cursor)
		VALUES ($1, COALESCE($2::timestamptz, now()), $3, $4, $5, $6, $7)
		ON CONFLICT (source) DO UPDATE SET
		  last_sync_at=COALESCE($2::timestamptz, now()), cursor=EXCLUDED.cursor,
		  total_synced=EXCLUDED.total_synced, last_error=EXCLUDED.last_error, enabled=EXCLUDED.enabled,
		  page_cursor=EXCLUDED.page_cursor`,
		st.Source, st.LastSyncAt, st.Cursor, st.TotalSynced, st.LastError, st.Enabled, st.PageCursor)
	return err
}

// ---- helpers ----

// marshalTextArray encodes a []string into a Postgres text[] literal ({"a","b"}) for use with
// the `$N::text[]` placeholder — the same shape as db.marshalStringArray.
func marshalTextArray(items []string) string {
	if len(items) == 0 {
		return "{}"
	}
	escaped := make([]string, len(items))
	for i, s := range items {
		escaped[i] = `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return "{" + strings.Join(escaped, ",") + "}"
}

func marshalJSONB(items []string) any {
	if len(items) == 0 {
		return nil
	}
	b, err := json.Marshal(items)
	if err != nil {
		return nil
	}
	return string(b)
}

func unmarshalStringArray(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func isNoRows(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no rows in result set")
}

// cpeVendorProduct extracts (vendor, product) from a CPE 2.3 criteria string:
// cpe:2.3:part:vendor:product:version:...  Escaped colons (\:) are tolerated by
// splitting on unescaped colons only. part must be a/app/o/h (device classes we
// care about); "cpe:2.3" prefixed rows only.
func cpeVendorProduct(criteria string) (vendor, product string, ok bool) {
	if !strings.HasPrefix(criteria, "cpe:2.3:") {
		return "", "", false
	}
	parts := splitUnescapedColons(criteria)
	// cpe:2.3:<part>:<vendor>:<product>:... → indices 2,3,4
	if len(parts) < 5 {
		return "", "", false
	}
	return unescape(parts[3]), unescape(parts[4]), true
}

// splitUnescapedColons splits on ':' not preceded by '\'.
func splitUnescapedColons(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i])
			i++
			cur.WriteByte(s[i])
			continue
		}
		if s[i] == ':' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	out = append(out, cur.String())
	return out
}

func unescape(s string) string {
	return strings.ReplaceAll(s, `\`, "")
}

// mergeRange folds another cpeMatch's range bounds into an existing index row
// (different cpeMatch entries for the same product may carry different bounds;
// query semantics are "any bound set matches").
func (s *Store) mergeRange(ctx context.Context, cveID, vendor, product string, r CPERange) {
	if r == (CPERange{}) {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE vuln_cpe_products SET
		  version_start_incl = COALESCE(version_start_incl, NULLIF($4,'')),
		  version_start_excl = COALESCE(version_start_excl, NULLIF($5,'')),
		  version_end_incl   = COALESCE(version_end_incl,   NULLIF($6,'')),
		  version_end_excl   = COALESCE(version_end_excl,   NULLIF($7,''))
		WHERE cve_id=$1 AND vendor=$2 AND product=$3`,
		cveID, vendor, product, r.StartIncluding, r.StartExcluding, r.EndIncluding, r.EndExcluding)
}

// VersionInRange reports whether version falls inside ANY stored range for
// (cve, product). Returns (false, false) when no comparable range exists —
// "not applicable" is distinct from "not in range".
func (s *Store) VersionInRange(ctx context.Context, cveID, product, version string) (in, comparable bool) {
	rows, err := s.db.QueryContext(ctx, `SELECT version_start_incl, version_start_excl,
		version_end_incl, version_end_excl FROM vuln_cpe_products
		WHERE cve_id=$1 AND product=$2
		  AND (version_start_incl IS NOT NULL OR version_start_excl IS NOT NULL
		    OR version_end_incl IS NOT NULL OR version_end_excl IS NOT NULL)`,
		strings.ToUpper(strings.TrimSpace(cveID)), strings.ToLower(strings.TrimSpace(product)))
	if err != nil {
		return false, false
	}
	defer rows.Close()
	any := false
	for rows.Next() {
		var si, se, ei, ee *string
		if err := rows.Scan(&si, &se, &ei, &ee); err != nil {
			continue
		}
		any = true
		ok := true
		for _, b := range []struct {
			bound *string
			cmp   int // -1: version must be > bound (excl) / >= (incl) → flip
		}{} {
			_ = b
		}
		if si != nil && cmpVersions(version, *si) < 0 {
			ok = false
		}
		if se != nil && cmpVersions(version, *se) <= 0 {
			ok = false
		}
		if ei != nil && cmpVersions(version, *ei) > 0 {
			ok = false
		}
		if ee != nil && cmpVersions(version, *ee) >= 0 {
			ok = false
		}
		if ok {
			return true, true
		}
	}
	return false, any
}

// cmpVersions compares dotted version strings leniently: numeric segments
// numerically, others lexically; missing segments count as 0 ("1.2" == "1.2.0").
// Returns -1/0/1. Non-numeric trailing suffixes ("1.0b3") sort below the bare
// number ("1.0"), matching common pre-release semantics closely enough for
// advisory ranges.
func cmpVersions(a, b string) int {
	a = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(a), "v"))
	b = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(b), "v"))
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := "0", "0" // missing segments count as 0 ("1.2" == "1.2.0")
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if c := cmpSegment(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

func cmpSegment(a, b string) int {
	an, aErr := strconv.Atoi(a)
	bn, bErr := strconv.Atoi(b)
	aNum, bNum := aErr == nil, bErr == nil
	switch {
	case aNum && bNum:
		return cmpInt(an, bn)
	case aNum:
		return 1 // numeric segment outranks suffixed ("1" > "1b3" handled per-field)
	case bNum:
		return -1
	default:
		// both non-numeric: strip trailing alpha for numeric compare then lex
		an2, aErr2 := strconv.Atoi(strings.TrimRight(a, "abcdefghijklmnopqrstuvwxyz"))
		bn2, bErr2 := strconv.Atoi(strings.TrimRight(b, "abcdefghijklmnopqrstuvwxyz"))
		if aErr2 == nil && bErr2 == nil && an2 != bn2 {
			return cmpInt(an2, bn2)
		}
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
