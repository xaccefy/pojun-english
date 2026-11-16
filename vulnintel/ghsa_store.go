package vulnintel

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Ingesting GHSA entries into the database.
//
// ## Which table to store in
//
// Reuse `vuln_cves` + `vuln_cpe_products` — **no new tables**.
//
// Rationale: search_vulns' retrieval and version matching (VersionInRange) are already
// built on these two tables. Creating new tables would mean writing a second set of
// queries, a second set of version matching, and a second set of UI rendering — and
// the two sets of logic would drift out of sync (exactly the pitfall we hit here:
// two implementations that got out of sync).
//
// The `vuln_cves.source` column was originally reserved for "merging a second source
// such as OSV later on" (see the comment in db/schema.sql) — this column is where
// GHSA lands.
//
// ## How to handle conflicts
//
// The same CVE may have both an NVD record and a GHSA record. The primary key is cve_id,
// so **later writes overwrite earlier ones**. Therefore:
//   - GHSA sync runs only **after** NVD sync, and writes only CVEs that NVD hasn't written;
//   - when a real merge is needed (GHSA has version ranges that NVD lacks), go through
//     MergeGhsaVersion — it only fills in version ranges, without overwriting NVD's
//     title/description/score.

// GhsaSyncResult is the result of one round of GHSA sync.
type GhsaSyncResult struct {
	// Fetched is the number of advisories pulled in this round.
	Fetched int `json:"fetched"`
	// Upserted is the number of entries successfully stored.
	Upserted int `json:"upserted"`
	// Skipped is the number of entries skipped because NVD already has the CVE.
	Skipped int `json:"skipped"`
	// Merged is the number of existing CVEs that had version ranges filled in.
	Merged int `json:"merged"`
	// Errors are the errors from this round (aggregated by source, no tokens).
	Errors []string `json:"errors,omitempty"`
}

// UpsertGhsa writes a GHSA finding into the database.
//
// A return of "merged" means the CVE was already in the database (written by NVD) and only version ranges were filled in this time.
func (s *Store) UpsertGhsa(ctx context.Context, f GhsaFinding) (string, error) {
	if f.ID == "" {
		return "", fmt.Errorf("vulnintel: empty ghsa id")
	}
	exists, err := s.cveExists(ctx, f.ID)
	if err != nil {
		return "", err
	}
	if exists {
		// NVD has already written this CVE — only fill in GHSA's version ranges, don't overwrite NVD's content.
		// NVD's description/score/title are higher quality and must not be covered by GHSA's summary.
		if err := s.mergeGhsaVersion(ctx, f); err != nil {
			return "", err
		}
		// CWE is supplemental in the same way: NVD weaknesses are often missing
		// (especially for newly disclosed ones), so GHSA's cwes are merged in for skill
		// linkage; existing values are not erased.
		if err := s.mergeGhsaCWEs(ctx, f); err != nil {
			return "", err
		}
		return "merged", nil
	}

	// cpe_criteria stores the GHSA package + range description (not a CPE string) — for display.
	criteria := ghsaCriteria(f)
	refs := marshalJSONB(f.Refs)
	cwes := marshalTextArray(f.Cwes)
	published := nullTime(f.Published)
	modified := nullTime(f.Updated)

	if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cves
		(cve_id, source, title, description, severity, cvss_score, cvss_vector,
		 published_at, modified_at, cpe_criteria, refs, cwes, synced_at)
		VALUES ($1,'ghsa',$2,$3,$4,$5,'',$6,$7,$8,$9,$10::text[],now())
		ON CONFLICT (cve_id) DO UPDATE SET
		  source='ghsa',
		  title=EXCLUDED.title, description=EXCLUDED.description,
		  severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score,
		  published_at=EXCLUDED.published_at, modified_at=EXCLUDED.modified_at,
		  cpe_criteria=EXCLUDED.cpe_criteria, refs=EXCLUDED.refs,
		  cwes=(SELECT ARRAY(SELECT DISTINCT unnest(vuln_cves.cwes || EXCLUDED.cwes))),
		  synced_at=now()`,
		f.ID, f.Title, "", f.Severity, f.Score, published, modified, criteria, refs, cwes); err != nil {
		return "", fmt.Errorf("upsert ghsa %s: %w", f.ID, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM vuln_cpe_products WHERE cve_id=$1`, f.ID); err != nil {
		return "", fmt.Errorf("clear ghsa index %s: %w", f.ID, err)
	}
	for _, p := range f.Packages {
		for _, idx := range ghsaIndexRows(p) {
			r := ghsaRangeToCPERange(p.Range)
			if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cpe_products
				(cve_id, vendor, product, version_start_incl, version_start_excl, version_end_incl, version_end_excl)
				VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''))
				ON CONFLICT (cve_id, vendor, product) DO UPDATE SET
				  version_start_incl = COALESCE(vuln_cpe_products.version_start_incl, NULLIF($4,'')),
				  version_start_excl = COALESCE(vuln_cpe_products.version_start_excl, NULLIF($5,'')),
				  version_end_incl   = COALESCE(vuln_cpe_products.version_end_incl,   NULLIF($6,'')),
				  version_end_excl   = COALESCE(vuln_cpe_products.version_end_excl,   NULLIF($7,''))`,
				f.ID, idx.vendor, idx.product, r.StartIncluding, r.StartExcluding,
				r.EndIncluding, r.EndExcluding); err != nil {
				return "", fmt.Errorf("index ghsa %s: %w", f.ID, err)
			}
		}
	}
	return "upserted", nil
}

// mergeGhsaVersion fills in GHSA version ranges for an existing CVE.
//
// Only fills the range columns of `vuln_cpe_products` — **does not touch vuln_cves content**.
// If a row for the same product already exists with range columns filled, don't overwrite (NVD's ranges are more trustworthy).
func (s *Store) mergeGhsaVersion(ctx context.Context, f GhsaFinding) error {
	for _, p := range f.Packages {
		r := ghsaRangeToCPERange(p.Range)
		for _, idx := range ghsaIndexRows(p) {
			if _, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cpe_products
				(cve_id, vendor, product, version_start_incl, version_start_excl, version_end_incl, version_end_excl)
				VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''))
				ON CONFLICT (cve_id, vendor, product) DO UPDATE SET
				  version_start_incl = COALESCE(vuln_cpe_products.version_start_incl, NULLIF($4,'')),
				  version_start_excl = COALESCE(vuln_cpe_products.version_start_excl, NULLIF($5,'')),
				  version_end_incl   = COALESCE(vuln_cpe_products.version_end_incl,   NULLIF($6,'')),
				  version_end_excl   = COALESCE(vuln_cpe_products.version_end_excl,   NULLIF($7,''))`,
				f.ID, idx.vendor, idx.product, r.StartIncluding, r.StartExcluding,
				r.EndIncluding, r.EndExcluding); err != nil {
				return fmt.Errorf("merge ghsa %s: %w", f.ID, err)
			}
		}
	}
	return nil
}

// mergeGhsaCWEs merges GHSA's weakness IDs into the cwes array of the existing row (deduplicated union).
// If GHSA provides no CWE, the row is left untouched.
func (s *Store) mergeGhsaCWEs(ctx context.Context, f GhsaFinding) error {
	if len(f.Cwes) == 0 {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE vuln_cves SET
		cwes=(SELECT ARRAY(SELECT DISTINCT unnest(cwes || $1::text[])))
		WHERE cve_id=$2`,
		marshalTextArray(f.Cwes), f.ID); err != nil {
		return fmt.Errorf("merge ghsa cwes %s: %w", f.ID, err)
	}
	return nil
}

// cveExists checks whether a CVE is already in the database.
func (s *Store) cveExists(ctx context.Context, cveID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM vuln_cves WHERE cve_id=$1`, cveID).Scan(&one)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return false, nil
		}
		return false, fmt.Errorf("check cve %s: %w", cveID, err)
	}
	return true, nil
}

// ghsaProductIndex is a (vendor, product) form of a GHSA package in the inverted index.
type ghsaIdxRow struct {
	vendor  string
	product string
}

// ghsaProductIndex converts a GHSA package into candidate forms for the inverted index.
//
// Problem: GHSA package names are in `vendor/package` (composer) form, while CPE product
// is a single segment (`contao`, `core_bundle`). An asset's technology fingerprint is
// written in a form like `Contao 5.3`. Storing `contao/core-bundle` directly would never match.
//
// Compromise: store **two** forms —
//  1. vendor = the part before the slash, product = the part after (`contao` / `core_bundle`)
//  2. vendor = empty, product = the part after the slash with hyphens removed (`corebundle`)
//
// Form 2 covers the case where "the vendor name differs from the technology fingerprint"
// (e.g. package name `symfony/http-kernel` corresponds to fingerprint `Symfony` —
// the "symfony" part is actually in form 1's vendor).
func ghsaIndexRows(p GhsaPackage) []ghsaIdxRow {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	if name == "" {
		return nil
	}
	out := []ghsaIdxRow{}
	vendor, product := "", name
	if i := strings.Index(name, "/"); i >= 0 {
		vendor = name[:i]
		product = name[i+1:]
	}
	// Hyphen → underscore: GHSA package name is `core-bundle`, CPE product is `core_bundle`.
	// Without this conversion, this index would never match an asset's technology fingerprint.
	underscored := strings.ReplaceAll(product, "-", "_")
	if underscored != "" {
		out = append(out, ghsaIdxRow{vendor: vendor, product: underscored})
	}
	if underscored != product && len(underscored) >= 2 {
		// Hyphen-free form: core_bundle → corebundle.
		out = append(out, ghsaIdxRow{vendor: "", product: strings.ReplaceAll(product, "-", "")})
	}
	// Also store the full package name (exact match in vendor/package form).
	if vendor != "" {
		out = append(out, ghsaIdxRow{vendor: vendor, product: name})
		// **Store the vendor segment alone as a product in its own row**.
		//
		// Rationale: in the composer package name `contao/core-bundle`, the asset's
		// technology fingerprint is written as "Contao" — only the vendor segment matches
		// (the package segment is a bundle/component and never appears in the fingerprint).
		// Storing this row is what lets GHSA match assets like "Contao 5.3".
		if len(vendor) >= 2 {
			out = append(out, ghsaIdxRow{vendor: "", product: vendor})
		}
	}
	return out
}

// ghsaRangeToCPERange converts a GHSA semver range into the existing CPE range columns.
//
// Mapping: `< X` → end_excl=X; `<= X` → end_incl=X; `> X` → start_excl=X;
// `>= X` → start_incl=X; `= X` → both ends set to X (a single-point closed interval).
//
// Compound ranges (AND) can only take the **tightest lower bound and tightest upper bound** —
// multiple conditions are intersected, and the intersection's bounds are the strictest
// among the conditions. If nothing can be derived, leave it empty.
func ghsaRangeToCPERange(expr string) CPERange {
	conds, unknown := ParseGhsaRange(expr)
	if len(conds) == 0 || len(unknown) > 0 {
		// There are unparseable fragments → the whole range is untrustworthy, set no bounds (let the upper layer judge "cannot compare").
		return CPERange{}
	}
	var r CPERange
	setStart := func(incl, excl string) {
		if incl != "" {
			if r.StartIncluding == "" || cmpVersions(incl, r.StartIncluding) > 0 {
				r.StartIncluding = incl
			}
			if r.StartExcluding != "" {
				if cmpVersions(incl, r.StartExcluding) >= 0 {
					r.StartIncluding, r.StartExcluding = incl, ""
				}
			}
		}
		if excl != "" {
			if r.StartExcluding == "" || cmpVersions(excl, r.StartExcluding) > 0 {
				r.StartExcluding = excl
			}
			if r.StartIncluding != "" {
				if cmpVersions(excl, r.StartIncluding) <= 0 {
					r.StartExcluding, r.StartIncluding = excl, ""
				}
			}
		}
	}
	setEnd := func(incl, excl string) {
		if incl != "" {
			if r.EndIncluding == "" || cmpVersions(incl, r.EndIncluding) < 0 {
				r.EndIncluding = incl
			}
			if r.EndExcluding != "" {
				if cmpVersions(incl, r.EndExcluding) <= 0 {
					r.EndIncluding, r.EndExcluding = incl, ""
				}
			}
		}
		if excl != "" {
			if r.EndExcluding == "" || cmpVersions(excl, r.EndExcluding) < 0 {
				r.EndExcluding = excl
			}
			if r.EndIncluding != "" {
				if cmpVersions(excl, r.EndIncluding) >= 0 {
					r.EndExcluding, r.EndIncluding = excl, ""
				}
			}
		}
	}
	for _, c := range conds {
		v := c.Ver
		switch c.Op {
		case ">":
			setStart("", v.String())
		case ">=":
			setStart(v.String(), "")
		case "<":
			setEnd("", v.String())
		case "<=":
			setEnd(v.String(), "")
		case "=":
			setStart(v.String(), "")
			setEnd(v.String(), "")
		}
	}
	return r
}

// ghsaCriteria generates the cpe_criteria description for a GHSA entry (for display, not a real CPE).
func ghsaCriteria(f GhsaFinding) any {
	out := make([]string, 0, len(f.Packages))
	for _, p := range f.Packages {
		s := fmt.Sprintf("ghsa:%s/%s %s", p.Ecosystem, p.Name, p.Range)
		if p.PatchedVersion != "" {
			s += " (patched: " + p.PatchedVersion + ")"
		}
		out = append(out, s)
	}
	return marshalJSONB(out)
}

// SyncGhsa runs one round of GHSA sync.
//
// Incremental: advisories updated after `since`. When `since` is the zero value,
// only the first page is pulled (the caller decides whether to do a full sync).
func (s *Store) SyncGhsa(ctx context.Context, c *GhsaClient, since time.Time, maxPages int) (*GhsaSyncResult, error) {
	if c == nil {
		return nil, fmt.Errorf("vulnintel: nil ghsa client")
	}
	if maxPages <= 0 {
		maxPages = 3
	}
	res := &GhsaSyncResult{}
	for page := 1; page <= maxPages; page++ {
		advs, err := c.FetchAdvisories(ctx, since, page)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("ghsa page %d: %v", page, err))
			break
		}
		res.Fetched += len(advs)
		if len(advs) == 0 {
			break
		}
		for _, a := range advs {
			f := ParseGhsa(a)
			outcome, err := s.UpsertGhsa(ctx, f)
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", f.ID, err))
				continue
			}
			switch outcome {
			case "merged":
				res.Merged++
			default:
				res.Upserted++
			}
		}
	}
	return res, nil
}

// GhsaVersionNote is the notice text after GHSA supplements version information.
//
// Used to tell the model that "GHSA filled in affected version ranges that NVD lacked".
func GhsaVersionNote(f GhsaFinding) string {
	if len(f.Packages) == 0 {
		return ""
	}
	parts := make([]string, 0, len(f.Packages))
	for _, p := range f.Packages {
		s := p.Name
		if p.Range != "" {
			s += " " + p.Range
		}
		if p.PatchedVersion != "" {
			s += " (fixed in " + p.PatchedVersion + ")"
		}
		parts = append(parts, s)
	}
	return fmt.Sprintf("Affected versions supplemented by GitHub Advisory Database: %s (GHSA %s)",
		strings.Join(parts, "; "), f.GHSID)
}
