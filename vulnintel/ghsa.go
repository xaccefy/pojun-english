package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitHub Advisory Database client.
//
// ## Why a second source is needed
//
// NVD often leaves the version range empty for **freshly disclosed** CVEs — measured
// 2026-10-22 on PHP CVE-2026-109618/109619, where the CPE in NVD is
// `cpe:2.3:a:php:php:*:*:*:*:*:*:*:*` with `*` in the version slot. All we can do is mark it
// "version undetermined" (see VersionRangeUndetermined in fastlane.go) — **that is damage
// control, not a solution**.
//
// The GitHub Advisory Database follows a different intake path (maintainers file advisories
// themselves, or GitHub's security team ingests them), **the version range is mandatory**, and
// it carries `first_patched_version` (the fixed version) — exactly what NVD lacks.
//
// ## Coverage boundaries (important, do not overestimate it)
//
// GHSA covers **components with a package ecosystem**: composer (PHP application-layer
// frameworks), npm, pip, maven, nuget, go, rust...
//
// **CVEs in the PHP core itself are not in GHSA** — measured: CVE-2026-109618/109619 return
// an empty array from the GHSA API. So GHSA is a **supplement**, not a **replacement**: it
// fills in "components with a package ecosystem" (the bulk of our assets), while core-language
// CVEs still rely on NVD + vendor advisories.
//
// That is also why this file makes no promise like "GHSA can solve those two PHP CVEs".

// GhsaClient  talks to the GitHub Advisory Database REST API.
//
// Public advisories can be read without a token (the rate limit is fairly loose); with a token
// configured the limit is wider. The token lives only in the configuration and never reaches
// logs or reports.
type GhsaClient struct {
	Base   string // override for tests; default api.github.com
	Token  string
	HTTP   *http.Client
	PerPag int
}

// NewGhsaClient builds a GHSA client.
func NewGhsaClient(token string, proxyURL string) (*GhsaClient, error) {
	transport, err := newFallbackTransport(proxyURL)
	if err != nil {
		return nil, err
	}
	return &GhsaClient{
		Base:   "https://api.github.com",
		Token:  strings.TrimSpace(token),
		HTTP:   &http.Client{Timeout: 60 * time.Second, Transport: transport},
		PerPag: 100,
	}, nil
}

// GhsaAdvisory is the subset of an advisory returned by the GHSA API.
type GhsaAdvisory struct {
	GHSID        string            `json:"ghsa_id"`
	CVEID        string            `json:"cve_id"`
	URL          string            `json:"html_url"`
	Summary      string            `json:"summary"`
	Description  string            `json:"description"`
	Severity     string            `json:"severity"`
	CVSS         *GhsaCVSS         `json:"cvss"`
	CVSSSeverity *GhsaCVSSSeverity `json:"cvss_severity"`
	Published    string            `json:"published_at"`
	Updated      string            `json:"updated_at"`
	Withdrawn    string            `json:"withdrawn_at"`
	// Vulnerabilities holds the affected packages and version ranges.
	Vulnerabilities []GhsaVulnerability `json:"vulnerabilities"`
	// References holds external links such as vendor advisories — the model uses them to confirm
	// the scope of impact.
	//
	// Measured: the GitHub API returns an **array of strings** ("https://..."), not an array of
	// objects. json.RawMessage accepts both shapes.
	References []json.RawMessage `json:"references"`
	// Cwes holds the weakness classifications.
	Cwes []GhsaCWE `json:"cwes"`
}

// GhsaCVSS is the advisory's own CVSS vector (advisories without a vector still have severity
// text).
type GhsaCVSS struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// GhsaCVSSSeverity is the CVSS v3/v4 breakdown.
type GhsaCVSSSeverity struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

// GhsaVulnerability describes one affected package.
type GhsaVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	// VulnerableVersionRange is a semver range expression, e.g. "< 3.10.0" or
	// ">= 1.0.0, <= 1.11.0".
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	// FirstPatchedVersion is the fixed version.
	//
	// Measured 2026-10-22: the GitHub API returns a **string** ("3.10.0"), but in the OSV
	// ecosystem the same field is sometimes an object {"identifier": "..."}. json.RawMessage
	// accepts both shapes.
	FirstPatchedVersion json.RawMessage `json:"first_patched_version"`
}

// patchedVersionFromRaw extracts the version from first_patched_version.
//
// Both shapes are supported: the string "3.10.0" and the object {"identifier": "3.10.0"}.
func patchedVersionFromRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return strings.TrimSpace(obj.Identifier)
	}
	return ""
}

// referenceURL extracts the URL from one reference.
//
// The GitHub API actually returns a string; the object shape ({"url": "..."}) is accepted too
// — other sources (such as an internal mirror) may use objects.
func referenceURL(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return strings.TrimSpace(obj.URL)
	}
	return ""
}

// GhsaCWE is a weakness identifier.
type GhsaCWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// The semantic parse result of a GhsaAdvisory.
type GhsaFinding struct {
	// ID is the primary key: the CVE number wins (so it merges with NVD), otherwise the GHSA id
	// is used.
	ID string
	// GHSID is GHSA's own identifier (always present).
	GHSID string
	Title string
	// Severity is the normalized severity (CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN).
	Severity string
	// Score is the CVSS score (nil when absent).
	Score *float64
	// Published / Updated are timestamps.
	Published time.Time
	Updated   time.Time
	// Refs holds the external references.
	Refs []string
	// Packages holds the affected packages and version ranges.
	Packages []GhsaPackage
	// Cwes is the list of weakness identifiers.
	Cwes []string
}

// GhsaPackage is one affected package and its version range.
type GhsaPackage struct {
	// Ecosystem is the GHSA ecosystem name (composer/npm/pip/...).
	Ecosystem string
	// Name is the package name (e.g. "contao/core-bundle").
	Name string
	// Range is the raw semver range expression.
	Range string
	// PatchedVersion is the fixed version (empty = not fixed yet).
	PatchedVersion string
}

// GhsaAffected is the verdict on "is this version of that package affected".
type GhsaAffected struct {
	Package GhsaPackage
	// Affected true means the target version falls inside the range.
	Affected bool
	// Reason explains the basis of the verdict (shown to the model).
	Reason string
}

// FetchAdvisories pulls a list of GHSA advisories.
//
// Cursor semantics: with sort=updated&direction=desc the results come back in updated_at
// descending order, so a caller can do incremental sync by filtering updated_at > since.
func (c *GhsaClient) FetchAdvisories(ctx context.Context, since time.Time, page int) ([]GhsaAdvisory, error) {
	perPage := c.PerPag
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	q := url.Values{}
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))
	q.Set("sort", "updated")
	q.Set("direction", "desc")

	u := c.Base + "/advisories?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ghsa: status %d: %s", resp.StatusCode, snippet(body))
	}
	var out []GhsaAdvisory
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ghsa: decode: %w", err)
	}
	// Incremental filter: keep only those whose updated_at is after since.
	if !since.IsZero() {
		kept := out[:0]
		for _, a := range out {
			if t, err := time.Parse(time.RFC3339, a.Updated); err == nil && t.After(since) {
				kept = append(kept, a)
			}
		}
		out = kept
	}
	return out, nil
}

// FetchByCVEID looks up GHSA by exact CVE number.
//
// Purpose: when a CVE synced from NVD has an undetermined version range, use this to fill it in
// from GHSA once.
// An empty slice is returned when GHSA does not cover it (not an error) — "not found" is the
// norm.
func (c *GhsaClient) FetchByCVEID(ctx context.Context, cveID string) ([]GhsaAdvisory, error) {
	q := url.Values{}
	q.Set("cve_id", cveID)
	q.Set("per_page", "10")
	u := c.Base + "/advisories?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ghsa: status %d: %s", resp.StatusCode, snippet(body))
	}
	var out []GhsaAdvisory
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ghsa: decode: %w", err)
	}
	return out, nil
}

func (c *GhsaClient) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "pojun-vulnintel")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

// snippet truncates an error body (do not stuff a whole HTML page into the log).
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// ParseGhsa parses one advisory into a Finding.
//
// Key trade-off: **advisories without a CVE number are kept** (using the GHSA id as the ID) —
// the version range is what we want, and it must not be dropped just because "it does not map
// to a CVE".
func ParseGhsa(a GhsaAdvisory) GhsaFinding {
	f := GhsaFinding{
		GHSID: a.GHSID,
		Title: strings.TrimSpace(a.Summary),
		Refs:  []string{},
		Cwes:  []string{},
	}
	if f.Title == "" {
		f.Title = a.Description
	}
	if len(f.Title) > 300 {
		f.Title = f.Title[:300]
	}
	// Primary key: the CVE wins (so it can merge into one row with the NVD record).
	f.ID = strings.TrimSpace(a.CVEID)
	if f.ID == "" {
		f.ID = a.GHSID
	}
	// Severity: the CVSS score first, then the text.
	if a.CVSS != nil && a.CVSS.Score > 0 {
		s := a.CVSS.Score
		f.Score = &s
		f.Severity = severityFromScore(s)
	} else if a.CVSSSeverity != nil && a.CVSSSeverity.Score > 0 {
		s := a.CVSSSeverity.Score
		f.Score = &s
		f.Severity = severityFromScore(s)
	} else {
		f.Severity = severityFromText(a.Severity)
	}
	if t, err := time.Parse(time.RFC3339, a.Published); err == nil {
		f.Published = t
	}
	if t, err := time.Parse(time.RFC3339, a.Updated); err == nil {
		f.Updated = t
	}
	for _, r := range a.References {
		if u := referenceURL(r); u != "" {
			f.Refs = append(f.Refs, u)
		}
	}
	for _, cw := range a.Cwes {
		if cw.CWEID != "" {
			f.Cwes = append(f.Cwes, cw.CWEID)
		}
	}
	for _, v := range a.Vulnerabilities {
		p := GhsaPackage{
			Ecosystem: v.Package.Ecosystem,
			Name:      v.Package.Name,
			Range:     strings.TrimSpace(v.VulnerableVersionRange),
		}
		if p.Name == "" {
			continue
		}
		p.PatchedVersion = patchedVersionFromRaw(v.FirstPatchedVersion)
		f.Packages = append(f.Packages, p)
	}
	return f
}

// severityFromScore normalizes severity from a CVSS score.
func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// severityFromText normalizes from the text severity (used when there is no CVSS score).
func severityFromText(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
