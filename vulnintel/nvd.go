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

// NvdClient talks to the NVD CVE API 2.0. Anonymous access is rate limited to
// ~5 requests / 30s (the client honors 429 Retry-After); an apiKey lifts it to
// 50 / 30s and is optional — configured in the UI, never logged.
type NvdClient struct {
	Base   string // override for tests; default services.nvd.nist.gov
	APIKey string
	HTTP   *http.Client
}

func NewNvdClient(apiKey string, proxyURL string) (*NvdClient, error) {
	// Fall back to a direct connection when the proxy transport fails — an unreachable proxy
	// for some sources must not fail the whole round.
	transport, err := newFallbackTransport(proxyURL)
	if err != nil {
		return nil, err
	}
	return &NvdClient{
		Base:   "https://services.nvd.nist.gov",
		APIKey: strings.TrimSpace(apiKey),
		HTTP:   &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}, nil
}

// nvdResponse is the subset of the CVE API 2.0 envelope we consume.
type nvdResponse struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Vulnerabilities []nvdWrapper `json:"vulnerabilities"`
}

type nvdWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string                     `json:"id"`
	Published      string                     `json:"published"`
	LastModified   string                     `json:"lastModified"`
	Descriptions   []nvdDescription           `json:"descriptions"`
	Metrics        map[string]json.RawMessage `json:"metrics"`
	Weaknesses     []nvdWeakness              `json:"weaknesses"`
	Configurations []nvdConfiguration         `json:"configurations"`
	References     []nvdReference             `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdConfiguration struct {
	Nodes []struct {
		CPEMatch []struct {
			Vulnerable            bool   `json:"vulnerable"`
			Criteria              string `json:"criteria"`
			VersionStartIncluding string `json:"versionStartIncluding"`
			VersionStartExcluding string `json:"versionStartExcluding"`
			VersionEndIncluding   string `json:"versionEndIncluding"`
			VersionEndExcluding   string `json:"versionEndExcluding"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}

type nvdReference struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

// nvdWeakness is one item of the weaknesses array (the lang=en value looks like "CWE-79").
type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

// nvdTime parses NVD timestamps ("2024-01-02T03:04:05.678").
func nvdTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000", s)
	if t.IsZero() {
		t, _ = time.Parse(time.RFC3339, s)
	}
	return t
}

// FetchPage fetches one page. modStart/modEnd bound the lastModified window
// (≤120 days per API contract, enforced by the caller); both empty = unfiltered.
func (c *NvdClient) FetchPage(ctx context.Context, startIndex, resultsPerPage int, modStart, modEnd time.Time) (*nvdResponse, error) {
	q := url.Values{}
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	if !modStart.IsZero() {
		q.Set("lastModStartDate", modStart.UTC().Format("2006-01-02T15:04:05.000"))
	}
	if !modEnd.IsZero() {
		q.Set("lastModEndDate", modEnd.UTC().Format("2006-01-02T15:04:05.000"))
	}
	return c.fetch(ctx, q)
}

// FetchByCVEID fetches one CVE by its exact ID.
//
// Why it is needed (measured 2026-10-22): FetchPage can only window by lastModifiedDate, so
// confirming whether one specific CVE exists meant scanning windows spanning hundreds of
// days — a measured 200-day scan took 40 minutes and was still interrupted by proxy TLS
// flakiness. The cveId parameter is a single exact query costing a fraction of a window
// query.
//
// A nonexistent CVE returns 0 results rather than an error (NVD returns totalResults=0 for an
// unknown ID).
func (c *NvdClient) FetchByCVEID(ctx context.Context, cveID string) (*nvdResponse, error) {
	id := strings.TrimSpace(cveID)
	if id == "" {
		return nil, fmt.Errorf("cve id must not be empty")
	}
	return c.fetch(ctx, url.Values{"cveId": {id}})
}

// FetchPublished fetches one page of CVEs **by publication date**.
//
// Difference from FetchPage: FetchPage windows by lastModifiedDate (<=120 days), and that
// path also counts "metadata of an old CVE was updated", while the cursor advances by
// 120-day windows that one MaxRuntime cannot page through — which is why "a freshly
// disclosed critical vulnerability" entered the database so slowly.
//
// Windowing by publication date gives a small window containing only "newly disclosed" —
// exactly what the recent fast lane needs.
//
// Measured (2026-10-22): a 7-day window returned 24513 records in 17 seconds, while a 1-3 day
// window times out (NVD is still indexing freshly published records, so queries are slow).
// The fast lane window should therefore not be shorter than 7 days.
func (c *NvdClient) FetchPublished(ctx context.Context, startIndex, resultsPerPage int, pubStart, pubEnd time.Time) (*nvdResponse, error) {
	q := url.Values{}
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	if !pubStart.IsZero() {
		q.Set("pubStartDate", pubStart.UTC().Format("2006-01-02T15:04:05.000"))
	}
	if !pubEnd.IsZero() {
		q.Set("pubEndDate", pubEnd.UTC().Format("2006-01-02T15:04:05.000"))
	}
	return c.fetch(ctx, q)
}

// fetch performs one NVD query and decodes the response.
func (c *NvdClient) fetch(ctx context.Context, q url.Values) (*nvdResponse, error) {
	base := c.Base
	if base == "" {
		base = "https://services.nvd.nist.gov"
	}
	// Shared rate-limit gate: the main sync and the fast lane hit the same NVD, so the budget is
	// shared. Without queueing here the two paths each overrun at their own pace (measured: the
	// fast lane got rate limited on its first page
	// rate limited).
	if err := c.waitNvdSlot(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/json/cves/2.0?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		// Honor Retry-After when present; the sync loop re-calls at its own pace.
		ra := resp.Header.Get("Retry-After")
		return nil, &RateLimited{RetryAfter: parseSeconds(ra)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("nvd api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("nvd api decode: %w", err)
	}
	return &out, nil
}

// recentCriticalScoreThreshold is the CVSS score bar for the recent fast lane.
//
// 9.0 is where NVD's CRITICAL tier starts. Anything below it stays out of the fast lane —
// tens of thousands of CVEs are disclosed every day, and without filtering both the database
// and the hint would drown in medium/low findings, so workers would never actually look.
const recentCriticalScoreThreshold = 9.0

// isRecentCritical reports whether a CVE qualifies for the "recent fast lane".
//
// Criteria: CVSS>=9.0 **or** the CISA KEV flag (already exploited in the wild — the score may
// be low but the harm is huge, so KEV outranks the score).
//
// When score is nil (empty metrics or unparseable) it does **not** let the CVE through just
// because the severity string says CRITICAL: severity is mapped from the score by NVD, so a
// missing score with CRITICAL written on it is a data anomaly, and "do not let it through
// when it cannot be judged" is the safer rule (better to enter the database late than to
// mislabel a batch).
func isRecentCritical(score *float64, kev bool) bool {
	if kev {
		return true
	}
	return score != nil && *score >= recentCriticalScoreThreshold
}

// RateLimited signals a 429 so the sync loop can back off without treating it
// as a source failure.
type RateLimited struct{ RetryAfter time.Duration }

func (e *RateLimited) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("nvd rate limited, retry after %s", e.RetryAfter)
	}
	return "nvd rate limited"
}

func parseSeconds(s string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// parseNVDCWEs extracts the CWE identifiers from weaknesses (lang=en), deduplicates them,
// normalizes to the uppercase "CWE-79" form and caps at 10. NVD often lists several entries
// for the same CWE (different sources); without deduplication the cwes array would bloat into
// a dozen repeated values.
func parseNVDCWEs(ws []nvdWeakness) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, w := range ws {
		for _, d := range w.Description {
			if d.Lang != "en" {
				continue
			}
			id := strings.ToUpper(strings.TrimSpace(d.Value))
			if id == "" || seen[id] {
				continue
			}
			// Only the standard identifier form is kept; NVD's internal placeholders
			// (NVD-CWE-OTHER / NVD-CWE-NOINFO / CWE-OTHER and the like) do not enter the database.
			if !strings.HasPrefix(id, "CWE-") ||
				strings.Contains(id, "NVD-CWE") ||
				id == "CWE-OTHER" {
				continue
			}
			seen[id] = true
			out = append(out, id)
			if len(out) >= 10 {
				return out
			}
		}
	}
	return out
}

// ToCVE converts an API record into the store shape. Scoring picks the first
// Primary V31, then any V31, then V30, then V2 — mirroring NVD's own precedence.
func ToCVE(w nvdWrapper) (CVE, bool) {
	c := w.CVE
	if c.ID == "" {
		return CVE{}, false
	}
	out := CVE{
		ID:        c.ID,
		Published: nvdTime(c.Published),
		Modified:  nvdTime(c.LastModified),
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" && d.Value != "" {
			out.Description = d.Value
			break
		}
	}
	out.Title = firstSentence(out.Description)
	score, vector, severity := pickScore(c.Metrics)
	out.Score, out.Vector, out.Severity = score, vector, severity
	out.Cwes = parseNVDCWEs(c.Weaknesses)
	seen := map[string]bool{}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable || m.Criteria == "" || seen[m.Criteria] {
					continue
				}
				seen[m.Criteria] = true
				out.Criteria = append(out.Criteria, m.Criteria)
				if m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
					m.VersionEndIncluding != "" || m.VersionEndExcluding != "" {
					out.Ranges = append(out.Ranges, CPERange{
						Criteria:       m.Criteria,
						StartIncluding: m.VersionStartIncluding,
						StartExcluding: m.VersionStartExcluding,
						EndIncluding:   m.VersionEndIncluding,
						EndExcluding:   m.VersionEndExcluding,
					})
				}
			}
		}
	}
	for _, r := range c.References {
		if r.URL != "" {
			out.Refs = append(out.Refs, r.URL)
		}
	}
	return out, true
}

// pickScore mirrors NVD precedence: Primary V31 > any V31 > V30 > V2.
func pickScore(metrics map[string]json.RawMessage) (score *float64, vector, severity string) {
	if metrics == nil {
		return nil, "", "UNKNOWN"
	}
	primary, anyHit := pickFromMetricList(metrics["cvssMetricV31"], "Primary")
	if anyHit {
		return primary.score, primary.vector, primary.severity
	}
	primary, anyHit = pickFromMetricList(metrics["cvssMetricV30"], "Primary")
	if anyHit {
		return primary.score, primary.vector, primary.severity
	}
	primary, anyHit = pickFromMetricList(metrics["cvssMetricV2"], "Primary")
	if anyHit {
		return primary.score, primary.vector, primary.severity
	}
	return nil, "", "UNKNOWN"
}

type picked struct {
	score    *float64
	vector   string
	severity string
}

func pickFromMetricList(raw json.RawMessage, wantType string) (picked, bool) {
	if len(raw) == 0 {
		return picked{}, false
	}
	var list []nvdMetric
	if json.Unmarshal(raw, &list) != nil {
		return picked{}, false
	}
	var fallback *nvdMetric
	for i := range list {
		m := list[i]
		if m.CVSSData.BaseScore == 0 && m.CVSSData.VectorString == "" {
			continue
		}
		if m.Type == wantType {
			return toPicked(m), true
		}
		if fallback == nil {
			fallback = &list[i]
		}
	}
	if fallback != nil {
		return toPicked(*fallback), true
	}
	return picked{}, false
}

func toPicked(m nvdMetric) picked {
	s := m.CVSSData.BaseScore
	p := picked{score: &s, vector: m.CVSSData.VectorString, severity: m.CVSSData.BaseSeverity}
	if p.severity == "" {
		p.severity = mapScoreToSeverity(m.CVSSData.BaseScore)
	}
	return p
}

// mapScoreToSeverity maps a numeric base score onto the v3 severity ladder.
// Used as fallback when the source doesn't carry a textual severity; the legacy
// v2 term set is intentionally folded onto this same ladder.
func mapScoreToSeverity(score float64) string {
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

// firstSentence trims the description to a one-line title: up to the first
// period followed by a space, capped at 160 runes.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 && i < 200 {
		s = s[:i+1]
	}
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > 160 {
		return string(r[:157]) + "..."
	}
	return s
}
