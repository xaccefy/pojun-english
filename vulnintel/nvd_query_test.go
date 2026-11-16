package vulnintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// New query dimensions for the NVD client: exact lookup by CVE ID, and "recently disclosed" lookup by publishedDate.
//
// Why needed (measured 2026-10-22):
//
//  1. **Lookup by ID**: the existing FetchPage can only window by lastModifiedDate; to confirm whether a specific
//     CVE exists you'd have to scan windows of hundreds of days (a measured 200-day scan ran 40 minutes and still broke off
//     due to proxy TLS flakiness). The cveId parameter is a single exact query, costing a fraction of a window query.
//
//  2. **Lookup by publishedDate**: "just-disclosed high-severity vulns" need the **publication time**,
//     not lastModified — the latter also counts metadata updates to old CVEs, and the
//     lastModified window spans 120 days with the cursor advancing by window, so one pass can't finish.
//     The recent fast channel needs a small-window, narrow-dimension query.
//
//  3. **CVSS threshold**: the fast channel keeps only high severity (CVSS≥9.0 or KEV), to avoid pulling in tens of thousands
//     of medium/low findings. The NVD API can't filter by score, so we filter ourselves after fetching —
//     which means FetchPublished results must include the score.

// nvdStub starts a fake NVD and records the query parameters it receives.
func nvdStub(t *testing.T, body string, gotQuery map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range r.URL.Query() {
			gotQuery[k] = v[0]
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Lookup by ID must pass cveId to the API and return only that ID's record.
func TestFetchByCVEIDPassesIDAndReturnsRecord(t *testing.T) {
	body := `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-109618",
		"published":"2026-10-01T00:00:00.000","descriptions":[{"lang":"en","value":"test vuln"}],
		"metrics":{}}}]}`
	q := map[string]string{}
	srv := nvdStub(t, body, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	got, err := c.FetchByCVEID(context.Background(), "CVE-2026-109618")
	if err != nil {
		t.Fatal(err)
	}
	if q["cveId"] != "CVE-2026-109618" {
		t.Errorf("cveId parameter=%q, should be CVE-2026-109618", q["cveId"])
	}
	if len(got.Vulnerabilities) != 1 {
		t.Fatalf("returned %d records, should be 1", len(got.Vulnerabilities))
	}
	if got.Vulnerabilities[0].CVE.ID != "CVE-2026-109618" {
		t.Errorf("returned ID=%q", got.Vulnerabilities[0].CVE.ID)
	}
}

// Lookup by ID of a nonexistent CVE → 0 records, not an error.
func TestFetchByCVEIDNotFoundReturnsEmpty(t *testing.T) {
	q := map[string]string{}
	srv := nvdStub(t, `{"totalResults":0,"vulnerabilities":[]}`, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	got, err := c.FetchByCVEID(context.Background(), "CVE-2020-00000")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vulnerabilities) != 0 {
		t.Errorf("a nonexistent CVE should return 0 records, got %d", len(got.Vulnerabilities))
	}
}

// An empty ID errors out immediately without hitting the API.
func TestFetchByCVEIDRejectsEmpty(t *testing.T) {
	c := &NvdClient{Base: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	if _, err := c.FetchByCVEID(context.Background(), "  "); err == nil {
		t.Error("an empty CVE ID should return an error")
	}
}

// Lookup by publication date must use pubStartDate/pubEndDate (not lastMod*).
func TestFetchPublishedUsesPublishDateParams(t *testing.T) {
	q := map[string]string{}
	srv := nvdStub(t, `{"totalResults":0,"vulnerabilities":[]}`, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	start := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	if _, err := c.FetchPublished(context.Background(), 0, 2000, start, end); err != nil {
		t.Fatal(err)
	}
	if q["pubStartDate"] == "" || q["pubEndDate"] == "" {
		t.Errorf("pubStartDate/pubEndDate not passed, actual params=%v", q)
	}
	if q["lastModStartDate"] != "" || q["lastModEndDate"] != "" {
		t.Errorf("lastMod* params should not be passed (that's a different dimension), actual params=%v", q)
	}
	if !strings.HasPrefix(q["pubStartDate"], "2026-10-15") {
		t.Errorf("pubStartDate=%q, should start with 2026-10-15", q["pubStartDate"])
	}
}

// Lookup by publication date must also paginate (startIndex / resultsPerPage).
func TestFetchPublishedPaginates(t *testing.T) {
	q := map[string]string{}
	srv := nvdStub(t, `{"totalResults":0,"vulnerabilities":[]}`, q)
	c := &NvdClient{Base: srv.URL, HTTP: srv.Client()}

	if _, err := c.FetchPublished(context.Background(), 4000, 500, time.Now().AddDate(0, 0, -7), time.Now()); err != nil {
		t.Fatal(err)
	}
	if q["startIndex"] != "4000" {
		t.Errorf("startIndex=%q, should be 4000", q["startIndex"])
	}
	if q["resultsPerPage"] != "500" {
		t.Errorf("resultsPerPage=%q, should be 500", q["resultsPerPage"])
	}
}

// RecentCritical keeps only "high severity": CVSS≥9.0 or KEV.
//
// Used by the recent fast channel: the NVD API can't filter by score, so we filter after fetching —
// without filtering, tens of thousands of medium/low findings a day would swamp the DB and hints.
func TestRecentCriticalFiltersBySeverityAndKEV(t *testing.T) {
	mk := func(id, sev string, score float64, kev bool) map[string]any {
		return map[string]any{
			"id":      id,
			"metrics": map[string]any{"cvssMetricV31": []any{map[string]any{"cvssData": map[string]any{"baseScore": score, "baseSeverity": sev}}}},
			"kev":     kev,
		}
	}
	_ = mk
	// Test the filter function directly. The severity string is deliberately not part of the criteria
	// ("CRITICAL" without a score is a data anomaly and must not be let through on that basis).
	cases := []struct {
		score  *float64
		kev    bool
		wantOK bool
	}{
		{f64(9.8), false, true},
		{f64(9.0), false, true},
		{f64(8.9), false, false},
		{f64(7.5), true, true}, // KEV takes priority: exploited in the wild
		{f64(5.0), false, false},
		{f64(8.5), false, false}, // score not high enough
	}
	for _, c := range cases {
		if got := isRecentCritical(c.score, c.kev); got != c.wantOK {
			t.Errorf("isRecentCritical(score=%v kev=%v)=%v, expected %v",
				c.score, c.kev, got, c.wantOK)
		}
	}
}

// A missing score (empty metrics) must not be misjudged as high severity.
func TestIsRecentCriticalHandlesMissingScore(t *testing.T) {
	if isRecentCritical(nil, false) {
		t.Error("with no score and no KEV it must not be judged high severity")
	}
}

// isRecentCritical's return value means "can enter the fast channel", not "definitely critical".
func TestRecentCriticalThresholdIsDocumented(t *testing.T) {
	if recentCriticalScoreThreshold != 9.0 {
		t.Errorf("fast-channel score threshold=%v, should be 9.0", recentCriticalScoreThreshold)
	}
}

// Compile-time check that nvdResponse's JSON tags weren't broken.
func TestNVDResponseTagsUnchanged(t *testing.T) {
	b, err := json.Marshal(nvdResponse{TotalResults: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"totalResults":7`) {
		t.Errorf("nvdResponse's JSON tags changed: %s", b)
	}
}
