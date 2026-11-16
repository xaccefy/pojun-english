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

// Real GHSA response sample (captured live from api.github.com/advisories?cve_id=CVE-2026-85990 on 2026-10-22).
//
// Kept verbatim instead of constructing a "nice-looking" sample: the real data has two pitfalls—
//  1. first_patched_version is a **string** "3.10.0", not {"identifier": ...};
//  2. references is an **array of strings**, not an array of objects.
//
// Writing tests against an "imagined" format would miss both of these.
const ghsaRealAdvisory = `[
  {
    "ghsa_id": "GHSA-54mm-6729-r5wp",
    "cve_id": "CVE-2026-85990",
    "html_url": "https://github.com/Leantime/leantime/security/advisories/GHSA-54mm-6729-r5wp",
    "summary": "Leantime: Any Authenticated User Can Self-Escalate to Admin via Unauthorized JSON-RPC Methods",
    "description": "Leantime 3.9.0 and below are vulnerable.",
    "severity": "high",
    "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 8.8},
    "cvss_severity": null,
    "published_at": "2026-10-15T20:14:43Z",
    "updated_at": "2026-10-15T20:14:44Z",
    "withdrawn_at": null,
    "vulnerabilities": [
      {
        "package": {"ecosystem": "composer", "name": "leantime/leantime"},
        "vulnerable_version_range": "< 3.10.0",
        "first_patched_version": "3.10.0",
        "vulnerable_functions": []
      }
    ],
    "references": [
      "https://github.com/Leantime/leantime/security/advisories/GHSA-54mm-6729-r5wp",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-85990"
    ],
    "cwes": [
      {"cwe_id": "CWE-269", "name": "Improper Privilege Management"},
      {"cwe_id": "CWE-862", "name": "Missing Authorization"}
    ]
  }
]`

// The real response should parse out package, range, and patched version.
func TestParseGhsaFromRealAdvisory(t *testing.T) {
	var advs []GhsaAdvisory
	if err := json.Unmarshal([]byte(ghsaRealAdvisory), &advs); err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advs))
	}
	f := ParseGhsa(advs[0])

	if f.ID != "CVE-2026-85990" {
		t.Errorf("primary key should be the CVE ID, got %q", f.ID)
	}
	if f.GHSID != "GHSA-54mm-6729-r5wp" {
		t.Errorf("GHSA ID parsed incorrectly: %q", f.GHSID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("severity should be HIGH, got %q", f.Severity)
	}
	if f.Score == nil || *f.Score != 8.8 {
		t.Errorf("CVSS score should be 8.8, got %v", f.Score)
	}
	if len(f.Packages) != 1 {
		t.Fatalf("expected 1 affected package, got %d", len(f.Packages))
	}
	p := f.Packages[0]
	if p.Ecosystem != "composer" || p.Name != "leantime/leantime" {
		t.Errorf("package info incorrect: %+v", p)
	}
	if p.Range != "< 3.10.0" {
		t.Errorf("version range incorrect: %q", p.Range)
	}
	// In the real API first_patched_version is a string—this pitfall must be covered by a test.
	if p.PatchedVersion != "3.10.0" {
		t.Errorf("patched version should be 3.10.0, got %q", p.PatchedVersion)
	}
	if len(f.Refs) != 2 {
		t.Errorf("expected 2 references, got %d", len(f.Refs))
	}
	if len(f.Cwes) != 2 || f.Cwes[0] != "CWE-269" {
		t.Errorf("CWE parsed incorrectly: %v", f.Cwes)
	}
	if f.Published.IsZero() {
		t.Error("published time not parsed")
	}
}

// Advisories without a CVE ID should be kept too—the version range is what we want.
func TestParseGhsaKeepsAdvisoryWithoutCVE(t *testing.T) {
	f := ParseGhsa(GhsaAdvisory{GHSID: "GHSA-xxxx-yyyy-zzzz", Summary: "some issue"})
	if f.ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("without a CVE ID the primary key should be the GHSA ID, got %q", f.ID)
	}
}

// The object form of first_patched_version (used by the OSV ecosystem) must also be recognized.
func TestParseGhsaAcceptsObjectPatchedVersion(t *testing.T) {
	var advs []GhsaAdvisory
	raw := `[{"ghsa_id":"GHSA-a","summary":"x","vulnerabilities":[{"package":{"ecosystem":"npm","name":"p"},"vulnerable_version_range":"< 1.2.3","first_patched_version":{"identifier":"1.2.3"}}]}]`
	if err := json.Unmarshal([]byte(raw), &advs); err != nil {
		t.Fatal(err)
	}
	f := ParseGhsa(advs[0])
	if f.Packages[0].PatchedVersion != "1.2.3" {
		t.Errorf("object-form patched version should be parsed, got %q", f.Packages[0].PatchedVersion)
	}
}

// semver range matching: hit / miss / boundary.
func TestGhsaVersionAffected(t *testing.T) {
	pkg := GhsaPackage{Ecosystem: "composer", Name: "leantime/leantime", Range: "< 3.10.0", PatchedVersion: "3.10.0"}
	cases := []struct {
		version string
		want    bool
		why     string
	}{
		{"3.9.0", true, "below upper bound → affected"},
		{"3.10.0", false, "equal to upper bound (< is exclusive) → not affected"},
		{"3.10.1", false, "above upper bound → not affected"},
		{"2.0.0", true, "far below upper bound → affected"},
		{"3.9", true, "two-segment version → below 3.10.0 → affected"},
		{"4.0", false, "above upper bound → not affected"},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			got := GhsaVersionAffected(pkg, c.version)
			if got.Affected != c.want {
				t.Errorf("version %s: Affected=%v, expected %v (%s)\nreason: %s",
					c.version, got.Affected, c.want, c.why, got.Reason)
			}
		})
	}
}

// Composite range (AND): both conditions must be satisfied.
func TestGhsaVersionAffectedCompositeRange(t *testing.T) {
	pkg := GhsaPackage{Name: "react/http", Range: ">= 1.0.0, <= 1.11.0"}
	cases := []struct {
		version string
		want    bool
	}{
		{"1.5.0", true},
		{"0.9.0", false},  // below lower bound
		{"1.11.0", true},  // equal to upper bound (<= inclusive)
		{"1.11.1", false}, // above upper bound
		{"2.0.0", false},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			got := GhsaVersionAffected(pkg, c.version)
			if got.Affected != c.want {
				t.Errorf("version %s: Affected=%v, expected %v\nreason: %s", c.version, got.Affected, c.want, got.Reason)
			}
		})
	}
}

// **Conservative policy**: when in doubt, always judge "potentially affected".
//
// The direction of an error is asymmetric: a wrong "not affected" judgment makes the model skip the vulnerability entirely—
// and that is exactly where newly disclosed CVEs are most often missed. So parse failures must lean toward "potentially affected".
func TestGhsaVersionAffectedIsConservative(t *testing.T) {
	cases := []struct {
		name    string
		pkg     GhsaPackage
		version string
	}{
		{"version cannot be parsed", GhsaPackage{Name: "p", Range: "< 3.10.0"}, "8.3.1-dev-build"},
		{"empty range", GhsaPackage{Name: "p", Range: ""}, "1.0.0"},
		{"unrecognized range operator", GhsaPackage{Name: "p", Range: "^2.0.0"}, "2.5.0"},
		{"range is natural language", GhsaPackage{Name: "p", Range: "all versions before 3.10"}, "3.0.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GhsaVersionAffected(c.pkg, c.version)
			if !got.Affected {
				t.Errorf("when in doubt should judge \"potentially affected\", but judged not affected: %s", got.Reason)
			}
			if got.Reason == "" {
				t.Error("should give a judgment reason")
			}
		})
	}
}

// Pre-release versions are smaller than the same-version release (per the semver spec).
func TestSemverPreReleaseOrdering(t *testing.T) {
	a := parseSemver("1.0.0-alpha")
	b := parseSemver("1.0.0")
	if !a.Valid || !b.Valid {
		t.Fatal("parse failed")
	}
	if compareSemver(a, b) != -1 {
		t.Error("pre-release should be less than the release")
	}
	if compareSemver(b, a) != 1 {
		t.Error("release should be greater than the pre-release")
	}
}

// Version parsing: all kinds of notations must be recognized.
func TestParseSemver(t *testing.T) {
	cases := []struct {
		in    string
		major int
		minor int
		patch int
		valid bool
	}{
		{"1.2.3", 1, 2, 3, true},
		{"v1.2.3", 1, 2, 3, true},
		{"8.3.1", 8, 3, 1, true},
		{"4.8.1", 4, 8, 1, true},
		{"1.2", 1, 2, 0, true},
		{"1", 1, 0, 0, true},
		{"1.2.3-rc1", 1, 2, 3, true},
		{"1.2.3RC1", 1, 2, 3, true},
		{"", 0, 0, 0, false},
		{"abc", 0, 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := parseSemver(c.in)
			if got.Valid != c.valid {
				t.Fatalf("valid=%v, expected %v", got.Valid, c.valid)
			}
			if !c.valid {
				return
			}
			if got.Major != c.major || got.Minor != c.minor || got.Patch != c.patch {
				t.Errorf("parsed as %d.%d.%d, expected %d.%d.%d",
					got.Major, got.Minor, got.Patch, c.major, c.minor, c.patch)
			}
		})
	}
}

// Two forms of an "undetermined" version range.
func TestGhsaRangeUndetermined(t *testing.T) {
	noPkg := GhsaFinding{GHSID: "GHSA-a"}
	if !GhsaRangeUndetermined(noPkg) {
		t.Error("no package info should count as undetermined")
	}
	emptyRange := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: ""}}}
	if !GhsaRangeUndetermined(emptyRange) {
		t.Error("has package but empty range should count as undetermined")
	}
	withRange := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: "< 3.10.0"}}}
	if GhsaRangeUndetermined(withRange) {
		t.Error("with an explicit range should not count as undetermined")
	}
}

// Client: query by CVE, fetch list (incremental filtering).
func TestGhsaClientFetchByCVEID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cve_id"); got != "CVE-2026-85990" {
			t.Errorf("cve_id parameter incorrect: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ghsaRealAdvisory))
	}))
	defer srv.Close()

	c := &GhsaClient{Base: srv.URL, HTTP: srv.Client()}
	advs, err := c.FetchByCVEID(context.Background(), "CVE-2026-85990")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(advs))
	}
	f := ParseGhsa(advs[0])
	if f.ID != "CVE-2026-85990" || f.Packages[0].Range != "< 3.10.0" {
		t.Errorf("parse result incorrect: %+v", f)
	}
}

// Incremental: entries before since should be filtered out.
func TestGhsaClientFetchAdvisoriesFiltersBySince(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("sort"); got != "updated" {
			t.Errorf("sort parameter should be updated, got %q", got)
		}
		if got := r.URL.Query().Get("direction"); got != "desc" {
			t.Errorf("direction parameter should be desc, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
 			{"ghsa_id":"GHSA-new","cve_id":"CVE-1","summary":"new","updated_at":"2026-10-22T10:00:00Z"},
 			{"ghsa_id":"GHSA-old","cve_id":"CVE-2","summary":"old","updated_at":"2026-10-01T10:00:00Z"}
 		]`))
	}))
	defer srv.Close()

	c := &GhsaClient{Base: srv.URL, HTTP: srv.Client()}
	since, err := time.Parse(time.RFC3339, "2026-10-20T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	advs, err := c.FetchAdvisories(context.Background(), since, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("should leave only 1 entry (the new one), got %d", len(advs))
	}
	if advs[0].GHSID != "GHSA-new" {
		t.Errorf("the remaining entry should be the new one, got %q", advs[0].GHSID)
	}
}

// Error status codes must be reported (cannot silently treat them as "no data"—that would make the sync look successful).
func TestGhsaClientReportsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"rate limit exceeded"}`))
	}))
	defer srv.Close()

	c := &GhsaClient{Base: srv.URL, HTTP: srv.Client()}
	_, err := c.FetchByCVEID(context.Background(), "CVE-2026-1")
	if err == nil {
		t.Fatal("403 should report an error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error message should contain the status code, got %q", err.Error())
	}
}

// GHSA's version range determination and NVD's "version undetermined" are two sources of the same thing—
// if either source can determine it, it counts as determined.
func TestGhsaAndNvdUndeterminedAreIndependent(t *testing.T) {
	// NVD side: empty version range → undetermined.
	nvdEmpty := CVE{ID: "CVE-1", Criteria: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}}
	if !VersionRangeUndetermined(nvdEmpty) {
		t.Error("NVD empty version range should be judged undetermined")
	}
	// GHSA side: has explicit range → determined.
	f := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: "< 3.10.0"}}}
	if GhsaRangeUndetermined(f) {
		t.Error("GHSA with an explicit range should not be judged undetermined")
	}
	// GHSA side: range also empty → still undetermined (neither source has info).
	f2 := GhsaFinding{Packages: []GhsaPackage{{Name: "p", Range: ""}}}
	if !GhsaRangeUndetermined(f2) {
		t.Error("GHSA empty range should be judged undetermined")
	}
}

// GHSA's note text must make clear "does not mean not affected"—otherwise the model will skip it.
func TestGhsaVersionNoteWording(t *testing.T) {
	f := GhsaFinding{
		GHSID:    "GHSA-abc",
		Packages: []GhsaPackage{{Name: "leantime/leantime", Range: "< 3.10.0", PatchedVersion: "3.10.0"}},
	}
	note := GhsaVersionNote(f)
	if note == "" {
		t.Fatal("note should not be empty")
	}
	for _, want := range []string{"leantime/leantime", "3.10.0", "GHSA-abc"} {
		if !strings.Contains(note, want) {
			t.Errorf("note should contain %q, got %q", want, note)
		}
	}
}
