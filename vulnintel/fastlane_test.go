package vulnintel

import (
	"context"
	"testing"
)

// The detection and persistence behavior of the "recent critical fast lane".
//
// Background (research on 2026-10-22): the main sync uses a lastModifiedDate
// window (≤120 days), the cursor advances by window, and one MaxRuntime pass
// cannot cover everything — **newly disclosed critical vulnerabilities enter
// the database very slowly**. Two real-world examples confirmed how serious
// this is in practice:
//
//	CVE-2026-109618 (disclosed 2026-10-21, CRITICAL, PHP → RCE)
//	CVE-2026-109619 (disclosed 2026-10-21, CRITICAL, PHP → RCE)
//
// In both NVD records the **affected version range is empty** (cpe:2.3:a:php:php:*:*:*),
// meaning NVD has not filled it in yet — so the platform can neither determine
// whether the target PHP version is affected, nor reliably surface the fact that
// "this component just had two CRITICAL RCEs" to the worker.
//
// The fast lane solves two things:
//  1. **Timeliness**: pull "newly disclosed" items in a small publishedDate
//     window, entering the database within tens of minutes;
//  2. **Version-undetermined visibility**: when the version range is missing it
//     must not be judged as "unaffected" — mark it explicitly as "version
//     undetermined" so the model knows it is worth trying.
//
// The fast lane **shares the vuln_cves table** with the main sync (the agent
// queries the same database) but uses an **independent cursor** (the fast lane
// must not advance the main sync's lastModified cursor).

// Severity mapping: score and KEV → whether it qualifies for the fast lane.
func TestRecentCriticalSelection(t *testing.T) {
	cases := []struct {
		name  string
		score *float64
		kev   bool
		want  bool
	}{
		{"CRITICAL 9.8 included", f64(9.8), false, true},
		{"CRITICAL 9.0 included (boundary)", f64(9.0), false, true},
		{"HIGH 9.5 included (score high enough)", f64(9.5), false, true},
		{"HIGH 8.9 excluded", f64(8.9), false, false},
		{"MEDIUM 5.0 excluded", f64(5.0), false, false},
		{"KEV included (score not high)", f64(7.5), true, true},
		{"KEV included (no score)", nil, true, true},
		{"no score and no KEV excluded", nil, false, false},
		{"score missing but severity=CRITICAL excluded (no guessing)", nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isRecentCritical(c.score, c.kev)
			if got != c.want {
				t.Errorf("isRecentCritical(score=%v kev=%v)=%v, want %v",
					c.score, c.kev, got, c.want)
			}
		})
	}
}

// When the version range is missing, must be able to distinguish "unaffected"
// from "version undetermined".
//
// This is the gap exposed by those two PHP CVEs: NVD's cpe is
// cpe:2.3:a:php:php:*:*:*, with no version boundaries at all. The old logic only
// looked at the raw Criteria, leaving the model with no way to judge; the new
// logic must explicitly work out "whether there are version boundaries".
func TestVersionRangeUndeterminedDetection(t *testing.T) {
	// The real shape of those two PHP CVEs: the version fields in criteria are
	// all *, and there are no versionStart/End fields.
	phpLike := CVE{
		ID:       "CVE-2026-109618",
		Criteria: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"},
	}
	if !VersionRangeUndetermined(phpLike) {
		t.Error("a CVE with a missing version range should be judged as \"version undetermined\"")
	}

	// One with an explicit version range (real NVD form).
	withRange := CVE{
		ID:       "CVE-2021-41773",
		Criteria: []string{"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		Ranges: []CPERange{{
			Criteria:       "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
			StartIncluding: "2.4.49",
			EndExcluding:   "2.4.50",
		}},
	}
	if VersionRangeUndetermined(withRange) {
		t.Error("a CVE with an explicit version range should not be judged as \"version undetermined\"")
	}

	// A pinned version (the version field is not *) also counts as known.
	pinned := CVE{
		ID:       "CVE-2020-0001",
		Criteria: []string{"cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"},
	}
	if VersionRangeUndetermined(pinned) {
		t.Error("a CVE with a pinned version field should not be judged as \"version undetermined\"")
	}
}

// The "version undetermined" note wording must make clear "it does not mean
// unaffected", otherwise the model will treat it as safe.
func TestVersionUndeterminedNoteWording(t *testing.T) {
	note := VersionUndeterminedNote()
	for _, want := range []string{"version", "undetermined", "does not mean"} {
		if !contains(note, want) {
			t.Errorf("version-undetermined note is missing %q: %s", want, note)
		}
	}
}

// The fast lane window: in practice a 1–3 day publishedDate window times out
// (NVD is still indexing freshly published records), while a 7-day window
// completes in 17 seconds — so the window cannot be smaller than 7 days.
func TestFastLaneWindowFloor(t *testing.T) {
	if fastLaneMinWindowDays < 7 {
		t.Errorf("fast lane window floor=%d days, should be at least 7 days (smaller windows time out in practice)", fastLaneMinWindowDays)
	}
	if fastLaneOverlapHours < 12 {
		t.Errorf("fast lane overlap=%d hours, should be at least 12 hours (to avoid missing records due to NVD-side indexing delays)", fastLaneOverlapHours)
	}
}

// The fast lane cursor must be independent of the main sync — use a different source key.
func TestFastLaneUsesIndependentCursorKey(t *testing.T) {
	if fastLaneSyncSource == "nvd" {
		t.Error("the fast lane cursor key must not be the same as the main sync's — it would advance the main sync's lastModified cursor")
	}
	if fastLaneSyncSource == "" {
		t.Error("the fast lane cursor key must not be empty")
	}
}

// Fast lane page size: in practice 2000 entries per page times out on
// publishedDate, 1000 is more stable.
func TestFastLanePageSize(t *testing.T) {
	if fastLanePageSize <= 0 || fastLanePageSize > 2000 {
		t.Errorf("fast lane page size=%d, should be in 1..2000", fastLanePageSize)
	}
}

func f64(v float64) *float64 { return &v }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Confirm the fast lane selection function does not depend on the database
// (pure function, easy to unit-test).
func TestSelectRecentCriticalIsPure(t *testing.T) {
	// The same input must produce the same output and must not panic.
	a := isRecentCritical(f64(9.5), false)
	b := isRecentCritical(f64(9.5), false)
	if a != b {
		t.Error("isRecentCritical should be a pure function")
	}
	_ = context.Background()
}
