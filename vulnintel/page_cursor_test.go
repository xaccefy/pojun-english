package vulnintel

import (
	"testing"
	"time"
)

// Page-level cursor: an NVD sync window can be too large to finish in one round; if the cursor advances only by "window",
// a failure inside the window reruns the whole window — the cursor stays stuck on the same window, wasting every round.
//
// Measured (2026-10-21): NVD's 120-day window can reach 140k records (71 pages × ~17s +
// rate-limit delays), more than one 30-minute MaxRuntime round can finish; the cursor stalled at 2026-06-10,
// the last window timed out repeatedly, and the 400k-record catalog stopped filling up at 140k.
func TestPageCursorRoundTrip(t *testing.T) {
	winStart := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	raw := formatPageCursor(winStart, 10000)
	gotWin, gotIdx, ok := parsePageCursor(raw)
	if !ok {
		t.Fatalf("round trip failed: %q", raw)
	}
	if !gotWin.Equal(winStart) {
		t.Errorf("window = %v, want %v", gotWin, winStart)
	}
	if gotIdx != 10000 {
		t.Errorf("index = %d, want 10000", gotIdx)
	}
}

func TestParsePageCursorRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"no-separator",
		"not-a-time|100",
		"2026-06-09T00:00:00Z|notanumber",
		"2026-06-09T00:00:00Z|-5",
		"|100",
	}
	for _, raw := range cases {
		if _, _, ok := parsePageCursor(raw); ok {
			t.Errorf("must reject %q", raw)
		}
	}
}

// The window start in a page-level cursor must match the actual window exactly — even a tiny difference
// carries the previous window's progress into the next one (skipped pages = missed data).
func TestPageCursorWindowMustMatchExactly(t *testing.T) {
	winStart := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	raw := formatPageCursor(winStart, 2000)
	gotWin, _, ok := parsePageCursor(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	other := winStart.AddDate(0, 0, 120)
	if gotWin.Equal(other) {
		t.Fatal("different windows must not compare equal")
	}
	// Different representations of the same instant (UTC vs local zone) must also compare equal
	local := winStart.In(time.FixedZone("CST", 8*3600))
	rawLocal := formatPageCursor(local, 2000)
	gotLocal, _, ok := parsePageCursor(rawLocal)
	if !ok {
		t.Fatal("parse failed for local-zone cursor")
	}
	if !gotLocal.Equal(winStart) {
		t.Errorf("same instant in another zone must compare equal: %v vs %v", gotLocal, winStart)
	}
}
