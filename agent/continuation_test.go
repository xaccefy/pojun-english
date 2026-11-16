package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/chu0119/pojun/db"
)

// summary length cap: oversized gets truncated keeping the head (target + what-to-do is at the start).
func TestClampIntentSummaryTruncates(t *testing.T) {
	long := strings.Repeat("probe the target host's login surface and try default credentials", 60)
	got := clampIntentSummary(long)
	if utf8.RuneCountInString(got) > maxIntentSummaryRunes+40 {
		t.Fatalf("still too long after truncation: %d runes", utf8.RuneCountInString(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("should carry a truncation marker: %q", got[:min(80, len(got))])
	}
	// The head must be kept — target + what-to-do is at the start.
	if !strings.HasPrefix(got, "probe the target host") {
		t.Errorf("head not preserved: %q", got[:min(40, len(got))])
	}
}

// Normal-length summaries must not be modified.
func TestClampIntentSummaryKeepsShort(t *testing.T) {
	short := "use the obtained root on 10.10.47.11 to extract ZStack admin API credentials"
	if got := clampIntentSummary(short); got != short {
		t.Fatalf("short summary must not change: got %q", got)
	}
}

// Empty summaries stay invalid.
func TestClampIntentSummaryEmpty(t *testing.T) {
	if got := clampIntentSummary("   "); got != "" {
		t.Fatalf("blank should be cleaned to empty: %q", got)
	}
}

// Continuation depth: generations in a chain must accumulate correctly.
func TestContinuationDepthAccumulates(t *testing.T) {
	// Old nodes (no continuation_depth field) count as first-gen.
	old := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`{"summary":"x"}`)}
	if got := continuationDepthOf(old); got != 1 {
		t.Fatalf("old intent without field should count as gen 1, got %d", got)
	}
	// Explicitly recorded depth.
	n2 := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`{"summary":"x","continuation_depth":2}`)}
	if got := continuationDepthOf(n2); got != 2 {
		t.Fatalf("should read gen 2, got %d", got)
	}
	// Illegal values fall back to 1.
	bad := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`{"summary":"x","continuation_depth":0}`)}
	if got := continuationDepthOf(bad); got != 1 {
		t.Fatalf("illegal depth should fall back to 1, got %d", got)
	}
	// nil-safe.
	if got := continuationDepthOf(nil); got != 1 {
		t.Fatalf("nil should return 1, got %d", got)
	}
	// Non-JSON payloads are safe too.
	broken := &db.Node{Kind: db.KindIntent, Payload: json.RawMessage(`not json`)}
	if got := continuationDepthOf(broken); got != 1 {
		t.Fatalf("bad payload should return 1, got %d", got)
	}
}

// The continuation-depth cap must be 3 — 2 is too tight (kills legitimate deep-dives), 4+ too loose (can't stop infinite chains).
func TestMaxContinuationDepthValue(t *testing.T) {
	if maxContinuationDepth != 3 {
		t.Fatalf("continuation depth cap should be 3, got %d", maxContinuationDepth)
	}
}

// intentItem must parse the continues field.
func TestIntentItemParsesContinues(t *testing.T) {
	var it intentItem
	in := `{"summary":"continue digging from #578","continues":[578],"parent_ids":[558],"asset_ids":[12]}`
	if err := json.Unmarshal([]byte(in), &it); err != nil {
		t.Fatal(err)
	}
	if got := pidList(it.Continues); len(got) != 1 || got[0] != 578 {
		t.Fatalf("continues parse error: %v", got)
	}
	if got := pidList(it.ParentIDs); len(got) != 1 || got[0] != 558 {
		t.Fatalf("parent_ids parse error: %v", got)
	}
}

// With no continues given, it's empty (not a 0-element containing 0).
func TestIntentItemWithoutContinues(t *testing.T) {
	var it intentItem
	if err := json.Unmarshal([]byte(`{"summary":"brand-new direction"}`), &it); err != nil {
		t.Fatal(err)
	}
	if got := pidList(it.Continues); len(got) != 0 {
		t.Fatalf("omitted continues should be empty: %v", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
