package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter is the contract of the notification_channels.filter JSONB column: a channel
// instance's filter conditions. All fields optional; absent = 'no filtering' — exactly the
// fallback semantics for malformed config, see ParseFilter.
type Filter struct {
	// MinSeverity is the minimum severity gate (low/medium/high/critical); empty = no gate.
	MinSeverity string `json:"min_severity"`
	// TaskIDs / AssetIDs: empty array = unrestricted; non-empty requires the event to intersect.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// VulnClassInclude: empty = accept all; non-empty requires vulnclass to hit any keyword.
	// VulnClassExclude: hitting any keyword excludes (exclusion wins over inclusion).
	// Matching is a case-insensitive substring — safer than regex: a bad user regex can't
	// silently kill the channel.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange decides whether the channel receives vuln status-change events (only meaningful in realtime mode).
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter parses a channel's filter config.
//
// **Never returns error.** Deliberate design: malformed filter config degrades to the zero
// Filter (= no filtering = everything matches), because for a vuln-notification system,
// **pushing one extra beats silently dropping a high-severity finding**. Turning a parse
// failure into 'push nothing' hands the user a channel that looks configured but pushes
// nothing — the worst failure mode.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// On parse failure f stays zero-valued — i.e. no filtering.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity reports whether s is a valid severity threshold (empty = no gate).
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks the **restricted-range** fields of a filter config, called on channel save.
//
// Why it must be blocked at write time: Match treats an unknown threshold as `rank >= 0` —
// always true. So a typo in min_severity ("hgih") makes the filter **silently dead**, pushing
// everything. That's consistent with this package's 'rather over-push than miss' trade-off
// (nothing is lost), but the result is a user who thinks they set tiered pushing while every
// vuln floods the group — with no sign anything is misconfigured. Exactly the kind of
// 'silent degradation' that belongs at the entry gate.
//
// Note Validate is for the **write** path only. Reads keep ParseFilter's lenient semantics so
// bad values already in historical data can't make a channel unreadable.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("invalid min severity %q — use low / medium / high / critical, or leave empty for no gate", f.MinSeverity)
	}
	return nil
}

// Match decides whether an event should be delivered to a channel with this filter.
//
// **Never returns error**, same rationale as ParseFilter: any internal anomaly counts as
// 'match'. Decision order: event kind → severity gate → task/asset scope → vulnclass keywords.
func Match(f Filter, s Snapshot) bool {
	// Status-change events go only to channels that explicitly opted in. Default off: most users
	// expect 'push' to mean 'new vuln found', not a log of every status transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclusion wins: hitting any exclude keyword rejects it, even if the include list matched.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// Linear scan over small sets is fine; both sides are 'a few dozen hand-picked ids' —
	// building a map costs more than it saves.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any keyword (case-insensitive).
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
