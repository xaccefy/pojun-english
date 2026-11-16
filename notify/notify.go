// Package notify implements the IM / email push-channel adapter layer for vuln findings.
//
// Layering: this is a **leaf package** — stdlib only. It knows neither the database nor the
// server. Channel config arrives as map[string]any (the notification_channels.config JSONB
// column), push content as a Message. The split exists so the genuinely error-prone parts —
// signature computation, UTF-8 truncation, filter matching — can be unit-tested without
// PostgreSQL; the host only orchestrates on the server side.
//
// Concurrency contract: Channel implementations must be **stateless**. One Channel instance is
// shared concurrently by many channel configs (even multiple bot instances of the same kind);
// all credentials come in via the cfg parameter — never cache things like webhook URLs into
// the implementation's own fields.
package notify

// Channel kind identifiers. The values are also the valid set for notification_channels.kind,
// whitelisted on the server side (same as findings.status — no DB CHECK, so kinds can be added).
const (
	KindDingTalk = "dingtalk" // DingTalk custom bot
	KindFeishu   = "feishu"   // Feishu (incl. Lark) custom bot
	KindWeCom    = "wecom"    // WeCom group bot
	KindWebhook  = "webhook"  // generic webhook: custom method/headers/JSON template
	KindTelegram = "telegram" // Telegram Bot API
	KindEmail    = "email"    // SMTP email
)

// Event kinds, matching notification_events.kind.
const (
	EventFindingCreated       = "finding_created"
	EventFindingStatusChanged = "finding_status_changed"
)

// InitKind is the fallback for an empty kind in config.
const InitKind = KindDingTalk

// severityRank maps vuln severity to a comparable ordinal. Unknown severities return 0, so any
// min_severity setting keeps them out — when in doubt, don't push; avoids false-alarm spam.
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityRank returns a severity's ordinal; unknown → 0.
func SeverityRank(severity string) int { return severityRank[severity] }

// SeverityLabel returns an emoji-prefixed level name for message titles and card colors.
// Unknown severities echo back verbatim — never invented.
func SeverityLabel(severity string) string {
	switch severity {
	case "critical":
		return "🔴 Critical"
	case "high":
		return "🟠 High"
	case "medium":
		return "🟡 Medium"
	case "low":
		return "🔵 Low"
	default:
		return severity
	}
}

// StatusLabel maps a triage status to its display label for status-change messages.
func StatusLabel(status string) string {
	switch status {
	case "pending":
		return "Pending"
	case "in_progress":
		return "In progress"
	case "confirmed":
		return "Confirmed"
	case "resolved":
		return "Resolved"
	case "fixed":
		return "Fixed"
	case "false_positive":
		return "False positive"
	case "ignored":
		return "Ignored"
	case "duplicate":
		return "Duplicate"
	case "risk_accepted":
		return "Risk accepted"
	default:
		return status
	}
}

// AtLeast reports whether severity meets the min threshold. Empty min = no gate, always pass.
// Note unknown severities rank 0 — rejected by any non-empty min (see severityRank comment).
func AtLeast(severity, min string) bool {
	if min == "" {
		return true
	}
	return SeverityRank(severity) >= SeverityRank(min)
}
