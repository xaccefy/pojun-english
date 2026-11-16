package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// telegramTextLimit is Telegram sendMessage's text field cap (in characters).
const telegramTextLimit = 4096

// telegramChannel implements the Telegram Bot API.
//
// Platform traits:
//   - All auth lives in the URL path (/bot<token>/sendMessage) — no signing needed.
//   - HTML parse mode, not MarkdownV2: MarkdownV2 needs 18 chars escaped
//     (`_*[]()~`>#+-=|{}.!`) and a single miss rejects the message; HTML needs only & < >.
//   - Business errors likewise hide inside HTTP 200 — the ok field decides.
type telegramChannel struct{}

func (telegramChannel) Kind() string { return KindTelegram }

// Telegram allows ~1 msg/s in private chats, 20/min in groups. Conservative value used.
func (telegramChannel) DefaultRatePerMin() int { return 20 }

// Bot Token is the full credential; chat_id is just a recipient — not secret (useless without the Token).
func (telegramChannel) SecretKeys() []string { return []string{"bot_token"} }

// base_url decides which API endpoint receives the Token (e.g. a self-hosted reverse proxy); changing it requires re-affirming the Token.
func (telegramChannel) DestinationKeys() []string { return []string{"base_url"} }

func (telegramChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "bot_token") == "" {
		return errors.New("missing bot token")
	}
	if cfgString(cfg, "chat_id") == "" {
		return errors.New("missing chat ID")
	}
	if base := cfgString(cfg, "base_url"); base != "" {
		if err := validateHTTPURL(base); err != nil {
			return fmt.Errorf("invalid API URL: %w", err)
		}
	}
	return nil
}

func (c telegramChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := telegramEndpoint(cfg)
	if err != nil {
		return 0, Permanent(err)
	}
	text, kept := telegramHTML(m)
	payload := map[string]any{
		"chat_id":                  cfgString(cfg, "chat_id"),
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": false,
	}
	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse Telegram response: %w (%s)", err, snippet(raw))
	}
	if res.OK {
		return kept, nil
	}
	// 429 is rate limiting — retry-after-backoff works; the rest (400 bad params, 401 bad
	// token, 403 blocked, 404 chat missing) are config problems retries can't heal.
	if res.ErrorCode == 429 {
		return 0, fmt.Errorf("Telegram rate-limited: %s", res.Description)
	}
	return 0, Permanent(fmt.Errorf("Telegram error %d: %s", res.ErrorCode, res.Description))
}

// telegramEndpoint builds the sendMessage URL. Empty base_url = official API; non-empty
// supports a self-hosted Bot API reverse proxy (common under restricted networks).
func telegramEndpoint(cfg map[string]any) (string, error) {
	base := cfgString(cfg, "base_url")
	if base == "" {
		base = "https://api.telegram.org"
	}
	base = strings.TrimSuffix(base, "/")
	token := cfgString(cfg, "bot_token")
	raw := base + "/bot" + token + "/sendMessage"
	u, err := url.Parse(raw)
	if err != nil {
		// Don't pass err through: the URL contains the Bot Token — even the addr must not echo.
		return "", fmt.Errorf("failed to build API URL (base URL: %s)", redactRequestTarget(base))
	}
	return u.String(), nil
}

// telegramHTML renders the HTML body, returning body + actually-written item count (see Channel.Send).
func telegramHTML(m Message) (string, int) {
	var b strings.Builder
	b.WriteString("<b>" + telegramEscape(markdownTitle(m)) + "</b>\n")
	if m.Batch {
		// Telegram's cap is in **characters** — packing measures in runes (runeSize).
		footer := ""
		if m.HomeURL != "" {
			footer = fmt.Sprintf("\n\n<a href=\"%s\">View all in platform</a>", telegramEscapeAttr(m.HomeURL))
		}
		kept := packItemCount(m.Items, telegramTextLimit, telegramReservedRunes, footer, runeSize, func(it Item, idx int) string {
			return telegramBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		b.Reset()
		b.WriteString("<b>" + telegramEscape(telegramBatchTitle(m, items, len(m.Items))) + "</b>")
		for i, it := range items {
			b.WriteString("\n" + telegramEscape(telegramBatchLine(it, i+1)))
		}
		b.WriteString(footer)
		return TruncateHTML(b.String(), telegramTextLimit), kept
	}
	if len(m.Items) == 0 {
		return b.String(), 0
	}
	it := m.Items[0]
	if it.IsStatusChange() {
		b.WriteString(fmt.Sprintf("\n<b>Status change</b>: %s → %s",
			telegramEscape(StatusLabel(it.FromStatus)), telegramEscape(StatusLabel(it.ToStatus))))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		b.WriteString("\n<b>Type</b>: " + telegramEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		b.WriteString("\n<b>Assets</b>: " + telegramEscape(a))
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		b.WriteString("\n<b>Summary</b>: " + telegramEscape(s))
	}
	if it.DetailURL != "" {
		b.WriteString(fmt.Sprintf("\n\n<a href=\"%s\">View details</a>", telegramEscapeAttr(it.DetailURL)))
	}
	return TruncateHTML(b.String(), telegramTextLimit), 1
}

// telegramReservedRunes is reserved for the title and a possible truncation note (in runes).
const telegramReservedRunes = 160

// telegramBatchLine renders one digest line (unescaped — the caller escapes uniformly).
func telegramBatchLine(it Item, idx int) string {
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		return fmt.Sprintf("%d. %s · %s — %s", idx, SeverityLabel(it.Severity), it.Title(), a)
	}
	return fmt.Sprintf("%d. %s · %s", idx, SeverityLabel(it.Severity), it.Title())
}

// telegramBatchTitle renders the digest title line. The count is what **this message
// actually holds**, not the batch total — otherwise readers take the header number as
// everything.
func telegramBatchTitle(m Message, items []Item, total int) string {
	title := fmt.Sprintf("Vuln digest · %d items", total)
	if extra := total - len(items); extra > 0 {
		title += fmt.Sprintf(" (first %d shown; %d more next message)", len(items), extra)
	}
	if m.WindowMinutes > 0 {
		title = fmt.Sprintf("Last %d min · %s", m.WindowMinutes, title)
	}
	return title
}

// telegramEscape escapes HTML text content.
// Telegram accepts only these three entities; an existing &amp; gets re-escaped — exactly
// the intent: display the raw characters, never let users inject HTML.
func telegramEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// telegramEscapeAttr escapes HTML attribute values — quotes on top of text escaping:
// a quote inside a URL would close the href early and turn the rest into an injection point.
func telegramEscapeAttr(s string) string {
	s = telegramEscape(s)
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
