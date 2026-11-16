package notify

import (
	"fmt"
	"strings"
)

// Shared message rendering for the 'Markdown family' channels (DingTalk, WeCom).
// Feishu uses card JSON, Telegram and email use HTML — each rendered in its own adapter.

// maxAssetsShown caps how many assets a message lists. A vuln may anchor dozens;
// listing them all floods the message with no information value — nobody reads past the
// 4th domain in an IM.
const maxAssetsShown = 3

// maxSummaryRunes caps summary length. An IM message is 'a nudge to open the details',
// not the report itself — full content lives in the platform.
const maxSummaryRunes = 120

// markdownReservedBytes is reserved for the message head (digest line + severity
// distribution + possible truncation note) and tail (platform link). Whole-item packing
// deducts it from the budget so head/tail can't be cut — once they are, the reader can't
// even tell which batch this is or how many items weren't shown.
const markdownReservedBytes = 320

// markdownEscape escapes markdown metacharacters.
//
// Why it's required: vuln titles, summaries, classes and asset display names all come from
// **untrusted sources** — titles and summaries come from model output (the model reads the
// tested target's responses), asset URLs are the full scanned URLs (with target-controlled
// query strings). Without escaping, a vuln titled
//
//	login SQL injection\n[URGENT: verify account](http://attacker.tld)
//
// renders as a **clickable external link** in a security engineer's DingTalk/Feishu; and
// `![](http://attacker.tld/beacon)` gets fetched by the client at render — announcing
// 'this vuln was viewed' while leaking the reader's IP. Even benign content, like injected
// bold or quote blocks, can push a critical vuln below the fold.
//
// The escape set covers the characters that change structure or produce clickable
// elements: headings/links/emphasis/lists/quotes/strikethrough. `\` must run first —
// otherwise it re-escapes the backslashes added later.
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText compresses untrusted text to one line and escapes it for markdown bodies.
// Single-lining is the other half beyond escaping: a newline alone can forge a new list
// item or quote block, and escapes can't stop it.
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle returns the message title (IM title bar / card title) — the **unescaped**
// original text.
//
// Deliberately no escaping here: this title is shared by four render contexts — markdown
// body, Telegram HTML, Feishu-card plain_text, and the generic webhook's JSON plus the email
// subject. Each context escapes differently (markdown escapes inside HTML leave visible
// backslashes; inside JSON they corrupt data), so escaping is each output's own job — see
// writeItem / feishuItemLines / telegramEscape. A shared markdown escape once produced
// visible `\(1\)` sequences in Telegram messages.
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("Vuln digest · %d items", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "Vuln notification"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

// markdownBody renders the message body, returning the body and the **actually written
// item count**.
//
// kept is how many items this delivery truly carries; the caller marks only the first kept
// as delivered — items the channel length cap kept out must wait for the next batch, not be
// marked sent alongside. That's the source of 'silent loss': the message got truncated yet
// delivery records show all sent, and nothing reveals the tail never went out.
//
// maxBytes<=0 means unlimited.
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// A single oversized message still goes out (final truncation is the backstop): partial
		// info on one vuln beats sending nothing.
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[View all in platform](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro renders a digest message's opening: time window, count, severity
// distribution. With those, recipients can judge whether the batch needs immediate action
// without opening the platform.
//
// items is what **actually fit**; total is the batch's full count. When they differ the
// message must say 'how many continue in the next message' — otherwise readers assume the
// header number is everything, while the undelivered items don't exist anywhere in the UI.
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**%d new vulns in the last %d minutes**", total, m.WindowMinutes)
	} else {
		fmt.Fprintf(&b, "**%d new vulns**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, " (showing first %d items; the remaining %d continue in the next message)", len(items), extra)
	}
	// Per-severity distribution so readers spot criticals at a glance. Counts only the items
	// **actually in this message** — 'Critical 3' must match what can be counted below.
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem renders a single vuln entry.
//
// prefix is the digest-list serial number; single=true renders the full version (summary +
// deep link), digest lists render one compressed line — otherwise a 50-item digest becomes
// a long document.
//
// All externally sourced content (title/class/assets/summary) goes through markdownText:
// single-lining + escaping. The deep link is built from the admin-configured
// public_base_url — not untrusted — and must stay clickable, so it's emitted verbatim.
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// digest mode: one line, assets and summary compressed behind it.
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**Status change**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**Type**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**Assets**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**Summary**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[View details](%s)\n", it.DetailURL)
	}
}
