package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes cuts s to at most max bytes, keeping valid UTF-8 and never splitting
// a character.
//
// Why rune boundaries matter: the WeCom bot's markdown has a hard 4096-**byte** cap (not
// characters), and a CJK char costs 3 bytes. A raw byte slice can split a character in
// half, producing invalid UTF-8 — the platform either rejects the message or shows mojibake
// blocks. Here we back off from the budget position to the nearest rune-start byte
// (utf8.RuneStart detects continuation bytes 0b10xxxxxx).
//
// max<=0 means unlimited. An ellipsis is appended unless max is too small to hold one.
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// max shorter than the ellipsis itself: drop the ellipsis, plain truncation — keeps the result within max.
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine collapses multi-line text to one line: fold all whitespace, then truncate by
// character count. Used for IM message title lines — summaries often contain newlines that
// would break tables/titles. max<=0 means unlimited.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes cuts s to at most max characters (not bytes), appending an ellipsis.
// max<=0 means unlimited.
//
// Unlike TruncateBytes the unit follows the platform: WeCom limits by bytes, Telegram by
// characters. The wrong unit doesn't error — it just cuts far shorter than expected (a CJK
// char = 3 bytes; byte-cutting 4096 leaves ~1365 chars) — so both functions must exist and
// be chosen per channel.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML truncates an HTML fragment by character count without leaving half tags.
//
// Raw rune truncation of HTML can cut out `<a href="htt`-style fragments; platform parsers
// either reject the whole message or swallow following text as an attribute value. Here we
// truncate by runes, then check the tail for an unclosed `<` and back off before it.
//
// No tag balancing (completing </b> etc.): Telegram's HTML parser auto-closes open tags,
// while rolling our own balancing means handling quoted attributes, comments and self-closing
// tags — complexity far beyond the payoff.
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// If the tail is a `<`-led fragment (last `<` has no following `>`), back off to before it.
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// A cut HTML entity at the tail (e.g. `&amp;` split into `&amp`) gets backed off the same
	// way. An entity fragment can make an entity-aware parser reject the **whole message** —
	// oversized digests are common enough that losing an entire notification isn't worth it.
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount computes how many items fit **whole** within budget, for whole-item digest
// packing.
//
// Why whole items instead of render-all-then-truncate: truncation makes the tail items
// vanish while their delivery records still say sent — invisible in the message and the
// history, the vulns simply disappear. With whole-item packing, leftovers stay queued for the
// next batch and the caller's kept is the true delivered count.
//
// Params: maxSize<=0 means unlimited; reserve is set aside for head/tail; size does the
// measuring (unit differs per platform: WeCom/DingTalk by bytes, Telegram by runes — the
// wrong unit doesn't error, it just crushes CJK messages far below the cap); render produces
// item idx's real text — length varies by content, estimation won't do.
//
// Returns at least 1 (while items remain). A single extreme-length item still goes out, with
// the caller's final truncation as backstop — otherwise one oversized vuln jams the batch
// forever.
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize / runeSize are packItemCount's two measure units, named so call sites don't show
// a bare func(s string) int closure that hides which unit is in use.
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine renders the asset list as one display line; beyond limit it elides the rest and
// notes the total. A vuln may anchor dozens of assets — listing all floods the message.
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " etc. " + itoa(len(assets)) + " total"
}

// itoa is a short alias for strconv.Itoa, used only for display text — avoids importing strconv everywhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
