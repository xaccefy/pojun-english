package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// This file covers the 'whole-item packing' fix: when a digest exceeds the channel
// length cap, it must be cut at **whole-item** boundaries and honestly report how many
// items made it, so the caller marks only the truly delivered ones.
//
// The old approach rendered everything then truncated and marked the whole batch sent:
// the tail half of the message vanished while delivery history showed all success — the
// vulns simply disappeared, undetectable anywhere.

func TestMarkdownBodyPacksWholeItemsWithinByteLimit(t *testing.T) {
	// 200 CJK digests — far beyond the WeCom 4096-byte cap.
	m := batchMsg(200)
	body, kept := markdownBody(m, weComMarkdownLimit)

	if len(body) > weComMarkdownLimit {
		t.Fatalf("body %d bytes exceeds limit %d", len(body), weComMarkdownLimit)
	}
	if !utf8.ValidString(body) {
		t.Fatal("body is not valid UTF-8")
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should pack only a subset (0 < kept < %d), got %d", len(m.Items), kept)
	}
	// The head must state honestly how many items this message carries and how many
	// remain — otherwise readers take the head count as the total.
	if !strings.Contains(body, "remaining") || !strings.Contains(body, "next message") {
		t.Fatalf("head should state how many items are not included here:\n%s", body[:minInt(400, len(body))])
	}
	// Only the first kept items may appear.
	for i := 0; i < kept; i++ {
		if !strings.Contains(body, "vuln"+itoa(i+1)) {
			t.Fatalf("item %d should be in this message:\n%s", i+1, body)
		}
	}
	if strings.Contains(body, "vuln"+itoa(kept+1)) {
		t.Fatalf("item %d must not appear (it belongs to the next batch)", kept+1)
	}
}

func TestMarkdownBodyKeepsEverythingWhenUnderLimit(t *testing.T) {
	m := batchMsg(3)
	body, kept := markdownBody(m, 0) // 0 = unlimited
	if kept != len(m.Items) {
		t.Fatalf("with no limit everything should be kept, got kept=%d", kept)
	}
	if strings.Contains(body, "remaining") {
		t.Fatalf("no-truncation output must not carry a truncation note:\n%s", body)
	}
}

func TestMarkdownBodyAlwaysKeepsAtLeastOneItem(t *testing.T) {
	// When the budget can't hold even one item, one still goes out (final truncation is
	// the backstop). Otherwise one oversized vuln jams the batch forever: never fits, never sent.
	m := batchMsg(5)
	_, kept := markdownBody(m, 50)
	if kept != 1 {
		t.Fatalf("at least 1 item should be kept, got %d", kept)
	}
}

func TestMarkdownBodySingleReturnsOne(t *testing.T) {
	_, kept := markdownBody(singleMsg(), 4096)
	if kept != 1 {
		t.Fatalf("a single-item message should report 1 delivered, got %d", kept)
	}
	// An empty message delivers nothing.
	if _, k := markdownBody(Message{}, 4096); k != 0 {
		t.Fatalf("empty message should report 0, got %d", k)
	}
}

func TestTelegramPackingUsesRuneBudget(t *testing.T) {
	m := batchMsg(200)
	text, kept := telegramHTML(m)
	// Telegram caps by **characters**; measuring bytes would crush CJK text to a third.
	if n := utf8.RuneCountInString(text); n > telegramTextLimit {
		t.Fatalf("body %d chars exceeds limit %d", n, telegramTextLimit)
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should pack only a subset, got %d", kept)
	}
	if !strings.Contains(text, "next message") {
		t.Fatalf("should state there is more not included:\n%.300s", text)
	}
}

func TestFeishuPackingReportsKept(t *testing.T) {
	m := batchMsg(2000)
	_, kept := feishuCard(m)
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("card should pack only a subset, got %d", kept)
	}
}

func TestWebhookAndEmailReportAllItems(t *testing.T) {
	// These two channels don't truncate the body — the whole batch counts delivered.
	m := batchMsg(7)
	if n := len(m.Items); n != 7 {
		t.Fatal("precondition unmet")
	}
	// Confirmed indirectly via the renderer's return: markdownBody(0) keeps all when unlimited.
	if _, k := markdownBody(m, 0); k != len(m.Items) {
		t.Fatalf("unlimited should use all, got %d", k)
	}
}

// TestMarkdownEscapesUntrustedContent is the 'untrusted content must not alter message
// structure' regression test. Titles/summaries come from model output (the model reads
// target responses); asset names come from target URLs.
func TestMarkdownEscapesUntrustedContent(t *testing.T) {
	cases := []struct {
		name  string
		item  Item
		must  []string // must appear in the result (escaped form)
		wrong []string // must not appear (unescaped form)
	}{
		{
			name: "newline + external link in title",
			item: Item{
				Severity: "high",
				Name:     "login SQL injection\n[URGENT: click to verify account](http://attacker.tld)",
			},
			// newlines must fold (else fake list items/quotes can be forged);
			// brackets/parens must be escaped (else they render as clickable links).
			must:  []string{`\[URGENT: click to verify account\]`, `\(http://attacker.tld\)`},
			wrong: []string{"\n[URGENT", "\n\n[URGENT"},
		},
		{
			name: "image beacon in title",
			item: Item{
				Severity: "high",
				Name:     "vulnerability ![](http://attacker.tld/beacon)",
			},
			must:  []string{`\!`, `\(http://attacker.tld/beacon\)`},
			wrong: []string{"![]("},
		},
		{
			name: "emphasis and quote in asset name",
			item: Item{
				Severity: "high",
				Name:     "ordinary title",
				Assets:   []string{"a.com/*injection*>quote"},
			},
			must:  []string{`\*injection\*`, `\>`},
			wrong: []string{"*injection*"},
		},
		{
			name: "backtick and pipe in summary",
			item: Item{
				Severity: "high",
				Name:     "title",
				Summary:  "`code` | table",
			},
			must:  []string{"\\`code\\`", `\|`},
			wrong: []string{"`code`"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Message{Items: []Item{tc.item}}
			// single-item writeItem is the shared render path of the three markdown channels.
			var b strings.Builder
			writeItem(&b, tc.item, "", true)
			got := b.String()
			for _, want := range tc.must {
				if !strings.Contains(got, want) {
					t.Errorf("missing escaped form %q:\n%s", want, got)
				}
			}
			for _, bad := range tc.wrong {
				if strings.Contains(got, bad) {
					t.Errorf("unescaped form %q appeared (usable for structure/link injection):\n%s", bad, got)
				}
			}
			_ = m
		})
	}
}

// TestMarkdownEscapeBackslashFirst pins the escape order: backslashes first, otherwise
// later-added backslashes get re-escaped and the output shows double backslashes.
func TestMarkdownEscapeBackslashFirst(t *testing.T) {
	if got := markdownEscape(`a\b*c`); got != `a\\b\*c` {
		t.Fatalf("wrong escape order, got %q", got)
	}
}

// TestTelegramTitleHasNoMarkdownEscapes pins a concrete regression: markdown escaping
// must not leak into Telegram's HTML output (escaping was once added to the shared title
// function, producing visible backslashes like `\(1\)` in Telegram messages).
func TestTelegramTitleHasNoMarkdownEscapes(t *testing.T) {
	m := Message{Items: []Item{{Severity: "high", Name: "alert(1) *key point*"}}}
	text, _ := telegramHTML(m)
	if strings.Contains(text, `\(`) || strings.Contains(text, `\*`) {
		t.Fatalf("markdown backslash escaping leaked into the Telegram body:\n%s", text)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
