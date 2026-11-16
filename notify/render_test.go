package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateBytesKeepsValidUTF8(t *testing.T) {
	// The single most important invariant in this package. WeCom caps by **bytes** and a
	// CJK char costs 3 bytes; any raw byte cut splits a character in half, producing
	// invalid UTF-8 the platform rejects. Inputs of coprime lengths (mixed CJK/ASCII)
	// hit every possible cut point.
	inputs := []string{
		"Chinese test content",
		"mixed Mixed content Content",
		"aXbYcZdWe",
		"🔴🟠🟡🔵", // 4-byte emoji — wrong cuts show up even more clearly
		strings.Repeat("vulnerability", 100),
	}
	for _, in := range inputs {
		for max := 1; max <= len(in)+2; max++ {
			got := TruncateBytes(in, max)
			if !utf8.ValidString(got) {
				t.Fatalf("input %q max=%d: produced invalid UTF-8 %q", in, max, got)
			}
			if len(got) > max {
				t.Fatalf("input %q max=%d: result %d bytes exceeds the cap", in, max, len(got))
			}
			// content must not be altered when nothing is truncated.
			if len(in) <= max && got != in {
				t.Fatalf("input %q max=%d: content altered despite being under the cap -> %q", in, max, got)
			}
		}
	}
}

func TestTruncateBytesZeroMeansUnlimited(t *testing.T) {
	long := strings.Repeat("x", 10000)
	if got := TruncateBytes(long, 0); got != long {
		t.Fatal("max=0 should mean unlimited")
	}
	if got := TruncateBytes(long, -5); got != long {
		t.Fatal("max<0 should mean unlimited")
	}
}

func TestTruncateBytesEllipsisBudget(t *testing.T) {
	// when max is smaller than the ellipsis itself, appending it must not overflow.
	got := TruncateBytes("abcdefgh", 1)
	if len(got) > 1 {
		t.Fatalf("max=1: result %q length %d exceeds", got, len(got))
	}
	// the normal case carries the ellipsis.
	if got := TruncateBytes("abcdefgh", 5); !strings.HasSuffix(got, ellipsis) {
		t.Fatalf("expected an ellipsis, got %q", got)
	}
}

func TestTruncateRunesCountsCharactersNotBytes(t *testing.T) {
	// The unit difference vs TruncateBytes must stay: Telegram caps by characters —
	// measuring bytes would cut a CJK message to a third.
	s := "café résumé naïve façade one two three"
	got := TruncateRunes(s, 5)
	if n := utf8.RuneCountInString(got); n != 5 {
		t.Fatalf("expected 5 chars, got %d (%q)", n, got)
	}
	// the same string measured in bytes should come out much shorter.
	if utf8.RuneCountInString(TruncateBytes(s, 5)) >= 5 {
		t.Fatal("the byte measure must not yield the same char count as the rune measure")
	}
}

func TestOneLineCollapsesWhitespace(t *testing.T) {
	got := OneLine("first line\n\nsecond line\twith tab   multiple spaces", 0)
	if strings.ContainsAny(got, "\n\t") {
		t.Fatalf("all whitespace should collapse, got %q", got)
	}
	if strings.Contains(got, "  ") {
		t.Fatalf("consecutive spaces must not survive, got %q", got)
	}
	// truncated output must stay readable and valid.
	got = OneLine("one two three four five six seven eight nine ten", 4)
	if n := utf8.RuneCountInString(got); n != 4 {
		t.Fatalf("expected 4 chars, got %d (%q)", n, got)
	}
}

func TestTruncateHTMLNeverCutsTagInHalf(t *testing.T) {
	// a raw HTML cut leaves fragments like `<a href="htt` — platforms reject the whole message.
	s := `<b>Title</b>body body body<a href="https://example.com/very/long/path">view details</a>`
	for max := 1; max <= utf8.RuneCountInString(s)+2; max++ {
		got := TruncateHTML(s, max)
		if n := utf8.RuneCountInString(got); max > 0 && n > max {
			t.Fatalf("max=%d: result %d chars exceeds", max, n)
		}
		// the tail must not end in an unclosed `<` (a `<` with no following `>`).
		if lt := strings.LastIndex(got, "<"); lt >= 0 && !strings.Contains(got[lt:], ">") {
			t.Fatalf("max=%d: tail tag was severed -> %q", max, got)
		}
	}
}

func TestAssetLineOmitsExcess(t *testing.T) {
	if got := assetLine(nil, 3); got != "" {
		t.Fatalf("no assets should yield an empty string, got %q", got)
	}
	if got := assetLine([]string{"a", "b"}, 3); got != "a, b" {
		t.Fatalf("under the cap everything should be listed, got %q", got)
	}
	// beyond the cap the total must be stated, or readers can't tell how many assets were elided.
	got := assetLine([]string{"a", "b", "c", "d", "e"}, 2)
	if !strings.Contains(got, "5 total") {
		t.Fatalf("should state the total 5, got %q", got)
	}
}

func TestSeverityAndStatusLabels(t *testing.T) {
	if AtLeast("", "low") {
		t.Fatal("empty severity ranks 0 — any threshold must block it")
	}
	if !AtLeast("critical", "") {
		t.Fatal("empty threshold should pass")
	}
	if got := StatusLabel("fixed"); got != "Fixed" {
		t.Fatalf("status mapping wrong, got %q", got)
	}
	// unknown statuses echo verbatim — never invent labels.
	if got := StatusLabel("weird_status"); got != "weird_status" {
		t.Fatalf("unknown status should echo verbatim, got %q", got)
	}
}

// TestTruncateHTMLNeverCutsEntity covers an audit-flagged gap: truncation must avoid
// severed HTML entities as well as half tags.
//
// Once `&amp;` is cut to `&amp`, an entity-aware parser may reject the **whole** message —
// oversized digests are common enough that the cost is too high.
func TestTruncateHTMLNeverCutsEntity(t *testing.T) {
	s := "aaaa&amp;bbbb&lt;cccc&quot;dddd"
	for max := 1; max <= utf8.RuneCountInString(s)+2; max++ {
		got := TruncateHTML(s, max)
		// the tail must not end in an entity fragment ('&' without its ';').
		if amp := strings.LastIndex(got, "&"); amp >= 0 && !strings.Contains(got[amp:], ";") {
			t.Fatalf("max=%d: tail holds entity fragment %q", max, got[amp:])
		}
		if strings.Contains(got, "&amp\x00") {
			t.Fatalf("max=%d: malformed entity", max)
		}
	}
}
