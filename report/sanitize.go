package report

import (
	"strings"
	"unicode/utf8"
)

// cleanText makes text from any source safe to write into UTF-8 artifacts (Markdown /
// OOXML):
//   - invalid UTF-8 byte sequences become U+FFFD, so a downstream encoding guess does not
//     turn the whole block into mojibake;
//   - control characters XML 1.0 forbids are removed (\x00-\x08, \x0B, \x0C, \x0E-\x1F,
//     \x7F), otherwise Word warns "there is a problem with the contents" or silently drops
//     characters.
//
// Tab/newline/carriage return are preserved. Idempotent.
func cleanText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
}

// truncateUTF8 cuts s to at most maxBytes bytes without splitting a multi-byte character.
// A byte-wise cut splits a CJK character's UTF-8 sequence in half and yields invalid
// UTF-8 — the zip then does not set the UTF-8 flag, and Windows/WinRAR decoding as
// CP437/GBK turns it into mojibake (measured: 86 of 192 entries hit).
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
