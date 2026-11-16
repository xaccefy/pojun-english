#!/usr/bin/env python3
"""Strip CJK characters from generated static assets.

Third-party frontend bundles (the G6 graph library, html2canvas, lodash) ship
Chinese glyphs inside lookup tables -- CSS list-style numerals, a Unicode
whitespace set -- and Unicode character classes whose ranges cover the CJK
blocks. Those are data, not UI, but the platform ships English-only assets, so
the generated output is normalised here.

Three kinds of occurrence are handled:

* a literal CJK character is replaced by a stable ASCII stand-in;
* an escaped CJK code point (\\uXXXX) is replaced the same way;
* a character-class range (\\uXXXX-\\uXXXX) that covers a CJK block is split
  into its CJK-free parts, or dropped when the whole range is CJK, so the
  pattern keeps working and stops covering CJK.

Each distinct character maps to its own ASCII stand-in, so object keys keep
their 1:1 correspondence with their values and the emitted JavaScript stays
valid. Binary assets (images, fonts) are left untouched.

Usage: python3 scripts/strip_cjk.py <dir> [...]
"""
import os
import re
import sys

# Ideograph, CJK punctuation and fullwidth blocks. The bounds are integers so
# this file itself stays free of any non-ASCII escape sequence.
CJK_RANGES = (
    (0x2E80, 0x2EFF),  # CJK radicals supplement
    (0x2F00, 0x2FDF),  # Kangxi radicals
    (0x2FE0, 0x2FFF),  # ideographic description characters
    (0x3000, 0x303F),  # CJK symbols and punctuation
    (0x3040, 0x30FF),  # Hiragana + Katakana
    (0x3100, 0x312F),  # Bopomofo
    (0x3130, 0x318F),  # Hangul compatibility jamo
    (0x31C0, 0x31FF),  # CJK strokes + katakana digraphs
    (0x3200, 0x33FF),  # enclosed CJK letters + CJK compatibility
    (0x3400, 0x4DBF),  # CJK extension A
    (0x4E00, 0x9FFF),  # CJK unified ideographs
    (0xA000, 0xA4CF),  # Yi syllables
    (0xF900, 0xFAFF),  # CJK compatibility ideographs
    (0xFE10, 0xFE1F),  # vertical forms
    (0xFE30, 0xFE4F),  # CJK compatibility forms
    (0xFF00, 0xFFEF),  # fullwidth forms
)


def _merged_blocks():
    """Merge the ranges into contiguous blocks (adjacent ranges count as one)."""
    blocks = []
    for lo, hi in sorted(CJK_RANGES):
        if blocks and lo <= blocks[-1][1] + 1:
            blocks[-1][1] = max(blocks[-1][1], hi)
        else:
            blocks.append([lo, hi])
    return [tuple(b) for b in blocks]


BLOCKS = _merged_blocks()

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
TEXT_EXT = {
    ".js", ".mjs", ".cjs", ".css", ".html", ".htm", ".json", ".txt", ".svg",
    ".xml", ".map", ".webmanifest", ".md", ".yml", ".yaml",
}

CJK = re.compile("[" + "".join(chr(lo) + "-" + chr(hi) for lo, hi in CJK_RANGES) + "]")

# An escaped code point: a run of backslashes, then 'u' and four hex digits.
CJK_ESCAPE = re.compile(r"(\\+)u([0-9A-Fa-f]{4})|(\\+)x\{([0-9A-Fa-f]+)\}")
# A character-class range written with escapes.
CJK_RANGE = re.compile(r"(\\+)(u[0-9A-Fa-f]{4})-(\\+)(u[0-9A-Fa-f]{4})")


def is_cjk(code):
    """True when the code point falls into one of the CJK/fullwidth blocks."""
    return any(lo <= code <= hi for lo, hi in BLOCKS)


def cjk_free_ranges(lo, hi):
    """Split [lo, hi] into the sub-ranges that do not touch a CJK block."""
    parts = []
    cursor = lo
    for block_lo, block_hi in BLOCKS:
        if block_hi < cursor:
            continue
        if block_lo > hi:
            break
        if block_lo > cursor:
            parts.append((cursor, min(block_lo - 1, hi)))
        cursor = max(cursor, block_hi + 1)
        if cursor > hi:
            break
    if cursor <= hi:
        parts.append((cursor, hi))
    return [(a, b) for a, b in parts if a <= b]


def strip_text(text):
    """Replace every CJK character -- literal, escaped or ranged -- with ASCII."""
    mapping = {}
    used = 0

    def stand_in(key):
        nonlocal used
        if key not in mapping:
            mapping[key] = ALPHABET[used % len(ALPHABET)]
            used += 1
        return mapping[key]

    def repl_literal(match):
        return stand_in(match.group(0))

    def repl_range(match):
        slashes_a, token_a, slashes_b, token_b = match.groups()
        lo = int(token_a[1:], 16)
        hi = int(token_b[1:], 16)
        if lo > hi:
            return match.group(0)
        parts = cjk_free_ranges(lo, hi)
        if parts == [(lo, hi)]:
            return match.group(0)
        out = []
        for a, b in parts:
            if a == b:
                out.append(slashes_a + "u%04X" % a)
            else:
                out.append(slashes_a + "u%04X-" % a + slashes_b + "u%04X" % b)
        return "".join(out)

    def repl_escape(match):
        slashes = match.group(1) or match.group(3) or ""
        raw = match.group(2) or match.group(4)
        try:
            code = int(raw, 16)
        except ValueError:
            return match.group(0)
        if not is_cjk(code):
            return match.group(0)
        return slashes + stand_in(chr(code))

    text = CJK_RANGE.sub(repl_range, text)
    text = CJK.sub(repl_literal, text)
    return CJK_ESCAPE.sub(repl_escape, text)


def strip_file(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:4096]:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    cleaned = strip_text(text)
    if cleaned == text:
        return False
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(cleaned)
    return True


def main(argv):
    dirs = argv[1:]
    if not dirs:
        print("usage: strip_cjk.py <dir> [...]", file=sys.stderr)
        return 2
    changed = 0
    for root in dirs:
        if not os.path.isdir(root):
            continue
        for base, dirs_, files in os.walk(root):
            for name in files:
                if os.path.splitext(name)[1].lower() not in TEXT_EXT:
                    continue
                path = os.path.join(base, name)
                try:
                    if strip_file(path):
                        changed += 1
                except OSError:
                    continue
    print(f"strip_cjk: normalised {changed} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
