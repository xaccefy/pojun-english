#!/usr/bin/env python3
"""Repo-wide CJK scan.

Reports every CJK character (ideographs, CJK punctuation, fullwidth forms) in
text files, both as literal characters and as escaped sequences, and lists the
binary image/font assets explicitly instead of skipping them silently -- binary
assets carry no text, so they are reported as "binary (no text layer)".

Usage: python3 scripts/scan_cjk.py [root ...]
"""
import os
import re
import sys

# Ideograph, CJK punctuation and fullwidth blocks, given as integers so this
# file itself stays free of any non-ASCII escape sequence.
CJK_RANGES = (
    (0x2E80, 0x2EFF),  # CJK radicals supplement
    (0x2F00, 0x2FDF),  # Kangxi radicals
    (0x2FE0, 0x2FFF),  # ideographic description characters
    (0x3000, 0x303F),  # CJK symbols and punctuation
    (0x3040, 0x30FF),  # kana
    (0x3100, 0x318F),  # bopomofo / hangul jamo
    (0x31C0, 0x31FF),  # CJK strokes
    (0x3200, 0x33FF),  # enclosed CJK + compatibility
    (0x3400, 0x4DBF),  # extension A
    (0x4E00, 0x9FFF),  # unified ideographs
    (0xA000, 0xA4CF),  # Yi syllables
    (0xF900, 0xFAFF),  # compatibility ideographs
    (0xFE10, 0xFE1F),  # vertical forms
    (0xFE30, 0xFE4F),  # compatibility forms
    (0xFF00, 0xFFEF),  # fullwidth forms
)


def _char_class():
    return "[" + "".join(chr(lo) + "-" + chr(hi) for lo, hi in CJK_RANGES) + "]"


CJK = re.compile(_char_class())
ESCAPE = re.compile(r"(\\+)u([0-9A-Fa-f]{4})|(\\+)x\{([0-9A-Fa-f]+)\}")
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".zip", ".gz", ".bz2", ".xz",
    ".pdf", ".mp4", ".mov", ".webm", ".wav", ".mp3", ".so", ".dylib", ".dll",
    ".exe", ".bin", ".sqlite", ".db",
}


def is_binary(path):
    if os.path.splitext(path)[1].lower() in BINARY_EXT:
        return True
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(4096)
    except OSError:
        return True


def main(argv):
    roots = argv[1:] or ["."]
    total_literal = 0
    total_escaped = 0
    binaries = []
    offenders = []

    for root in roots:
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".next")]
            for name in files:
                path = os.path.join(base, name)
                if is_binary(path):
                    binaries.append(path)
                    continue
                try:
                    with open(path, encoding="utf-8") as fh:
                        text = fh.read()
                except (UnicodeDecodeError, OSError):
                    binaries.append(path)
                    continue
                literal = CJK.findall(text)
                escaped = []
                for m in ESCAPE.finditer(text):
                    raw = m.group(2) or m.group(4)
                    try:
                        code = int(raw, 16)
                    except ValueError:
                        continue
                    if any(lo <= code <= hi for lo, hi in CJK_RANGES):
                        escaped.append(m.group(0))
                if literal or escaped:
                    offenders.append((path, len(literal), len(escaped)))
                    total_literal += len(literal)
                    total_escaped += len(escaped)

    print("CJK scan")
    print("=" * 60)
    for path, lit, esc in offenders:
        print(f"  {path}: {lit} literal, {esc} escaped")
    print("-" * 60)
    print(f"  literal CJK characters : {total_literal}")
    print(f"  escaped CJK sequences  : {total_escaped}")
    print(f"  text files with CJK    : {len(offenders)}")
    print(f"  binary assets (no text layer, listed explicitly): {len(binaries)}")
    for path in binaries:
        print(f"      binary  {path}")
    print("=" * 60)
    ok = total_literal == 0 and total_escaped == 0
    print("RESULT:", "CLEAN - no CJK anywhere" if ok else "CJK FOUND")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
