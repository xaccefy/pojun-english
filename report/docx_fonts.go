package report

import "embed"

// The three official-document fonts ship with the binary (go:embed) and are embedded
// into the document (odttf) on Word export, so the recipient can render it per GB/T 9704
// without installing them. The font file names are ASCII — go:embed paths containing CJK
// are unreliable across cross-platform builds and git checkouts; the TTF-internal family
// names (the ones referenced in the docx) are still FangSong_GB2312 / KaiTi_GB2312 /
// FangZheng XiaoBiaoSong_GBK (measured with fc-scan).
// Copyright note: the three fonts are the standard official-document font pack supplied by
// the user and are only distributed with reports exported by this platform.
//
//go:embed fonts/fangsong_gb2312.ttf fonts/kaiti_gb2312.ttf fonts/fzxiaobiaosong_gbk.ttf
var gongwenFontFS embed.FS

// embedGongwenFonts attaches the three official-document fonts to the document. A single
// font failing to load is only skipped, never an error — without it we degrade to
// "reference the font name" (still fine when the recipient has the font installed), and
// the whole export must not fail.
func embedGongwenFonts(d *Docx) {
	for _, e := range []struct{ name, file string }{
		{"FangSong_GB2312", "fonts/fangsong_gb2312.ttf"},
		{"KaiTi_GB2312", "fonts/kaiti_gb2312.ttf"},
		{"FangZheng XiaoBiaoSong_GBK", "fonts/fzxiaobiaosong_gbk.ttf"},
	} {
		if b, err := gongwenFontFS.ReadFile(e.file); err == nil {
			d.EmbedFont(e.name, b)
		}
	}
}
