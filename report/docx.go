// The docx sub-module of package report: a hand-written minimal OOXML (.docx) generator.
// It introduces no third-party document library — a .docx is essentially zip + XML, and the
// elements a report needs (heading levels / paragraphs / lists / tables / page breaks) are
// covered by a small generator. In exchange: zero new dependencies, the single-binary
// philosophy stays intact, and the output structure is fully controllable (the built-in
// report template's fonts/sizes/table borders all live in styles.xml).
package report

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"
)

// Docx is a document being assembled; the methods append elements in order.
type Docx struct {
	buf        bytes.Buffer
	headerText string      // header text (SetHeaderText; empty = the default "Penetration Test Report")
	fonts      []docxFont  // embedded fonts (EmbedFont; obfuscated into odttf on Encode)
	images     []docxImage // report illustrations (Image; packed into word/media on Encode)
	// artifactImage resolves ![caption](artifact:<id>) inside Markdown (injected by the host:
	// it fetches image bytes and captions from the task evidence attachment store).
	// nil = inline images are not supported.
	artifactImage func(id int64) (data []byte, caption string, ok bool)
}

// docxFont is a font waiting to be embedded: the OOXML font name plus the raw TTF bytes.
type docxFont struct {
	name string
	ttf  []byte
}

// EmbedFont registers a TTF with the document and packs it obfuscated on Encode. The three
// official-document fonts (FangSong_GB2312/KaiTi_GB2312/FZXiaoBiaoSong_GBK) ship with neither recent
// Windows nor Linux; without embedding, Word silently falls back to SimSun and both the line
// box and the glyphs change (the other half of the root cause behind the user-reported
// "the line spacing is all wrong"). Once embedded, the recipient needs no fonts to render
// it as intended.
func (d *Docx) EmbedFont(name string, ttf []byte) {
	d.fonts = append(d.fonts, docxFont{name: name, ttf: ttf})
}

// obfuscateFont produces the ECMA-376 odttf obfuscated body and the fontKey: a random GUID,
// and the first 32 bytes of the TTF are XORed with the GUID's 16 bytes in reverse cyclic
// order at index 15-(i%16) (the same algorithm as docx4j / OpenXML SDK); Word/WPS reverse
// it via the fontKey when opening. Returns a fontKey shaped like {XXXXXXXX-...}.
func obfuscateFont(ttf []byte) (data []byte, key string) {
	var g [16]byte
	_, _ = rand.Read(g[:])
	g[6] = g[6]&0x0f | 0x40 // version 4
	g[8] = g[8]&0x3f | 0x80 // variant 10
	key = fmt.Sprintf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15])
	out := make([]byte, len(ttf))
	copy(out, ttf)
	for i := 0; i < 32 && i < len(out); i++ {
		out[i] ^= g[15-i%16]
	}
	return out, key
}

// NewDocx creates an empty document (the first heading after the automatic cover page is
// likewise controlled by the caller).
func NewDocx() *Docx { return &Docx{} }

// SetArtifactImageResolver injects the evidence attachment image resolver (v0.5.0).
func (d *Docx) SetArtifactImageResolver(fn func(id int64) ([]byte, string, bool)) {
	d.artifactImage = fn
}

var xmlEsc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

// esc escapes XML and cleans the input: invalid UTF-8 and control characters XML 1.0 forbids
// make Word report "there is a problem with the contents" or render a whole block wrong, so
// they must be handled before writing (see cleanText).
func esc(s string) string { return xmlEsc.Replace(cleanText(s)) }

// H1/H2/H3 headings.
func (d *Docx) H1(text string) { d.heading(text, 1) }
func (d *Docx) H2(text string) { d.heading(text, 2) }
func (d *Docx) H3(text string) { d.heading(text, 3) }

func (d *Docx) heading(text string, level int) {
	fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:pStyle w:val="Heading%d"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, level, esc(text))
}

// headingColored is a heading with a heading color (for severity coloring: critical red /
// high orange / medium amber / low blue).
func (d *Docx) headingColored(text string, level int, hex string) {
	fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:pStyle w:val="Heading%d"/></w:pPr><w:r><w:rPr><w:color w:val="%s"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, level, hex, esc(text))
}

// H4 is a fourth-level heading (subsections inside a finding's detail: the ## in the report
// body is demoted to this instead of being flattened).
func (d *Docx) H4(text string) { d.heading(text, 4) }

// Run is a rich-text fragment (used by PRich).
type Run struct {
	Text string
	Bold bool
	Code bool // inline code (`x`): distinguished by the Consolas font
}

// PRich is a rich-text paragraph: supports **bold** (the basis of Markdown rich rendering
// A5). \n splits it into several paragraphs.
func (d *Docx) PRich(text string) {
	for _, line := range strings.Split(text, "\n") {
		d.buf.WriteString(`<w:p>`)
		d.buf.WriteString(runsXML(parseRich(line)))
		d.buf.WriteString(`</w:p>`)
	}
}

// parseRich supports `inline code` on top of **bold** (distinguished by the Consolas font,
// v0.4.0): reporter bodies contain many `POST /path` and `totalRows` markers, and emitting
// the backticks verbatim is hard to read.
func parseRich(line string) []Run {
	var out []Run
	rest := line
	for {
		i := strings.Index(rest, "`")
		if i < 0 {
			break
		}
		if i > 0 {
			out = append(out, parseBold(rest[:i])...)
		}
		rest = rest[i+1:]
		j := strings.Index(rest, "`")
		if j < 0 {
			out = append(out, Run{Text: "`"})
			break
		}
		out = append(out, Run{Text: rest[:j], Code: true})
		rest = rest[j+1:]
	}
	if len(rest) > 0 || len(out) == 0 {
		out = append(out, parseBold(rest)...)
	}
	return out
}

// parseBold splits a line into Runs by **bold**. Unpaired ** is treated literally.
func parseBold(line string) []Run {
	var runs []Run
	rest := line
	bold := false
	for {
		i := strings.Index(rest, "**")
		if i < 0 {
			break
		}
		if i > 0 {
			runs = append(runs, Run{Text: rest[:i], Bold: bold})
		}
		rest = rest[i+2:]
		bold = !bold
	}
	if rest != "" || len(runs) == 0 {
		runs = append(runs, Run{Text: rest, Bold: bold})
	}
	return runs
}

func runsXML(runs []Run) string {
	var b strings.Builder
	for _, r := range runs {
		var props []string
		if r.Bold {
			props = append(props, "<w:b/>")
		}
		if r.Code {
			props = append(props, `<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>`)
		}
		rpr := ""
		if len(props) > 0 {
			rpr = "<w:rPr>" + strings.Join(props, "") + "</w:rPr>"
		}
		fmt.Fprintf(&b, `<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>`, rpr, esc(r.Text))
	}
	return b.String()
}

// P is a body paragraph (\n splits it into several).
func (d *Docx) P(text string) {
	for _, line := range strings.Split(text, "\n") {
		fmt.Fprintf(&d.buf, `<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(line))
	}
}

// Code is a monospaced code block (for evidence/PoC): shading + left vertical rule,
// Consolas, whitespace preserved.
// The whole block becomes a single paragraph (w:br between lines) — one paragraph per line
// would split a long JSON into hundreds of separate paragraphs that visually scatter (one of
// the main causes of the Kali user-reported "it all piles up together").
func (d *Docx) Code(text string) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var b strings.Builder
	b.WriteString(`<w:p><w:pPr><w:pStyle w:val="Code"/></w:pPr>`)
	for i, line := range lines {
		if i > 0 {
			b.WriteString(`<w:r><w:br/></w:r>`)
		}
		fmt.Fprintf(&b, `<w:r><w:t xml:space="preserve">%s</w:t></w:r>`, esc(line))
	}
	b.WriteString(`</w:p>`)
	d.buf.WriteString(b.String())
}

// Hei1 is an official-document level-1 heading: SimHei size 3, first-line indent of 2
// characters (e.g. "1. Assessment overview").
func (d *Docx) Hei1(text string) {
	d.buf.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(text)))
}

// Kai2 is an official-document level-2 heading: KaiTi size 3, first-line indent of 2
// characters (e.g. "(1) Reproduction steps").
func (d *Docx) Kai2(text string) {
	d.buf.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(text)))
}

// Bullet is an unordered list item.
func (d *Docx) Bullet(text string) {
	// ind firstLine=0: clear Normal's official-document first-line indent; indentation is left
	// to the numbering definition
	fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr><w:ind w:firstLine="0"/><w:jc w:val="both"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(text))
}

// Table is a table with a header row. When rows and header disagree on column count, the
// shorter one is padded.
func (d *Docx) Table(header []string, rows [][]string) {
	d.TableFills(header, rows, nil)
}

// TableFills is a table with row fills: fills[i] is the fill hex for data row i (empty string
// or out of range = no fill). Used to color the severity distribution table by severity
// (A2).
func (d *Docx) TableFills(header []string, rows [][]string, fills []string) {
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="0" w:type="auto"/></w:tblPr><w:tblGrid>`)
	for range header {
		b.WriteString(`<w:gridCol w:w="1800"/>`)
	}
	b.WriteString(`</w:tblGrid>`)
	// Cell text at 10pt: with the body font size raised to size 3, a table that inherits it
	// would deform badly
	cell := func(text, fill string) {
		sty := ""
		if fill != "" {
			sty = fmt.Sprintf(`<w:shd w:val="clear" w:fill="%s"/>`, fill)
		}
		fmt.Fprintf(&b, `<w:tc><w:tcPr>%s</w:tcPr><w:p><w:pPr><w:spacing w:line="240" w:lineRule="auto"/><w:ind w:firstLine="0"/></w:pPr><w:r><w:rPr><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>`, sty, esc(text))
	}
	b.WriteString(`<w:tr>`)
	for _, h := range header {
		cell(h, "DEEAF6")
	}
	b.WriteString(`</w:tr>`)
	for ri, r := range rows {
		b.WriteString(`<w:tr>`)
		fill := ""
		if ri < len(fills) {
			fill = fills[ri]
		}
		for i := range header {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			cell(v, fill)
		}
		b.WriteString(`</w:tr>`)
	}
	b.WriteString(`</w:tbl>`)
	// OOXML requires an empty paragraph after a table
	b.WriteString(`<w:p/>`)
	d.buf.WriteString(b.String())
}

// PageBreak inserts a page break.
func (d *Docx) PageBreak() {
	d.buf.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
}

// coverLineSpacing is the cover line spacing: size-2 text (>=20pt, the cover document title)
// uses 35pt — 28pt exact cannot hold size-2 text and Word/LibreOffice crops the glyphs top
// and bottom (one of the main causes of the user-reported "the line spacing is all wrong";
// GB/T 9704 practice sets the title line spacing at 35pt); everything else uses 28pt.
func coverLineSpacing(sz int) string {
	line := 560
	if sz >= 40 {
		line = 700
	}
	return fmt.Sprintf(`<w:spacing w:before="120" w:after="0" w:line="%d" w:lineRule="exact"/>`, line)
}

// CoverLine is a cover line: centered, with a selectable half-point size (sz) and color.
// Empty text emits an empty line (to pad the layout).
func (d *Docx) CoverLine(text string, sz int, bold bool) {
	// Override Normal's justification/first-line indent/28pt line spacing — cover lines are
	// centered with independently controlled spacing.
	spacing := coverLineSpacing(sz)
	if text == "" {
		spacing = `<w:spacing w:before="0" w:after="0" w:line="720" w:lineRule="exact"/>`
	}
	pPr := fmt.Sprintf(`<w:pPr>%s<w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>`, spacing)
	if text == "" {
		fmt.Fprintf(&d.buf, `<w:p>%s</w:p>`, pPr)
		return
	}
	rpr := "<w:rPr>"
	if bold {
		// Official-document title: FZXiaoBiaoSong size 2, not bold (GB/T 9704 7.3.3 title setting; the
		// font is embedded with the document, so it renders as intended even without the font
		// installed)
		rpr += `<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="FZXiaoBiaoSong_GBK"/><w:b w:val="0"/>`
	}
	if sz > 0 {
		rpr += fmt.Sprintf(`<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, sz, sz)
	}
	rpr += "</w:rPr>"
	fmt.Fprintf(&d.buf, `<w:p>%s<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r></w:p>`, pPr, rpr, esc(text))
}

// CoverLineColored is a colored cover line (used to color the single-finding cover by
// severity).
func (d *Docx) CoverLineColored(text string, sz int, hex string, bold bool) {
	// Same layout as CoverLine (centered/indent cleared/spacing overridden, size-2 title at
	// 35pt); the official-document title uses XiaoBiaoSong without bold and ascii is uniformly Times
	// New Roman.
	boldXML := ""
	if bold {
		boldXML = `<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="FZXiaoBiaoSong_GBK"/><w:b w:val="0"/>`
	} else {
		boldXML = `<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="FangSong_GB2312"/><w:b w:val="0"/>`
	}
	szXML := ""
	if sz > 0 {
		szXML = fmt.Sprintf(`<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, sz, sz)
	}
	fmt.Fprintf(&d.buf,
		`<w:p><w:pPr>%s<w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr><w:r><w:rPr>%s<w:color w:val="%s"/>%s</w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		coverLineSpacing(sz), boldXML, hex, szXML, esc(text))
}

// TOC field: Word refreshes it automatically per the updateFields setting when opening
// (settings.xml already sets updateFields, see Encode). \o "1-3" collects Heading1-3 — H4
// (finding detail subsections) stays out of the TOC.
func (d *Docx) TOC() {
	d.buf.WriteString(`<w:p><w:fldSimple w:instr=" TOC \o &quot;1-3&quot; \h \z \u ">` +
		`<w:r><w:t>(press F9 or use print preview in Word to refresh the table of contents)</w:t></w:r></w:fldSimple></w:p>`)
}

// Encode packs the document into a .docx byte stream.
func (d *Docx) Encode(w io.Writer) error {
	// Header/footer references use the r: namespace (r:id of headerReference/footerReference).
	// Page setup matches the official-document reference: margins top 2098/right 1474/bottom
	// 1984/left 1587, docGrid 360.
	// The official document has no header — headerReference is removed, and page numbers go in
	// the footer as "— N —".
	document := `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body>` +
		d.buf.String() +
		`<w:sectPr>` +
		`<w:footerReference w:type="default" r:id="rIdFtr"/>` +
		`<w:pgSz w:w="11906" w:h="16838"/>` +
		`<w:pgMar w:top="2098" w:right="1474" w:bottom="1984" w:left="1587" w:header="720" w:footer="720" w:gutter="0"/>` +
		// docGrid 580: GB/T 9704 text block 225mm ÷ 22 lines per page ≈ 29pt per line grid
		// (the reference file's 360 is Word's default 18pt grid, which does not match the 22-line
		// spec).
		`<w:cols w:space="720"/><w:docGrid w:linePitch="580"/>` +
		`</w:sectPr></w:body></w:document>`

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>`
	if len(d.images) > 0 {
		contentTypes += `
<Default Extension="png" ContentType="image/png"/>
<Default Extension="jpg" ContentType="image/jpeg"/>
<Default Extension="gif" ContentType="image/gif"/>`
	}
	if len(d.fonts) > 0 {
		// odttf content type: the official MIME (the same one Word uses for its own embedded
		// documents) — with application/octet-stream Word judges the file corrupt and refuses
		// to open it.
		contentTypes += `
<Default Extension="odttf" ContentType="application/vnd.openxmlformats-officedocument.obfuscatedFont"/>
<Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/>`
	}
	contentTypes += "\n</Types>"

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

	// numbering.xml: Bullet references numId=1 — the package previously lacked this part and
	// bullets silently did not render in Word (v0.3.93 A1, a visible bug in report
	// presentation).
	// The styles.xml relationship was missing too — Word never received the style part, so the
	// entire official-document style system (FangSong_GB2312 body / first-line indent / 28pt fixed
	// line spacing / heading fonts) never took effect and everything rendered in Word's
	// default DengXian (the overall root cause of the user-reported "the line spacing is all
	// wrong", fixed in v0.4.4).
	documentRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
<Relationship Id="rIdSty" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rIdFtr" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
<Relationship Id="rIdSet" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>`
	for _, img := range d.images {
		documentRels += fmt.Sprintf(`
<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/%s"/>`, img.rid, img.name)
	}
	if len(d.fonts) > 0 {
		documentRels += `
<Relationship Id="rIdFT" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>`
	}
	documentRels += "\n</Relationships>"

	// settings.xml: embedTrueTypeFonts declares embedded fonts; updateFields makes Word
	// refresh TOC/PAGE and similar fields when opening the document. (The schema requires
	// embedTrueTypeFonts before updateFields; a wrong order makes Word report the document as
	// corrupt.)
	settings := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
` + func() string {
		if len(d.fonts) > 0 {
			return "<w:embedTrueTypeFonts/>"
		}
		return ""
	}() + `
<w:updateFields w:val="true"/>
</w:settings>`

	// Official-document page number: centered footer "— N —" (size-4 half-width SimSun digits
	// between two em dashes), no header.
	footer := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:p><w:pPr><w:jc w:val="center"/></w:pPr>
<w:r><w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr><w:t xml:space="preserve">— </w:t></w:r>
<w:r><w:fldChar w:fldCharType="begin"/></w:r>
<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>
<w:r><w:fldChar w:fldCharType="end"/></w:r>
<w:r><w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr><w:t xml:space="preserve"> —</w:t></w:r>
</w:p>
</w:ftr>`

	zw := zip.NewWriter(w)
	files := []struct{ name, body string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + document},
		{"word/_rels/document.xml.rels", documentRels},
		{"word/styles.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + docxStyles},
		{"word/numbering.xml", numbering()},
		{"word/settings.xml", settings},
		{"word/footer1.xml", footer},
	}
	// Report illustrations: word/media/imageN.ext (the relationships are already in
	// document.xml.rels).
	for _, img := range d.images {
		fw, err := zw.Create("word/media/" + img.name)
		if err != nil {
			return err
		}
		if _, err := fw.Write(img.data); err != nil {
			return err
		}
	}
	// Embedded fonts: fontTable.xml (font name → odttf relationship + fontKey) and
	// word/fonts/fontN.odttf per font (its relationship table is
	// word/_rels/fontTable.xml.rels).
	if len(d.fonts) > 0 {
		var fontDecls, fontRels strings.Builder
		for i, f := range d.fonts {
			data, key := obfuscateFont(f.ttf)
			fw, err := zw.Create(fmt.Sprintf("word/fonts/font%d.odttf", i+1))
			if err != nil {
				return err
			}
			if _, err := fw.Write(data); err != nil {
				return err
			}
			rid := fmt.Sprintf("rIdF%d", i+1)
			fontDecls.WriteString(fmt.Sprintf(
				`<w:font w:name="%s"><w:charset w:val="86"/><w:family w:val="auto"/><w:pitch w:val="variable"/><w:embedRegular r:id="%s" w:fontKey="%s"/></w:font>`,
				esc(f.name), rid, key))
			fmt.Fprintf(&fontRels,
				`<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/font" Target="fonts/font%d.odttf"/>`,
				rid, i+1)
		}
		files = append(files,
			struct{ name, body string }{"word/fontTable.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` + fontDecls.String() + `</w:fonts>`},
			struct{ name, body string }{"word/_rels/fontTable.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + fontRels.String() + `</Relationships>`},
		)
	}
	for _, f := range files {
		fw, err := zw.Create(f.name)
		if err != nil {
			return err
		}
		if _, err := io.Copy(fw, strings.NewReader(f.body)); err != nil {
			return err
		}
	}
	return zw.Close()
}

// SetHeaderText customizes the header text (client name/report name). Must be called before
// Encode.
func (d *Docx) SetHeaderText(text string) { d.headerText = text }

// numbering is the numbering.xml part: numId=1 → bullet (referenced by the Bullet method).
func numbering() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:abstractNum w:abstractNumId="0">
<w:multiLevelType w:val="hybridMultilevel"/>
<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#8226;"/><w:lvlJc w:val="left"/>
<w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Symbol" w:hAnsi="Symbol" w:hint="default"/></w:rPr></w:lvl>
<w:lvl w:ilvl="1"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="o"/><w:lvlJc w:val="left"/>
<w:pPr><w:ind w:left="1440" w:hanging="360"/></w:pPr></w:lvl>
<w:lvl w:ilvl="2"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#61623;"/><w:lvlJc w:val="left"/>
<w:pPr><w:ind w:left="2160" w:hanging="360"/></w:pPr></w:lvl>
</w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
</w:numbering>`
}

// docxNum is packed on demand; headerText is passed through via the Docx field.

// docxStyles holds the built-in Chinese official-document style (GB/T 9704 style choices):
// body FangSong size 3 (16pt), first-line indent of 2 characters, fixed 28pt line spacing;
// level-1 heading SimHei size 3, level-2 SimHei size 4, levels 3/4 SimHei size small-4;
// code Consolas size small-5 tightly set with shading. Heading1 outline level 0 (visible in
// Word's navigation pane).
const docxStyles = `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="FangSong_GB2312"/>
<w:b w:val="0"/><w:color w:val="000000"/>
<w:sz w:val="32"/><w:szCs w:val="32"/>
</w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:styleId="Normal" w:default="1"><w:name w:val="Normal"/>
<w:pPr><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/>
<w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="0"/><w:spacing w:before="120" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="SimHei"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="1"/><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="KaiTi_GB2312"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="2"/><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="SimHei"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="3"/><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="SimHei"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="60" w:after="60" w:line="240" w:lineRule="auto"/>
<w:ind w:left="240" w:firstLine="0"/><w:jc w:val="left"/>
<w:shd w:val="clear" w:fill="F7F7F7"/>
<w:pBdr><w:left w:val="single" w:sz="12" w:space="4" w:color="BFBFBF"/></w:pBdr></w:pPr>
<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="SimSun"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/>
<w:tblPr><w:tblBorders>
<w:top w:val="single" w:sz="4" w:color="999999"/><w:left w:val="single" w:sz="4" w:color="999999"/>
<w:bottom w:val="single" w:sz="4" w:color="999999"/><w:right w:val="single" w:sz="4" w:color="999999"/>
<w:insideH w:val="single" w:sz="4" w:color="999999"/><w:insideV w:val="single" w:sz="4" w:color="999999"/>
</w:tblBorders></w:tblPr></w:style>
</w:styles>`

// SeverityHex is the primary severity color (for headings/table fills, A2).
func SeverityHex(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "C00000" // deep red
	case "high":
		return "ED7D31" // orange
	case "medium":
		return "BF9000" // amber
	case "low":
		return "5B9BD5" // blue
	default:
		return ""
	}
}

// SeverityHexSoft is the soft severity fill (for table row fills, lighter than the primary
// color).
func SeverityHexSoft(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "F8CBCC"
	case "high":
		return "FBE5D5"
	case "medium":
		return "FFF2CC"
	case "low":
		return "DEEAF6"
	default:
		return ""
	}
}

// SeverityCN maps a severity to its display label (used in reports).
func SeverityCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return s
	}
}

// FormatTimeUTC is the unified time display (UTC, avoiding timezone ambiguity in reports).
func FormatTimeUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
