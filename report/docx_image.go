package report

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif"  // registers DecodeConfig (gif is allowed too, re-saved in its original format)
	_ "image/jpeg" // registers DecodeConfig
	_ "image/png"  // registers DecodeConfig
)

// docxImage is an inline image waiting to be embedded (v0.5.0 report screenshots).
// In OOXML an image is a separate media part plus a relationship reference, and sizes are
// in EMU (1pt=12700EMU, and 1px=9525EMU at 96dpi). It is scaled proportionally to fit the
// text block so a screenshot cannot burst the page.
type docxImage struct {
	rid     string
	name    string // file name under word/media/ (image1.png)
	data    []byte
	cx, cy  int64 // EMU
	caption string
	seq     int
}

// Text block size (GB/T 9704: 156mm × 225mm); images leave a margin, at most ~144mm wide.
const (
	maxImageWidthEMU  int64 = 5_200_000 // ≈144.4mm
	maxImageHeightEMU int64 = 7_000_000 // ≈194.4mm
	pxToEMU           int64 = 9525      // 96dpi
)

// Image embeds one image and emits "centered image paragraph + centered caption
// paragraph". Only formats whose size the Go standard library can decode (png/jpeg/gif) are
// accepted; on failure it returns false and the caller decides whether to fall back to a
// text description (one bad image must not fail the whole report).
func (d *Docx) Image(data []byte, caption string) bool {
	if len(data) == 0 {
		return false
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 {
		return false
	}
	ext := "png"
	switch format {
	case "jpeg":
		ext = "jpg"
	case "gif":
		ext = "gif"
	}
	w := int64(cfg.Width) * pxToEMU
	h := int64(cfg.Height) * pxToEMU
	if w > maxImageWidthEMU {
		h = h * maxImageWidthEMU / w
		w = maxImageWidthEMU
	}
	if h > maxImageHeightEMU {
		w = w * maxImageHeightEMU / h
		h = maxImageHeightEMU
	}
	n := len(d.images) + 1
	img := docxImage{
		rid: fmt.Sprintf("rIdImg%d", n), name: fmt.Sprintf("image%d.%s", n, ext),
		data: data, cx: w, cy: h, caption: caption, seq: n,
	}
	d.images = append(d.images, img)

	// Image paragraph: centered, no first-line indent, line spacing auto (exact would crop the
	// image).
	fmt.Fprintf(&d.buf,
		`<w:p><w:pPr><w:spacing w:before="120" w:after="60" w:line="240" w:lineRule="auto"/><w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>`+
			`<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">`+
			`<wp:extent cx="%d" cy="%d"/><wp:docPr id="%d" name="figure%d" descr="%s"/>`+
			`<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">`+
			`<pic:pic><pic:nvPicPr><pic:cNvPr id="%d" name="%s"/><pic:cNvPicPr/></pic:nvPicPr>`+
			`<pic:blipFill><a:blip r:embed="%s"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>`+
			`<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm>`+
			`<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>`+
			`</a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`,
		img.cx, img.cy, img.seq, img.seq, esc(caption), img.seq, esc(img.name), img.rid, img.cx, img.cy)
	if caption != "" {
		// Caption: centered, 10.5pt (size 5), 28pt line spacing.
		fmt.Fprintf(&d.buf,
			`<w:p><w:pPr><w:spacing w:before="0" w:after="120" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>`+
				`<w:r><w:rPr><w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr><w:t xml:space="preserve">Figure %d: %s</w:t></w:r></w:p>`,
			n, esc(caption))
	}
	return true
}
