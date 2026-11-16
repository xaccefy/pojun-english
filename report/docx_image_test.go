package report

import (
	"archive/zip"
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

// TestDocxImageEmbed verifies the OOXML structure of image embedding: the media part, the
// drawing in document.xml, the relationship table and Content_Types are all mandatory
// (Word has zero tolerance for a missing relationship or content type).
func TestDocxImageEmbed(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 4, 3))
	for x := 0; x < 4; x++ {
		for y := 0; y < 3; y++ {
			img.Set(x, y, color.RGBA{R: 200, A: 255})
		}
	}
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		t.Fatal(err)
	}

	d := NewDocx()
	d.P("before")
	if !d.Image(pngBuf.Bytes(), "user list page after login") {
		t.Fatal("Image() rejected valid png")
	}
	d.P("after")
	var out bytes.Buffer
	if err := d.Encode(&out); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		var b bytes.Buffer
		_, _ = b.ReadFrom(rc)
		rc.Close()
		files[f.Name] = b.String()
	}
	if _, ok := files["word/media/image1.png"]; !ok {
		t.Fatal("missing media part")
	}
	doc := files["word/document.xml"]
	for _, want := range []string{
		"<w:drawing>", `r:embed="rIdImg1"`, "Figure 1: user list page after login",
		`xmlns:wp=`, `xmlns:pic=`, `<wp:extent cx=`,
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document.xml missing %q", want)
		}
	}
	rels := files["word/_rels/document.xml.rels"]
	if !strings.Contains(rels, "media/image1.png") || !strings.Contains(rels, "relationships/image") {
		t.Fatalf("document rels missing image relationship: %s", rels)
	}
	if !strings.Contains(files["[Content_Types].xml"], `Extension="png"`) {
		t.Fatal("content types missing png")
	}
	// A bad image must not panic; it returns false and the caller degrades.
	if d.Image([]byte("not-an-image"), "x") {
		t.Fatal("invalid image must be rejected")
	}
}
