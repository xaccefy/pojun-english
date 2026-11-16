package server

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

// TestArtifactKindDocument v0.4.21: Office/PDF count as previewable types.
func TestArtifactKindDocument(t *testing.T) {
	cases := map[string]string{
		"a.docx": "document", "a.xlsx": "spreadsheet", "a.pptx": "presentation", "a.pdf": "pdf", "a.csv": "spreadsheet",
		"a.png": "image", "a.json": "data", "a.bin": "other",
	}
	for name, want := range cases {
		if got, _ := artifactKindByExt(name); got != want {
			t.Fatalf("artifactKindByExt(%q)=%q want %q", name, got, want)
		}
	}
}

// TestWriteThumbnail verifies thumbnails: long edge scaled within 480, output is valid
// JPEG.
func TestWriteThumbnail(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "big.png")
	img := image.NewRGBA(image.Rect(0, 0, 1600, 900))
	for x := 0; x < 1600; x += 40 {
		for y := 0; y < 900; y++ {
			img.Set(x, y, color.RGBA{200, 30, 30, 255})
		}
	}
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dst := filepath.Join(dir, "big.png.thumb.jpg")
	if err := writeThumbnail(src, dst, 480); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil || len(raw) == 0 {
		t.Fatalf("thumb missing: %v", err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("thumb not jpeg: %v", err)
	}
	if cfg.Width != 480 || cfg.Height != 270 {
		t.Fatalf("thumb size=%dx%d want 480x270", cfg.Width, cfg.Height)
	}
	// a broken image returns an error (the caller falls back to the original).
	bad := filepath.Join(dir, "bad.jpg")
	_ = os.WriteFile(bad, []byte("not-an-image"), 0o644)
	if err := writeThumbnail(bad, filepath.Join(dir, "bad.thumb.jpg"), 480); err == nil {
		t.Fatal("invalid image must error")
	}
}
