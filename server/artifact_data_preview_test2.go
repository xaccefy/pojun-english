package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Large files read only the first 20MB (truncated is decided upstream with TotalRows;
// this verifies it doesn't blow up).
func TestParseLargeTextHead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.log")
	f, _ := os.Create(p)
	line := strings.Repeat("x", 200) + "\n"
	for i := 0; i < dataPreviewMaxLines*3; i++ {
		_, _ = f.WriteString(line)
	}
	f.Close()
	b, _ := os.ReadFile(p)
	r := parseTextPreview(string(b))
	if !r.Truncated || r.TotalRows != dataPreviewMaxLines*3 {
		t.Fatalf("meta=%+v", r)
	}
}
