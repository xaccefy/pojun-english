package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Log reads must be bounded: offset=0 reads the tail, offset>0 reads a window, total stays accurate.
func TestReadJobLogTailAndWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.log")
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "line-%d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	tail, total, err := readJobLog(path, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1000 || len(tail) != 10 {
		t.Fatalf("total=%d window=%d, want 1000/10", total, len(tail))
	}
	if tail[0] != "line-990" || tail[9] != "line-999" {
		t.Fatalf("tail window wrong: first %q last %q", tail[0], tail[9])
	}

	win, total, err := readJobLog(path, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1000 || len(win) != 3 {
		t.Fatalf("total=%d window=%d, want 1000/3", total, len(win))
	}
	if win[0] != "line-5" || win[2] != "line-7" {
		t.Fatalf("offset window wrong: %v", win)
	}

	// Out-of-range offset: empty window, no error.
	empty, total, err := readJobLog(path, 5000, 10)
	if err != nil || len(empty) != 0 || total != 1000 {
		t.Fatalf("out-of-range offset should return an empty window: window=%d total=%d err=%v", len(empty), total, err)
	}
}

// Oversized single lines must not load whole lines into memory: truncate + mark, numbering unaffected.
func TestReadJobLogTruncatesHugeLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.log")
	huge := strings.Repeat("A", jobLogLineMax*4)
	if err := os.WriteFile(path, []byte(huge+"\nshort\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, total, err := readJobLog(path, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(lines) != 2 {
		t.Fatalf("total=%d lines=%d, want 2/2", total, len(lines))
	}
	if len(lines[0]) > jobLogLineMax+len(" …(line too long, truncated)") {
		t.Fatalf("overlong line not truncated: %d bytes", len(lines[0]))
	}
	if !strings.Contains(lines[0], "truncated") {
		t.Fatal("overlong line should carry a truncation marker")
	}
	if lines[1] != "short" {
		t.Fatalf("truncation must not affect later lines: %q", lines[1])
	}
}

func TestReadJobLogEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	lines, total, err := readJobLog(path, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(lines) != 0 {
		t.Fatalf("empty file should return 0 lines: total=%d lines=%d", total, len(lines))
	}
}
