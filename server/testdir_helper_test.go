package server

// Test infrastructure: a tolerant directory for async-teardown races.
//
// NewManager/the engine hold async goroutines (activity writes, transcript persistence)
// that briefly outlive m.Close() and still write files; t.TempDir()'s framework cleanup is
// a strict RemoveAll, and hitting such a 'closed but goroutines alive' directory fails the
// test outright (unlinkat ... directory not empty). Reproduced three times on CI (under
// different test names).
//
// testDir substitutes lenient cleanup via t.Cleanup: wait briefly for async writers to
// exit, then delete, ignoring failure. Only tests that hit the problem migrate here; new
// tests can still use t.TempDir() by default.

import (
	"os"
	"strings"
	"testing"
	"time"
)

func testDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pojun-test-"+sanitizeName(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Retry with backoff for up to 30s: async writers plus a template tree of tens of thousands
		// of small files — a single RemoveAll often doesn't delete it cleanly.
		var last error
		for i := 0; i < 120; i++ {
			if last = os.RemoveAll(dir); last == nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Logf("cleanup temp dir %s: %v", dir, last) // best-effort, but no longer silent
	})
	return dir
}

func sanitizeName(name string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(name)
}
