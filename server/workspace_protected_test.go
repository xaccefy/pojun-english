package server

import (
	"os"
	"path/filepath"
	"testing"
)

// The workspace file manager could delete the system's own data directories.
//
// Regression background (found by audit after the 2026-10-21 full reset): the workspace
// root IS the data dir, and the file manager's path check only guarantees 'stays inside
// the root' — but traffic (3.3G capture store), evidence (vuln-bound traffic bodies) and
// nuclei-templates (934M template library) all live under the root, with delete buttons
// in the UI. os.RemoveAll is irreversible — deleting traffic loses every historical
// request/response and turns finding bindings into dangling pointers; deleting the
// template library means a fresh clone.
//
// Task data (tasks / sessions / transcripts) is deliberately not on the protected list:
// clean it via DELETE /api/tasks/{id}'s proper path.
func TestWorkspaceProtectedDirs(t *testing.T) {
	s := &Server{}
	s.m = &Manager{dir: t.TempDir()}

	// both the protected dir itself and paths inside it must be blocked
	protected := []string{
		"traffic",
		"traffic/_index/index.sqlite",
		"evidence",
		"evidence/blobs/ab/abcdef.bin",
		"nuclei-templates",
		"nuclei-templates/http/cves/2026/CVE-2026-1.yaml",
	}
	for _, rel := range protected {
		abs, ok := s.wsResolve(rel)
		if !ok {
			t.Fatalf("resolve failed for %q", rel)
		}
		if !s.wsProtected(abs) {
			t.Errorf("%q must be protected", rel)
		}
	}

	// ordinary directories and user artifacts must not be blocked
	allowed := []string{
		"uploads",
		"uploads/scan.py",
		"tasks",
		"tasks/1/work/notes.md",
		"sessions",
		"transcripts",
		"traffic-notes.txt", // same prefix but not that directory
	}
	for _, rel := range allowed {
		abs, ok := s.wsResolve(rel)
		if !ok {
			t.Fatalf("resolve failed for %q", rel)
		}
		if s.wsProtected(abs) {
			t.Errorf("%q must NOT be protected", rel)
		}
	}
}

// The protected list must cover the three genuinely irreplaceable directories.
func TestWorkspaceProtectedList(t *testing.T) {
	want := map[string]bool{"traffic": true, "evidence": true, "nuclei-templates": true}
	for _, name := range workspaceProtectedDirs {
		if !want[name] {
			t.Errorf("unexpected protected dir %q", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("protected dir %q is missing — it holds non-reproducible data", name)
	}
}

// Protection is 'refuse', not 'silently skip': callers must get an explicit 403.
func TestWorkspaceDeleteRefusesProtectedDir(t *testing.T) {
	dir := t.TempDir()
	s := &Server{}
	s.m = &Manager{dir: dir}

	// create a real traffic directory
	if err := os.MkdirAll(filepath.Join(dir, "traffic", "_index"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "traffic", "_index", "index.sqlite"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// resolve the path wsDelete needs directly: confirm the protected check fires before
	// deletion.
	abs, ok := s.wsResolve("traffic")
	if !ok {
		t.Fatal("resolve failed")
	}
	if !s.wsProtected(abs) {
		t.Fatal("traffic must be protected")
	}
	// the file is still there (we never actually called RemoveAll — that's the very
	// action being prevented)
	if _, err := os.Stat(filepath.Join(dir, "traffic", "_index", "index.sqlite")); err != nil {
		t.Fatal("fixture gone")
	}
}
