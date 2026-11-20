package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A workspace symlink must not become a read/write/delete escape hatch.
func TestWorkspaceResolveRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &Server{m: &Manager{dir: base}}
	for _, rel := range []string{"link/secret", "link/new-file"} {
		if _, ok := s.wsResolve(rel); ok {
			t.Fatalf("workspace escape via %q was accepted", rel)
		}
	}
	if abs, ok := s.wsResolve("safe/new-file"); !ok || !pathWithin(base, abs) {
		t.Fatalf("safe path rejected: abs=%q ok=%v", abs, ok)
	}
	if abs, ok := s.wsResolve(""); !ok || filepath.Clean(abs) != filepath.Clean(base) {
		t.Fatalf("workspace root rejected: abs=%q ok=%v", abs, ok)
	}
}

// 工作区内指向受保护目录的符号链接不能成为写入口。
func TestWorkspaceSymlinkCannotWriteProtectedDirs(t *testing.T) {
	data := t.TempDir()
	traffic := filepath.Join(data, "traffic")
	if err := os.MkdirAll(traffic, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(traffic, "existing.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(data, "alias")
	if err := os.Symlink(traffic, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &Server{m: &Manager{dir: data}}

	// write：alias/pwned.txt 实际落在 traffic/
	body, _ := json.Marshal(map[string]string{"path": "alias/pwned.txt", "content": "pwned"})
	w := httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", bytes.NewReader(body)))
	if w.Code != 403 {
		t.Fatalf("write through symlink: status=%d body=%s, want 403", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(traffic, "pwned.txt")); err == nil {
		t.Fatal("write through symlink created a file in protected traffic dir")
	}

	// mkdir：alias/new-dir 实际落在 traffic/
	body, _ = json.Marshal(map[string]string{"path": "alias/new-dir"})
	w = httptest.NewRecorder()
	s.wsMkdir(w, httptest.NewRequest("POST", "/api/workspace/mkdir", bytes.NewReader(body)))
	if w.Code != 403 {
		t.Fatalf("mkdir through symlink: status=%d body=%s, want 403", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(traffic, "new-dir")); err == nil {
		t.Fatal("mkdir through symlink created a directory in protected traffic dir")
	}

	// upload 到 alias/ 目录：目录本身是符号链接
	upload := func(dir string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "upload.txt")
		_, _ = fw.Write([]byte("pwned"))
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/api/workspace/upload?path="+dir, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		s.wsUpload(rec, req)
		return rec
	}
	if rec := upload("alias"); rec.Code != 403 {
		t.Fatalf("upload into symlinked dir: status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(traffic, "upload.txt")); err == nil {
		t.Fatal("upload into symlinked dir created a file in protected traffic dir")
	}

	// 最终目标本身是符号链接：uploads/upload.txt -> traffic/existing.txt
	uploads := filepath.Join(data, "uploads")
	if err := os.MkdirAll(uploads, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(traffic, "existing.txt"), filepath.Join(uploads, "upload.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if rec := upload("uploads"); rec.Code != 403 {
		t.Fatalf("upload onto symlinked file: status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}

	// 正常路径仍可写（不能因为修复把所有写入都挡掉）
	body, _ = json.Marshal(map[string]string{"path": "notes/a.txt", "content": "ok"})
	w = httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("normal write rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}
