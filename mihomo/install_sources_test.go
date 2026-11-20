package mihomo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func gzBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPayloadFromArchive(t *testing.T) {
	raw := []byte("binary-bytes")
	got, err := payloadFromArchive("mihomo-linux-amd64-v1.gz", gzBytes(t, raw))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("gz unpack: %v %q", err, got)
	}
	// 裸二进制按原样返回（自定义来源常见）。
	got, err = payloadFromArchive("mihomo", raw)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("raw unpack: %v %q", err, got)
	}
}

func TestInstallFromFile(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	payload := []byte("#!/bin/sh\necho vtest\n")
	src := filepath.Join(t.TempDir(), "mihomo-test.gz")
	if err := os.WriteFile(src, gzBytes(t, payload), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := m.InstallFromFile(src)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	got, err := os.ReadFile(res.Path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("installed payload mismatch: %v", err)
	}
	if res.ChecksumVerified {
		t.Fatalf("file install without sha must not claim verified")
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(res.Path); err != nil || st.Mode().Perm()&0o111 == 0 {
			t.Fatalf("binary not executable: %v", st)
		}
	}
}

func TestInstallFromURLVerifiesSHA(t *testing.T) {
	payload := []byte("mihomo-binary")
	body := gzBytes(t, payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	m := New(t.TempDir())
	res, err := m.InstallFromURL(context.Background(), srv.URL+"/mihomo-linux-amd64-v1.gz", sha, "")
	if err != nil {
		t.Fatalf("install url: %v", err)
	}
	if !res.ChecksumVerified {
		t.Fatalf("expected verified checksum")
	}
	got, _ := os.ReadFile(res.Path)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}

	// 错误的 sha 必须拒绝安装，且不留下可执行文件。
	m2 := New(t.TempDir())
	if _, err := m2.InstallFromURL(context.Background(), srv.URL+"/mihomo-linux-amd64-v1.gz", "deadbeef", ""); err == nil {
		t.Fatalf("expected checksum failure")
	}
	if _, err := os.Stat(filepath.Join(m2.Dir(), "mihomo")); !os.IsNotExist(err) {
		t.Fatalf("checksum failure must not leave binary behind")
	}
	// 已有可用二进制时，升级包校验失败不能把它删掉。
	first, err := m2.InstallFromURL(context.Background(), srv.URL+"/mihomo-linux-amd64-v1.gz", sha, "")
	if err != nil {
		t.Fatalf("initial install: %v", err)
	}
	before, _ := os.ReadFile(first.Path)
	if _, err := m2.InstallFromURL(context.Background(), srv.URL+"/mihomo-linux-amd64-v1.gz", "deadbeef", ""); err == nil {
		t.Fatalf("expected checksum failure on upgrade")
	}
	after, err := os.ReadFile(first.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed upgrade must keep previous binary: %v", err)
	}
}

// 审计 B8：远程 URL 安装缺 sha256 必须直接拒绝（供应链投毒防线），
// 不再「先装上再人工比对」。
func TestInstallFromURLRequiresSHA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzBytes(t, []byte("mihomo-binary")))
	}))
	defer srv.Close()
	m := New(t.TempDir())
	if _, err := m.InstallFromURL(context.Background(), srv.URL+"/mihomo-linux-amd64-v1.gz", "  ", ""); err == nil {
		t.Fatalf("URL 安装缺 sha256 应被拒绝")
	}
	if _, err := os.Stat(filepath.Join(m.Dir(), "mihomo")); !os.IsNotExist(err) {
		t.Fatalf("拒绝后不应留下二进制")
	}
}

// 服务端忽略 Range 时（返回 200）必须从头写，不能把两段数据拼坏。
func TestDownloadResumableIgnoresRange(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 4096)
	body := gzBytes(t, payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusOK) // 忽略 Range，整包返回
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "dl")
	if err := os.WriteFile(dst, []byte("PARTIAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := downloadResumable(context.Background(), srv.Client(), srv.URL, dst)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("resume with ignored range corrupted data: %d vs %d", len(got), len(body))
	}
}

func TestApplyMirrorPrefix(t *testing.T) {
	raw := "https://github.com/o/r/releases/download/v1/x.gz"
	if got := applyMirrorPrefix("https://ghproxy.net/", raw); got != "https://ghproxy.net/"+raw {
		t.Fatalf("concat mirror: %q", got)
	}
	if got := applyMirrorPrefix("https://m.example/fetch?url={url}", raw); got != "https://m.example/fetch?url="+raw {
		t.Fatalf("placeholder mirror: %q", got)
	}
	if got := applyMirrorPrefix("", raw); got != "" {
		t.Fatalf("empty prefix must yield empty: %q", got)
	}
}

func TestParseMirrors(t *testing.T) {
	got := ParseMirrors("https://a/, https://b/\nhttps://c/  ")
	if len(got) != 3 || got[0] != "https://a/" || got[2] != "https://c/" {
		t.Fatalf("parse mirrors: %v", got)
	}
	if len(ParseMirrors("")) != 0 {
		t.Fatalf("empty input must yield none")
	}
}
