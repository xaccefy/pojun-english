package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 审计 B3：绕过 decode() 直连 NewDecoder 的 handler 也要有请求体上限。
func TestLimitRequestBody(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	h := limitRequestBody(okHandler)

	// 普通小请求：通过
	small := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"q":"hi"}`))
	small.Header.Set("Content-Length", "9")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, small)
	if w.Code != http.StatusOK {
		t.Fatalf("小请求被误拒: %d", w.Code)
	}

	// 超过 32MB（ContentLength 可判定）：直接 413，不进入 handler
	big := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(strings.Repeat("a", maxAPIBody+1)))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, big)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求: status=%d，期望 413", w.Code)
	}

	// 豁免路径：workspace 上传 512MB 不受限
	exempt := httptest.NewRequest(http.MethodPost, "/api/workspace/upload",
		strings.NewReader(strings.Repeat("a", maxAPIBody+1)))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, exempt)
	if w.Code != http.StatusOK {
		t.Fatalf("豁免路径被误拒: %d", w.Code)
	}

	// MaxBytesReader 兜底：ContentLength 未知（chunked）的超大 body 也会被截断
	chunked := httptest.NewRequest(http.MethodPost, "/api/chat", &chunkedReader{total: maxAPIBody + 1024})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, chunked)
	if w.Code != http.StatusOK {
		t.Fatalf("chunked 请求应进 handler（由 handler 读失败兜底）: %d", w.Code)
	}
}

// chunkedReader 产出 total 字节的 'a'，ContentLength -1（chunked）。
type chunkedReader struct {
	total  int64
	sent   int64
	buf    []byte
	begin  bool
	closed bool
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}
	if !c.begin {
		c.begin = true
	}
	if c.sent >= c.total {
		c.closed = true
		return 0, io.EOF
	}
	n := len(p)
	if remain := c.total - c.sent; int64(n) > remain {
		n = int(remain)
	}
	for i := 0; i < n; i++ {
		p[i] = 'a'
	}
	c.sent += int64(n)
	return n, nil
}
