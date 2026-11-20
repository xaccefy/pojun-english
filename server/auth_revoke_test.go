package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/golang-jwt/jwt/v5"
)

// 审计 B1：会话吊销机制。改密码（轮 key）之外，管理员应能不改密码就踢掉
// 已签发的 7 天 token；「吊销当前会话」按 jti 精确失效不牵连其他设备。
func newRevokeTestServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{m: &Manager{pg: d}, dataDir: t.TempDir()}
	s.jwtKey.Store(key)
	// 清掉可能残留的吊销状态，保证用例独立
	_ = d.SetSetting(authRevokeAllBeforeKey, "")
	_ = d.SetSetting(authRevokedJtisKey, "")
	t.Cleanup(func() {
		_ = d.SetSetting(authRevokeAllBeforeKey, "")
		_ = d.SetSetting(authRevokedJtisKey, "")
	})
	return s, d
}

func authedRequest(tok, path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	return req
}

func authedRequestWithBody(tok, path string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	return req
}

func requireAuthCode(s *Server, tok string) int {
	ok := false
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ok = true }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authedRequest(tok, "/api/stats"))
	_ = w
	if ok {
		return http.StatusOK
	}
	return w.Code
}

// TestSessionRevokeAll — 无 confirm 拒绝；吊销后旧 token（含无 jti 的历史 token）
// 全部 401；吊销之后新签发的 token 正常（等 1.1s 跨秒，iat 才严格大于哨兵）。
func TestSessionRevokeAll(t *testing.T) {
	s, _ := newRevokeTestServer(t)
	oldTok, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	legacyClaims := jwt.RegisteredClaims{
		Subject:   "POJUN",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	legacyTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims).SignedString(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}

	// 1) 缺 confirm：400
	body, _ := json.Marshal(map[string]any{})
	w := httptest.NewRecorder()
	s.sessionRevokeAll(w, authedRequestWithBody(oldTok, "/api/sessions/revoke-all", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 confirm 应 400，得 %d：%s", w.Code, w.Body.String())
	}

	// 2) 带 confirm：200；旧 token 全部失效（含无 jti 的历史 token）
	body, _ = json.Marshal(map[string]any{"confirm": true})
	w = httptest.NewRecorder()
	s.sessionRevokeAll(w, authedRequestWithBody(oldTok, "/api/sessions/revoke-all", body))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke-all 应 200，得 %d：%s", w.Code, w.Body.String())
	}
	if code := requireAuthCode(s, oldTok); code != http.StatusUnauthorized {
		t.Fatalf("吊销后旧 token 应 401，得 %d", code)
	}
	if code := requireAuthCode(s, legacyTok); code != http.StatusUnauthorized {
		t.Fatalf("吊销后无 jti 历史 token 应 401（哨兵覆盖），得 %d", code)
	}

	// 3) 哨兵是秒级：跨 1 秒后新签发的 token 必须存活
	time.Sleep(1100 * time.Millisecond)
	newTok, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	if code := requireAuthCode(s, newTok); code != http.StatusOK {
		t.Fatalf("吊销后新签发 token 应 200，得 %d", code)
	}
}

// TestSessionRevokeCurrent — 吊销按 jti 精确生效：A 被吊销 401，B 仍 200；
// 无 jti 的历史 token 不能逐个吊销（400 提示走 revoke-all）。
func TestSessionRevokeCurrent(t *testing.T) {
	s, _ := newRevokeTestServer(t)
	tokA, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	legacyClaims := jwt.RegisteredClaims{
		Subject:   "POJUN",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	legacyTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims).SignedString(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}

	// 1) 历史 token 无 jti：400
	w := httptest.NewRecorder()
	s.sessionRevokeCurrent(w, authedRequest(legacyTok, "/api/sessions/revoke-current"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("无 jti 应 400，得 %d：%s", w.Code, w.Body.String())
	}

	// 2) 吊销当前会话：200，A 失效、新签的 B 存活
	time.Sleep(1100 * time.Millisecond) // 与后续新 token 隔开一个秒级 iat
	tokB, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.sessionRevokeCurrent(w, authedRequest(tokA, "/api/sessions/revoke-current"))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke-current 应 200，得 %d：%s", w.Code, w.Body.String())
	}
	if code := requireAuthCode(s, tokA); code != http.StatusUnauthorized {
		t.Fatalf("被吊销会话应 401，得 %d", code)
	}
	if code := requireAuthCode(s, tokB); code != http.StatusOK {
		t.Fatalf("其他会话应不受牵连（200），得 %d", code)
	}
}

// TestSignJWTJtiUnique — 每次签发的 jti 唯一（「吊销当前会话」的前提）。
func TestSignJWTJtiUnique(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	a, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	_, jtiA, ok := parseTokenClaims(a, key)
	if !ok || jtiA == "" {
		t.Fatalf("token 应带非空 jti，ok=%v jti=%q", ok, jtiA)
	}
	_, jtiB, _ := parseTokenClaims(b, key)
	if jtiA == jtiB {
		t.Fatalf("两次签发的 jti 不应相同：%s", jtiA)
	}
}
