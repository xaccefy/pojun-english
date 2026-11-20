package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
)

// 审计 B2：公网部署后、管理员完成 /setup 之前，未认证者可抢占 /api/auth/init
// 接管实例。修复后 init 必须携带服务端生成的 setup token。
func TestAuthInitRequiresSetupToken(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	dataDir := t.TempDir()
	s := &Server{m: &Manager{pg: d}, dataDir: dataDir}
	tokenPath := filepath.Join(dataDir, setupTokenFilename)
	tokenFile := func() string {
		b, err := os.ReadFile(tokenPath)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	initReq := func(password, tokHdr string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"password": password})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/init", bytes.NewReader(body))
		if tokHdr != "" {
			req.Header.Set("X-Setup-Token", tokHdr)
		}
		w := httptest.NewRecorder()
		s.authInit(w, req)
		return w
	}

	const strongPassword = "Str0ng-Passw0rd!"

	// 1) 无 token：生成 token 文件并拒绝（403 提示 token 位置）
	w := initReq(strongPassword, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("无 token init: status=%d body=%s，期望 403", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "setup token") {
		t.Fatalf("提示缺少 token 说明：%s", w.Body.String())
	}
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatalf("token 文件未生成: %v", err)
	}

	// 2) 错误 token：拒绝
	w = initReq(strongPassword, "wrong-token")
	if w.Code != http.StatusForbidden {
		t.Fatalf("错误 token: status=%d，期望 403", w.Code)
	}

	// 3) 正确 token：成功，token 文件删除
	tok := tokenFile()
	w = initReq(strongPassword, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("正确 token init: status=%d body=%s，期望 200", w.Code, w.Body.String())
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("init 成功后 setup token 文件应删除")
	}

	// 4) Password already set: any init 403s with "password already set"
	w = initReq(strongPassword, tok)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "password already set") {
		t.Fatalf("已设置后 init: status=%d body=%s", w.Code, w.Body.String())
	}
}
