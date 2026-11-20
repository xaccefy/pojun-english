package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyEnvIncludesExplicitProxy(t *testing.T) {
	env := proxyEnv("http://127.0.0.1:18080", "/tmp/ca.pem")
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"HTTP_PROXY=http://127.0.0.1:18080",
		"ALL_PROXY=http://127.0.0.1:18080",
		"EGRESS_PROXY=http://127.0.0.1:18080",
		"EGRESS_PROXY_CA=/tmp/ca.pem",
		"REQUESTS_CA_BUNDLE=/tmp/ca.pem",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("proxyEnv 缺少 %q\n%s", want, joined)
		}
	}
}

func TestMergeProxyEnvOverridesParent(t *testing.T) {
	base := []string{"PATH=/bin", "HTTP_PROXY=http://old:1", "https_proxy=http://old:1", "NO_PROXY=*"}
	merged := mergeProxyEnv(base, "http://127.0.0.1:18080", "/tmp/ca.pem")
	joined := strings.Join(merged, "\n")
	if strings.Contains(joined, "http://old:1") {
		t.Fatalf("父进程旧代理变量未被剔除：\n%s", joined)
	}
	if !strings.Contains(joined, "HTTP_PROXY=http://127.0.0.1:18080") || !strings.Contains(joined, "EGRESS_PROXY=http://127.0.0.1:18080") {
		t.Fatalf("平台出口未注入：\n%s", joined)
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "NO_PROXY=*") {
		t.Fatalf("无关环境变量被误删：\n%s", joined)
	}
	// 未配置代理时保持原环境不变
	if got := mergeProxyEnv(base, "", ""); strings.Join(got, "\n") != strings.Join(base, "\n") {
		t.Fatalf("空代理不应改写父环境")
	}
}

// 原生 http_request 必须经 ToolSet 的 egressProxy，而不是服务进程的环境变量。
func TestHTTPRequestUsesEgressProxy(t *testing.T) {
	var proxied int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied++
		if r.URL.Host != "target.invalid" {
			t.Errorf("代理收到非预期目标：%s", r.URL.String())
		}
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()

	ts := &ToolSet{}
	ts.SetEgressProxy(proxy.URL, "")
	res, err := ts.httpRequest().Call(context.Background(),
		json.RawMessage(`{"url":"http://target.invalid/check","timeout":5}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("http_request 失败：%s", res.Flatten())
	}
	if proxied != 1 {
		t.Fatalf("请求未经过 egressProxy，代理命中 %d 次", proxied)
	}
	if !strings.Contains(res.Flatten(), "via-proxy") {
		t.Fatalf("响应不是代理返回的内容：%s", res.Flatten())
	}
}

// 后台作业必须继承任务出口代理（issue：job_start 只取 os.Environ）。
func TestJobStartInheritsEgressProxy(t *testing.T) {
	taskDir := filepath.Join(t.TempDir(), "tasks", "1")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := &ToolSet{runDir: taskDir, ownerNode: 1}
	ts.SetEgressProxy("http://127.0.0.1:18080", "")
	if _, err := ts.jobStart().Call(context.Background(), json.RawMessage(
		`{"name":"proxyenv","command":"echo \"$HTTP_PROXY|$EGRESS_PROXY\""}`), nil); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(taskDir, "shared", "jobs", "proxyenv.log")
	rcPath := filepath.Join(taskDir, "shared", "jobs", "proxyenv.rc")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(rcPath); err == nil && strings.TrimSpace(string(b)) != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(b)
	if !strings.Contains(log, "http://127.0.0.1:18080|http://127.0.0.1:18080") {
		t.Fatalf("作业未继承出口代理，日志：\n%s", log)
	}
	// 清理可能残留的进程
	if m, ok := readJobMeta(filepath.Join(taskDir, "shared", "jobs"), "proxyenv"); ok {
		_ = jobKillGroup(m.PID)
		jobWaitGone(m.PID, 2*time.Second)
	}
}
