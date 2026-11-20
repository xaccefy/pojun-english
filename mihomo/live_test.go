package mihomo

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveInstallAndStart 是手动 gate 的端到端测试：
// 下载 mihomo → 用本机 Clash 作为上游启动 → 经 mixed-port 出网。
// 默认跳过；需要时：
//
//	POJUN_MIHOMO_LIVE=1 POJUN_MIHOMO_PROXY=http://127.0.0.1:7897 go test ./mihomo -run TestLiveInstallAndStart -v
func TestLiveInstallAndStart(t *testing.T) {
	if os.Getenv("POJUN_MIHOMO_LIVE") != "1" {
		t.Skip("设置 POJUN_MIHOMO_LIVE=1 才跑真实下载/启动")
	}
	proxy := os.Getenv("POJUN_MIHOMO_PROXY")
	if proxy == "" {
		proxy = "http://127.0.0.1:7897"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	m := New(t.TempDir())
	defer func() { _ = m.Stop() }()
	res, err := m.Install(ctx, proxy, DefaultMirrors)
	if err != nil {
		t.Fatalf("安装 mihomo 失败: %v", err)
	}
	if res.Path == "" || res.Version == "" {
		t.Fatalf("安装结果不完整: %+v", res)
	}
	t.Logf("installed %s (%s)", res.Version, res.Path)

	// 用本机 Clash 7897 作为唯一上游，验证 mixed-port 能真正出网。
	yaml := `mixed-port: 7890
allow-lan: true
proxies:
  - name: local-clash
    type: http
    server: 127.0.0.1
    port: 7897
proxy-groups:
  - name: proxy
    type: select
    proxies: [local-clash]
rules:
  - MATCH,proxy
`
	st, err := m.Start(ctx, yaml, res.Path, 0, StartOptions{})
	if err != nil {
		t.Fatalf("启动 mihomo 失败: %v", err)
	}
	if !st.Running || st.Port <= 0 {
		t.Fatalf("状态异常: %+v", st)
	}
	if st.LastError != "" {
		t.Fatalf("mixed-port 出口探测失败: %s", st.LastError)
	}
	t.Logf("mihomo running pid=%d port=%d version=%s", st.PID, st.Port, st.Version)
}
