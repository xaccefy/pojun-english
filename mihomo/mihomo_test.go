package mihomo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestWriteConfigRewritesListeners(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	src := `mixed-port: 7890
port: 7891
socks-port: 7892
allow-lan: true
external-controller: 127.0.0.1:9090
proxies:
  - name: n1
    type: http
    server: 1.2.3.4
    port: 8080
proxy-groups:
  - name: proxy
    type: select
    proxies: [n1]
rules:
  - MATCH,proxy
`
	path, err := m.writeConfig(src, 17890, StartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg["mixed-port"]; got != 17890 {
		t.Fatalf("mixed-port=%v，期望 17890", got)
	}
	if got := cfg["allow-lan"]; got != false {
		t.Fatalf("allow-lan=%v，期望 false", got)
	}
	if _, ok := cfg["port"]; ok {
		t.Fatal("port 未被删除，可能与 mixed-port 冲突")
	}
	if _, ok := cfg["socks-port"]; ok {
		t.Fatal("socks-port 未被删除，可能与 mixed-port 冲突")
	}
	if _, ok := cfg["proxies"]; !ok {
		t.Fatal("proxies 被误删")
	}
	if got := cfg["external-controller"]; got != "" {
		t.Fatalf("external-controller=%v，期望空", got)
	}
}

func TestWriteConfigRejectsNonClash(t *testing.T) {
	m := New(t.TempDir())
	if _, err := m.writeConfig("foo: bar\n", 17890, StartOptions{}); err == nil {
		t.Fatal("非 Clash YAML 应被拒绝")
	}
}

func TestFindBinaryConfigured(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mihomo")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if err := os.WriteFile(bin, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(filepath.Join(dir, "data"))
	got, err := m.FindBinary(bin)
	if err != nil {
		t.Fatal(err)
	}
	if got != bin {
		t.Fatalf("FindBinary=%q，期望 %q", got, bin)
	}
}

func TestStatusDetectsInstalledBinary(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	name := "mihomo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.MkdirAll(m.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Dir(), name), []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if !st.Installed || st.Binary == "" {
		t.Fatalf("重启后应识别已安装的二进制: %+v", st)
	}
}

func TestPickAsset(t *testing.T) {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	plain := "mihomo-" + osName + "-" + arch + "-v1.0.0"
	ext := ".gz"
	if osName == "windows" {
		ext = ".zip"
	}
	assets := []releaseAsset{
		{Name: "mihomo-" + osName + "-" + arch + "-compatible-v1.0.0" + ext, URL: "compatible"},
		{Name: plain + ext, URL: "plain"},
		{Name: "mihomo-other-arch-v1.0.0" + ext, URL: "other"},
	}
	got := pickAsset(assets)
	if got.URL != "plain" {
		t.Fatalf("pickAsset=%q，期望 plain", got.URL)
	}
	// 只有 compatible 时回退到 compatible。
	got = pickAsset(assets[:1])
	if got.URL != "compatible" {
		t.Fatalf("compatible 回退失败: %q", got.URL)
	}
	if !strings.Contains(got.Name, "compatible") {
		t.Fatalf("回退资产名异常: %s", got.Name)
	}
}

// 订阅里的 GEOIP/GEOSITE/rule-providers 会让 mihomo 启动时下载 MMDB/GeoSite；
// 受限网络里表现为「20s 内未监听 / Can't find MMDB, start download」。
// 平台只需要一个 mixed-port 上游，规则应收敛为 MATCH 首选出口并关掉 geo 更新。
func TestWriteConfigStripsGeoRules(t *testing.T) {
	m := New(t.TempDir())
	src := `
mixed-port: 7890
tun:
  enable: true
rule-providers:
  cn:
    type: http
    url: https://example.com/cn.yaml
sub-rules:
  cn: [cn]
proxies:
  - name: n1
    type: http
    server: 1.2.3.4
    port: 8080
proxy-groups:
  - name: proxy
    type: select
    proxies: [n1]
rules:
  - GEOIP,CN,DIRECT
  - RULE-SET,cn,DIRECT
  - MATCH,proxy
`
	path, err := m.writeConfig(src, 17890, StartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"rule-providers", "sub-rules", "tun"} {
		if _, ok := cfg[k]; ok {
			t.Fatalf("%s 应被删除（会阻塞启动）", k)
		}
	}
	if v, ok := cfg["geo-auto-update"]; !ok || v != false {
		t.Fatalf("geo-auto-update=%v，期望 false", cfg["geo-auto-update"])
	}
	rules, _ := cfg["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,proxy" {
		t.Fatalf("rules=%v，期望 [MATCH,proxy]", cfg["rules"])
	}
}

// 用户选择的出口组/节点：存在就 MATCH 到它；订阅换版后名字变了则静默回落默认（第一个 proxy-group）。
func TestWriteConfigPreferredOutbound(t *testing.T) {
	m := New(t.TempDir())
	src := `
mixed-port: 7890
proxies:
  - name: n1
    type: http
    server: 1.2.3.4
    port: 8080
  - name: n2
    type: http
    server: 5.6.7.8
    port: 8080
proxy-groups:
  - name: auto
    type: url-test
    proxies: [n1, n2]
  - name: 香港
    type: select
    proxies: [n1]
`
	cases := []struct{ preferred, want string }{
		{"香港", "MATCH,香港"},
		{"n2", "MATCH,n2"},      // 直接点名节点也可以
		{"不存在的组", "MATCH,auto"}, // 名字失配回落默认组
		{"", "MATCH,auto"},
	}
	for _, c := range cases {
		path, err := m.writeConfig(src, 17891, StartOptions{Preferred: c.preferred})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		var cfg map[string]any
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		rules, _ := cfg["rules"].([]any)
		if len(rules) != 1 || rules[0] != c.want {
			t.Fatalf("preferred=%q rules=%v，期望 [%s]", c.preferred, cfg["rules"], c.want)
		}
	}
}

// Clash 节点管理模式：轮询/测速/故障转移在所选节点上建 POJUN-AUTO 组，
// MATCH 到该组；指定节点模式必须命中订阅里的名字。
func TestWriteConfigOutboundModes(t *testing.T) {
	m := New(t.TempDir())
	src := `
mixed-port: 7890
proxies:
  - name: n1
    type: http
    server: 1.2.3.4
    port: 8080
  - name: n2
    type: http
    server: 5.6.7.8
    port: 8080
proxy-groups:
  - name: auto
    type: url-test
    proxies: [n1, n2]
`
	read := func(t *testing.T, opts StartOptions) map[string]any {
		t.Helper()
		path, err := m.writeConfig(src, 17892, opts)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		var cfg map[string]any
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	findGroup := func(cfg map[string]any, name string) map[string]any {
		groups, _ := cfg["proxy-groups"].([]any)
		for _, g := range groups {
			if m, ok := g.(map[string]any); ok {
				if n, _ := m["name"].(string); n == name {
					return m
				}
			}
		}
		return nil
	}

	cfg := read(t, StartOptions{Mode: "load-balance", Nodes: []string{"n1", "n2", "不存在"}})
	rules, _ := cfg["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,"+autoGroupName {
		t.Fatalf("rules=%v", cfg["rules"])
	}
	g := findGroup(cfg, autoGroupName)
	if g == nil || g["type"] != "load-balance" || g["strategy"] != "round-robin" {
		t.Fatalf("load-balance 组异常: %v", g)
	}
	if proxies, _ := g["proxies"].([]any); len(proxies) != 2 || proxies[0] != "n1" || proxies[1] != "n2" {
		t.Fatalf("节点过滤异常: %v", g["proxies"])
	}
	if findGroup(cfg, "auto") == nil {
		t.Fatal("订阅自带组被误删")
	}

	cfg = read(t, StartOptions{Mode: "url-test", Nodes: []string{"n2"}})
	if g := findGroup(cfg, autoGroupName); g == nil || g["type"] != "url-test" || g["url"] == "" {
		t.Fatalf("url-test 组异常: %v", g)
	}

	cfg = read(t, StartOptions{Mode: "fallback", Nodes: []string{"n1"}})
	if g := findGroup(cfg, autoGroupName); g == nil || g["type"] != "fallback" {
		t.Fatalf("fallback 组异常: %v", g)
	}

	cfg = read(t, StartOptions{Mode: "node", Preferred: "n1"})
	rules, _ = cfg["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,n1" {
		t.Fatalf("node 模式 rules=%v", cfg["rules"])
	}

	if _, err := m.writeConfig(src, 17892, StartOptions{Mode: "load-balance"}); err == nil {
		t.Fatal("空节点列表应报错")
	}
	if _, err := m.writeConfig(src, 17892, StartOptions{Mode: "node", Preferred: "ghost"}); err == nil {
		t.Fatal("不存在的节点应报错")
	}
	if _, err := m.writeConfig(src, 17892, StartOptions{Mode: "bogus"}); err == nil {
		t.Fatal("未知模式应报错")
	}
}

// Status 里的「当前出口」从配置文件反推：MATCH 到自建组时带出模式与节点。
func TestReadActivePlan(t *testing.T) {
	m := New(t.TempDir())
	src := `
mixed-port: 7890
proxies:
  - name: n1
    type: http
    server: 1.2.3.4
    port: 8080
  - name: n2
    type: http
    server: 5.6.7.8
    port: 8080
`
	path, err := m.writeConfig(src, 17893, StartOptions{Mode: "load-balance", Nodes: []string{"n1", "n2"}})
	if err != nil {
		t.Fatal(err)
	}
	out, mode, nodes := readActivePlan(path)
	if out != autoGroupName || mode != "load-balance" || len(nodes) != 2 {
		t.Fatalf("plan=(%q,%q,%v)", out, mode, nodes)
	}

	path, err = m.writeConfig(src, 17893, StartOptions{Mode: "node", Preferred: "n2"})
	if err != nil {
		t.Fatal(err)
	}
	out, mode, nodes = readActivePlan(path)
	if out != "n2" || mode != "node" || len(nodes) != 1 || nodes[0] != "n2" {
		t.Fatalf("node plan=(%q,%q,%v)", out, mode, nodes)
	}
}

// external-controller：配置里必须只绑回环并带 secret（节点测速依赖它）。
func TestWriteConfigController(t *testing.T) {
	m := New(t.TempDir())
	src := `
mixed-port: 7890
proxies:
  - name: n1
    type: http
    server: 1.2.3.4
    port: 8080
`
	path, err := m.writeConfig(src, 17894, StartOptions{ControllerAddr: "127.0.0.1:19090", ControllerSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["external-controller"] != "127.0.0.1:19090" || cfg["secret"] != "s3cret" {
		t.Fatalf("controller=%v secret=%v", cfg["external-controller"], cfg["secret"])
	}
}

func TestDelayOneAndProxyNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sec" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{
				"node-a":{"type":"Vmess"},
				"HK 01":{"type":"Shadowsocks"},
				"🌐︎ 官网: x":{"type":"Shadowsocks"},
				"POJUN-AUTO":{"type":"LoadBalance"},
				"DIRECT":{"type":"Direct"}}}`))
		case strings.HasPrefix(r.URL.Path, "/proxies/"):
			_, _ = w.Write([]byte(`{"delay":123}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	client := &http.Client{}
	res := delayOne(context.Background(), client, addr, "sec", "HK 01", "https://example.com", time.Second)
	if res.Error != "" || res.DelayMS != 123 {
		t.Fatalf("delay result=%+v", res)
	}
	m := New(t.TempDir())
	names, err := m.proxyNames(addr, "sec")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "官网") || strings.Contains(joined, "POJUN-AUTO") || strings.Contains(joined, "DIRECT") {
		t.Fatalf("过滤异常: %v", names)
	}
	if len(names) != 2 {
		t.Fatalf("names=%v want 2", names)
	}
}

// unknownNames 判定「订阅换了但内核还是旧配置」：全部不认识才算不一致。
func TestUnknownNames(t *testing.T) {
	running := []string{"a", "b"}
	if got := unknownNames([]string{"a", "b"}, running); got != 0 {
		t.Fatalf("unknown=%d want 0", got)
	}
	if got := unknownNames([]string{"x", "a"}, running); got != 1 {
		t.Fatalf("unknown=%d want 1", got)
	}
	if got := unknownNames([]string{"x", "y"}, running); got != 2 {
		t.Fatalf("unknown=%d want 2", got)
	}
}

// 审计 B4：订阅可注入 listeners 数组（每项自带 listen/port），
// writeConfig 必须整键删除——bind-address/allow-lan 只约束 mixed-port。
func TestWriteConfigStripsListenersArray(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	src := `mixed-port: 7890
allow-lan: false
listeners:
  - name: open
    type: socks
    port: 10808
    listen: 0.0.0.0
proxies:
  - name: n1
    type: http
    server: 1.2.3.4
    port: 8080
rules:
  - MATCH,DIRECT
`
	path, err := m.writeConfig(src, 17891, StartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["listeners"]; ok {
		t.Fatalf("listeners 未被删除：恶意订阅可在非回环地址开监听")
	}
}
