package server

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestParseSubscriptionText(t *testing.T) {
	plain := "http://1.2.3.4:8080\nsocks5://u:p@5.6.7.8:1080\nvmess://eyJhZGQiOiIxLjIuMy40In0=\nss://YWVzOnB3ZA==\n1.2.3.4:3128\n"
	res := parseSubscriptionText(plain)
	if len(res.Supported) != 3 {
		t.Fatalf("supported=%d，期望 3: %v", len(res.Supported), res.Supported)
	}
	if res.Unsupported != 2 {
		t.Fatalf("unsupported=%d，期望 2", res.Unsupported)
	}
	// base64 订阅
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	res2 := parseSubscriptionText(b64)
	if len(res2.Supported) != 3 {
		t.Fatalf("base64 订阅解析失败: %v", res2)
	}
	// 私网订阅地址应被拒绝
	if !privateHost("127.0.0.1") || !privateHost("10.0.0.1") {
		t.Fatal("私网地址判定失败")
	}
	if privateHost("8.8.8.8") {
		t.Fatal("公网地址被误判为私网")
	}
}

func TestParseClashSubscription(t *testing.T) {
	body := `mixed-port: 7890
allow-lan: true
external-controller: 127.0.0.1:9090
proxies:
  - name: http-1
    type: http
    server: 1.2.3.4
    port: 8080
    username: user
    password: pass
  - name: socks-1
    type: socks5
    server: 5.6.7.8
    port: 1080
  - name: ss-1
    type: ss
    server: 9.9.9.9
    port: 443
    cipher: aes-256-gcm
    password: secret
proxy-groups:
  - name: proxy
    type: select
    proxies: [http-1, socks-1, ss-1]
rules:
  - MATCH,proxy
`
	res := parseSubscriptionText(body)
	if res.Format != "clash" {
		t.Fatalf("format=%q，期望 clash", res.Format)
	}
	if res.Proxies != 3 {
		t.Fatalf("proxies=%d，期望 3", res.Proxies)
	}
	if len(res.Supported) != 2 || res.DirectNodes != 2 {
		t.Fatalf("直接可用节点=%v（direct=%d），期望 2", res.Supported, res.DirectNodes)
	}
	if res.Unsupported != 1 {
		t.Fatalf("unsupported=%d，期望 1", res.Unsupported)
	}
	if len(res.LocalPorts) != 1 || res.LocalPorts[0] != 7890 {
		t.Fatalf("local_ports=%v，期望 [7890]", res.LocalPorts)
	}
	if res.ClashYAML == "" {
		t.Fatal("ClashYAML 为空，前端无法启动 mihomo")
	}
	if !containsString(res.Supported, "http://user:pass@1.2.3.4:8080") {
		t.Fatalf("HTTP 节点未正确生成: %v", res.Supported)
	}
	if !containsString(res.Supported, "socks5://5.6.7.8:1080") {
		t.Fatalf("SOCKS5 节点未正确生成: %v", res.Supported)
	}

	// base64 包裹的 Clash YAML 也要能识别（部分订阅读接口会这样返回）。
	b64 := base64.StdEncoding.EncodeToString([]byte(body))
	res2 := parseSubscriptionText(b64)
	if res2.Format != "clash" || len(res2.Supported) != 2 {
		t.Fatalf("base64 Clash 解析失败: format=%q supported=%v", res2.Format, res2.Supported)
	}
}

// 全 vmess 的 Clash 订阅：supported 必须是 []，不能是 null；direct_nodes 必须存在且为 0。
// 2026-11-13 实测崩溃：前端 direct_nodes ?? supported.length 在 null.length 上抛错整页崩。
func TestParseClashAllUnsupportedJSONContract(t *testing.T) {
	body := `mixed-port: 7890
proxies:
  - name: vmess-1
    type: vmess
    server: 9.9.9.9
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
  - name: trojan-1
    type: trojan
    server: 8.8.8.8
    port: 443
    password: secret
`
	res := parseSubscriptionText(body)
	if res.Supported == nil {
		t.Fatal("Supported 不能是 nil（JSON 会变成 null）")
	}
	if res.DirectNodes != 0 {
		t.Fatalf("direct_nodes=%d，期望 0", res.DirectNodes)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, `"supported":[]`) {
		t.Fatalf("JSON 里 supported 必须是空数组：%s", js)
	}
	if !strings.Contains(js, `"direct_nodes":0`) {
		t.Fatalf("direct_nodes 0 不能被 omitempty 省略：%s", js)
	}
}

// 机场常见的 URL-safe base64（含 -/_）也要能解开。
func TestParseSubscriptionURLSafeBase64(t *testing.T) {
	plain := "http://1.2.3.4:8080\nsocks5://5.6.7.8:1080\n"
	b64 := base64.RawURLEncoding.EncodeToString([]byte(plain))
	res := parseSubscriptionText(b64)
	if len(res.Supported) != 2 {
		t.Fatalf("URL-safe base64 解析失败: %+v", res)
	}
}

func TestIsBlockedIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.1.1", "0.0.0.0", "::1", "fc00::1", "fe80::1"} {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("%s 应被判定为屏蔽地址", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		if isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("%s 不应被判定为屏蔽地址", s)
		}
	}
}

// 订阅过期时机场常返回登录/错误网页：必须给出可读提示，而不是只显示 0 节点。
func TestParseSubscriptionHTMLNote(t *testing.T) {
	res := parseSubscriptionText("<!DOCTYPE html><html><body>请先登录</body></html>")
	if res.Note == "" || !strings.Contains(res.Note, "web page") {
		t.Fatalf("HTML 响应应提示不是节点配置：%q", res.Note)
	}
}

func TestParseSubscriptionEmptyNote(t *testing.T) {
	res := parseSubscriptionText("   \n  ")
	if res.Note == "" || !strings.Contains(res.Note, "empty content") {
		t.Fatalf("空响应应给出提示：%q", res.Note)
	}
}

// 订阅里混入的「剩余流量/到期时间/官网」不是节点：单独计数 ignored，
// 不能算 invalid（旧版会让用户以为节点坏了）。
func TestParseSubscriptionIgnoresInfoLines(t *testing.T) {
	body := "# comment\n" +
		"剩余流量：100 GB\n" +
		"到期时间：2026-12-01\n" +
		"官网地址：https://example-airport.test\n" +
		"距离下次重置剩余：12 天\n" +
		"http://1.2.3.4:8080\n" +
		"socks5://5.6.7.8:1080\n"
	res := parseSubscriptionText(body)
	if res.Format != "uri" {
		t.Fatalf("format=%q", res.Format)
	}
	if res.Ignored != 4 {
		t.Fatalf("ignored=%d want 4 (note=%q)", res.Ignored, res.Note)
	}
	if res.Invalid != 0 {
		t.Fatalf("info lines must not count as invalid: %d", res.Invalid)
	}
	if res.DirectNodes != 2 {
		t.Fatalf("direct nodes=%d want 2", res.DirectNodes)
	}
}

// Clash 里以「剩余流量/到期」开头的伪节点要过滤，而不是计入「需内核」。
func TestParseClashIgnoresInfoNodes(t *testing.T) {
	body := `
mixed-port: 7890
proxy-groups:
  - name: 自动选择
    type: url-test
    proxies: ["香港 01"]
  - name: 香港
    type: select
    proxies: ["香港 01"]
proxies:
  - name: "剩余流量：100GB"
    type: ss
    server: 1.1.1.1
    port: 443
    cipher: aes-128-gcm
    password: x
  - name: "到期时间：2026-12-01"
    type: ss
    server: 2.2.2.3
    port: 443
    cipher: aes-128-gcm
    password: x
  - name: "🌐︎ 官网: cloud.example.tech"
    type: ss
    server: 2.2.2.2
    port: 443
    cipher: aes-128-gcm
    password: x
  - name: "香港 01"
    type: vmess
    server: 3.3.3.3
    port: 443
    uuid: u
    alterId: 0
    cipher: auto
  - name: "香港 02"
    type: http
    server: 4.4.4.4
    port: 8080
`
	res, ok := parseClashSubscription(body)
	if !ok {
		t.Fatal("not parsed as clash")
	}
	if res.Ignored != 3 {
		t.Fatalf("ignored=%d want 3（含 emoji 前缀的官网伪节点）(note=%q)", res.Ignored, res.Note)
	}
	if res.Unsupported != 1 {
		t.Fatalf("unsupported=%d want 1 (info nodes must not count)", res.Unsupported)
	}
	if res.DirectNodes != 1 {
		t.Fatalf("direct=%d want 1", res.DirectNodes)
	}
	if len(res.GroupNames) != 2 || res.GroupNames[0] != "自动选择" || res.GroupNames[1] != "香港" {
		t.Fatalf("group_names=%v want [自动选择 香港]", res.GroupNames)
	}
	if len(res.Nodes) != 2 || res.Nodes[0].Name != "香港 01" || res.Nodes[1].Name != "香港 02" {
		t.Fatalf("nodes=%v（伪节点不应出现）", res.Nodes)
	}
	if len(res.Groups) != 2 || res.Groups[0].Type != "url-test" || len(res.Groups[0].Members) != 1 || res.Groups[0].Members[0] != "香港 01" {
		t.Fatalf("groups=%v", res.Groups)
	}
}
