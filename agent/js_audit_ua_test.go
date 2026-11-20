package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	jsAuditUAHeadRE = regexp.MustCompile(`(?s)UA = \{(.*?)\}`)
	jsAuditUAPairRE = regexp.MustCompile(`"([A-Za-z-]+)":\s*"([^"]*)"`)
	// tools_http.go 里 http_request 的默认 UA / Accept 赋值形态。
	platformUARE     = regexp.MustCompile(`Header\.Set\("User-Agent",\s*"([^"]+)"\)`)
	platformAcceptRE = regexp.MustCompile(`Header\.Set\("Accept",\s*"([^"]+)"\)`)
	// 真实 Chrome 的 UA 产品令牌序列：平台标记 + AppleWebKit + (KHTML, like Gecko) + 四段式版本。
	chromeUARe = regexp.MustCompile(`^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/\d+\.0\.0\.0 Safari/537\.36$`)
)

func jsAuditHeaders(t *testing.T) map[string]string {
	t.Helper()
	m := jsAuditUAHeadRE.FindStringSubmatch(jsAuditScript)
	if m == nil {
		t.Fatal("内嵌脚本里找不到 UA = {...} 头字典")
	}
	h := map[string]string{}
	for _, kv := range jsAuditUAPairRE.FindAllStringSubmatch(m[1], -1) {
		h[kv[1]] = kv[2]
	}
	return h
}

// platformDefaultUA 从 tools_http.go 源码里取平台默认 UA，避免在测试里再存一份副本，
// 从而让「脚本 UA 偏离平台默认」在两个方向上都会被这条断言抓到。
func platformDefaultUA(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("tools_http.go")
	if err != nil {
		t.Fatalf("读 tools_http.go: %v", err)
	}
	m := platformUARE.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("tools_http.go 里找不到 http_request 的默认 UA 字面量")
	}
	return m[1]
}

// platformAccept 同样回读 tools_http.go，避免把 "*/*" 再抄一份、两边漂移抓不到。
func platformAccept(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("tools_http.go")
	if err != nil {
		t.Fatalf("读 tools_http.go: %v", err)
	}
	m := platformAcceptRE.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("tools_http.go 里找不到 http_request 的默认 Accept 字面量")
	}
	return m[1]
}

func TestJsAuditScriptHeaders(t *testing.T) {
	got := jsAuditHeaders(t)
	// UA 与 Accept 回读 tools_http.go 交叉断言，不在这里存副本；Accept-Language /
	// Accept-Encoding 是本工具有意补齐的浏览器常规头（http_request 不发 Language、
	// AE 由 Go transport 自动补 gzip），差异已在 tools_jsaudit.go 注释里写明。
	want := map[string]string{
		"User-Agent":      platformDefaultUA(t),
		"Accept":          platformAccept(t),
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate",
	}
	if len(got) != len(want) {
		t.Fatalf("头集合 = %#v，期望恰好 %d 项（多余的头同样是指纹）", got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("头 %s = %q，期望 %q", k, got[k], v)
		}
	}
	if !chromeUARe.MatchString(want["User-Agent"]) {
		t.Fatalf("平台默认 UA 不是合法 Chrome 形态：%q", want["User-Agent"])
	}
	ps, err := os.ReadFile("poc_scaffold.go")
	if err != nil {
		t.Fatalf("读 poc_scaffold.go: %v", err)
	}
	if !strings.Contains(string(ps), want["User-Agent"]) {
		t.Fatalf("poc_scaffold.go 的 UA 与平台默认不一致：期望包含 %q", want["User-Agent"])
	}
	for _, enc := range []string{"br", "zstd"} {
		if strings.Contains(got["Accept-Encoding"], enc) {
			t.Fatalf("Accept-Encoding 声明了 stdlib 无法解码的 %q：%q", enc, got["Accept-Encoding"])
		}
	}
	if !strings.Contains(jsAuditScript, "zlib.decompressobj") ||
		!strings.Contains(jsAuditScript, `_decode(raw, r.headers.get("Content-Encoding"), cap)`) {
		t.Fatal("Accept-Encoding 声明了 gzip/deflate，但 fetch 未解压")
	}
}

func pythonBinary(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("未找到 python3/python，跳过内嵌脚本的 python 侧校验")
	return ""
}

func TestJsAuditScriptCompiles(t *testing.T) {
	py := pythonBinary(t)
	p := filepath.Join(t.TempDir(), "js_audit.py")
	if err := os.WriteFile(p, []byte(jsAuditScript), 0o600); err != nil {
		t.Fatalf("写脚本: %v", err)
	}
	if out, err := exec.Command(py, "-m", "py_compile", p).CombinedOutput(); err != nil {
		t.Fatalf("py_compile 失败: %v\n%s", err, out)
	}
}

func noProxyEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		k := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		switch k {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
}

func TestJsAuditDecodesCompressedBodies(t *testing.T) {
	py := pythonBinary(t)
	routes := map[string]string{
		"/":           `<html><script src="/app.js"></script></html>`,
		"/app.js":     "var k='AKIAABCDEFGHIJKLMNOP';\n//# sourceMappingURL=app.js.map\n",
		"/app.js.map": `{"version":3,"sources":["src/main.js"],"sourcesContent":["const k=1;"],"mappings":""}`,
	}
	// Accept-Encoding 不在此断言：identity 对照组会故意把它改成 identity，
	// 编码协商是否生效由 gzip/identity 两组结果一致性来验证。
	wantHeaders := map[string]string{
		"User-Agent":      platformDefaultUA(t),
		"Accept":          platformAccept(t),
		"Accept-Language": "en-US,en;q=0.9",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 链路上真实发出的头才算数：只对脚本源码做正则断言时，把 headers=UA 改成
		// headers={}（或在 Request 后覆盖 UA）仍会全绿，原始缺陷会静默复发。
		for h, want := range wantHeaders {
			if got := r.Header.Get(h); got != want {
				t.Errorf("链路头 %s = %q，期望 %q", h, got, want)
			}
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write([]byte(body))
			_ = gz.Close()
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	run := func(script string) map[string]any {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, "js_audit.py")
		if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
			t.Fatalf("写脚本: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, py, p, "--out", filepath.Join(dir, "out"), srv.URL+"/")
		cmd.Env = noProxyEnv()
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("脚本执行失败: %v\n%s", err, raw)
		}
		var summary map[string]any
		for _, line := range strings.Split(string(raw), "\n") {
			var ev map[string]any
			if json.Unmarshal([]byte(line), &ev) != nil {
				continue
			}
			if ev["type"] == "summary" {
				summary = ev
			}
		}
		if summary == nil {
			t.Fatalf("没有 summary 事件:\n%s", raw)
		}
		return summary
	}

	identity := strings.Replace(jsAuditScript,
		`"Accept-Encoding": "gzip, deflate"`, `"Accept-Encoding": "identity"`, 1)
	if identity == jsAuditScript {
		t.Fatal("构造 identity 对照组失败：脚本头字典里没有 Accept-Encoding: gzip, deflate")
	}
	for name, summary := range map[string]map[string]any{
		"gzip":     run(jsAuditScript),
		"identity": run(identity),
	} {
		if got := summary["sourcemaps_found"]; got != float64(1) {
			t.Fatalf("%s: sourcemaps_found = %v，期望 1（解压路径与原文路径结果必须一致）", name, got)
		}
		if n, _ := summary["secret_signals"].(float64); n < 1 {
			t.Fatalf("%s: secret_signals = %v，期望 >=1（解压后必须扫得到明文）", name, summary["secret_signals"])
		}
	}
}

// TestJsAuditDecodeVariants 直接驱动内嵌脚本的 _decode：端到端只跑了 gzip，这里补齐
// zlib 头 deflate / 裸 deflate / x-gzip / identity，以及多值编码与损坏数据的告警降级。
func TestJsAuditDecodeVariants(t *testing.T) {
	py := pythonBinary(t)
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "js_audit.py")
	if err := os.WriteFile(scriptPath, []byte(jsAuditScript), 0o600); err != nil {
		t.Fatalf("写脚本: %v", err)
	}
	harness := `import contextlib, importlib.util, io, json, sys, zlib
spec = importlib.util.spec_from_file_location("js_audit", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
data = b"var k='AKIAABCDEFGHIJKLMNOP';" * 40
def comp(wbits):
    c = zlib.compressobj(9, zlib.DEFLATED, wbits)
    return c.compress(data) + c.flush()
gz = comp(16 + zlib.MAX_WBITS)
gz2 = gz + comp(16 + zlib.MAX_WBITS)
out = {
    "gzip": m._decode(gz, "gzip", len(data)) == data,
    "x_gzip": m._decode(gz, "x-gzip", len(data)) == data,
    "zlib_deflate": m._decode(comp(zlib.MAX_WBITS), "deflate", len(data)) == data,
    "raw_deflate": m._decode(comp(-zlib.MAX_WBITS), "deflate", len(data)) == data,
    "identity": m._decode(data, "identity", len(data)) == data,
    "multi_member": m._decode(gz2, "gzip", 2 * len(data)) == data + data,
}
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    multi = m._decode(gz, "gzip, br", len(data))
    broken = m._decode(b"not-gzip", "gzip", len(data))
out["multi_value_raw"] = multi == gz
out["broken_raw"] = broken == b"not-gzip"
out["warn_events"] = len([w for w in (json.loads(l) for l in buf.getvalue().splitlines() if l.strip())
                          if w.get("type") == "warn"])
print(json.dumps(out))
`
	hp := filepath.Join(dir, "decode_check.py")
	if err := os.WriteFile(hp, []byte(harness), 0o600); err != nil {
		t.Fatalf("写 harness: %v", err)
	}
	raw, err := exec.Command(py, hp, scriptPath).CombinedOutput()
	if err != nil {
		t.Fatalf("python 校验失败: %v\n%s", err, raw)
	}
	var res map[string]any
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			var one map[string]any
			if json.Unmarshal([]byte(line), &one) == nil {
				res = one
			}
		}
	}
	if res == nil {
		t.Fatalf("解析 harness 输出失败:\n%s", raw)
	}
	for _, k := range []string{"gzip", "x_gzip", "zlib_deflate", "raw_deflate", "identity", "multi_member", "multi_value_raw", "broken_raw"} {
		if res[k] != true {
			t.Errorf("%s = %v，期望 true", k, res[k])
		}
	}
	if res["warn_events"] != float64(2) {
		t.Errorf("warn_events = %v，期望 2（多值编码与损坏数据各一次）", res["warn_events"])
	}
}
