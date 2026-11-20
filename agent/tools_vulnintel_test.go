package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/vulnintel"
)

// CWE→methodology-skill linkage (M1 closure): relatedSkillsFor dedupe-returns skill names by hit CWE;
// with no index injected or no hits it returns nil — related_skills must not appear in tool output:
// the linkage is purely additive and can't change the existing shape.
func TestRelatedSkillsFor(t *testing.T) {
	// No index injected: always nil.
	if got := relatedSkillsFor([]string{"CWE-89"}); got != nil {
		t.Fatalf("nil index should return nil, got=%v", got)
	}

	SetCweSkillIndex(map[string][]string{
		"CWE-89":  {"inj-skill"},
		"CWE-862": {"authz-skill"},
		"CWE-639": {"authz-skill"},
	})
	t.Cleanup(func() { SetCweSkillIndex(nil) })

	// Single CWE hit.
	if got := relatedSkillsFor([]string{"CWE-89"}); !reflect.DeepEqual(got, []string{"inj-skill"}) {
		t.Fatalf("CWE-89 → %v", got)
	}
	// Multi-CWE dedupe: two CWEs pointing at the same skill appear once; case-insensitive.
	got := relatedSkillsFor([]string{"CWE-862", "cwe-639"})
	if !reflect.DeepEqual(got, []string{"authz-skill"}) {
		t.Fatalf("CWE-862+cwe-639 → %v, want deduped [authz-skill]", got)
	}
	// No hits → nil.
	if got := relatedSkillsFor([]string{"CWE-999"}); got != nil {
		t.Fatalf("no hits should return nil, got=%v", got)
	}
}

// The linkage field must be 'absent when empty': get_vuln output without related_skills stays
// consistent with existing callers (the field names written in the prompts).
func TestVulnDetailWithSkillsOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(vulnDetailWithSkills{VulnDetail: nil})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["related_skills"]; ok {
		t.Fatal("related_skills must not appear in output when there's no linkage")
	}
}

// TestNucleiScanArgsCarriesEgressProxy 锁住出口接线：egressProxy 必须原样进
// ScanArgs.Proxy。回归（漏接）时这条立刻红，而不是等线上扫描默默直连。
func TestNucleiScanArgsCarriesEgressProxy(t *testing.T) {
	ts := &ToolSet{egressProxy: "http://127.0.0.1:8788"}
	a := ts.nucleiScanArgs("https://t/", "CVE-2021-41773", "critical,high")
	if a.Proxy != "http://127.0.0.1:8788" {
		t.Fatalf("Proxy = %q, want 出口代理原值", a.Proxy)
	}
	if a.TimeoutTotal != 10*time.Minute {
		t.Fatalf("TimeoutTotal = %v, want 10m", a.TimeoutTotal)
	}
	if a.Target != "https://t/" || a.CVEID != "CVE-2021-41773" || a.Severity != "critical,high" {
		t.Fatalf("入参未透传: %+v", a)
	}
	if empty := (&ToolSet{}).nucleiScanArgs("u", "", ""); empty.Proxy != "" {
		t.Fatalf("空代理应为空串, got %q", empty.Proxy)
	}
}

// TestNucleiBashCommand 在无 nuclei、无 PG 的机器上断言整条命令串：
// -proxy 的相邻位置、逐参数单引号、空代理不发射、含逗号报错。
func TestNucleiBashCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	run, err := nucleiBashCommand(dir, vulnintel.ScanArgs{
		Target:       "https://t/api?a=1&b=2",
		TimeoutTotal: 10 * time.Minute,
		Proxy:        "http://127.0.0.1:8788",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 前缀按实际环境计算：Linux/CI 上 PATH 有 GNU timeout 时会前置
	// "'<timeout>' 600 "（CI 是 ubuntu-latest，必然命中这条分支），
	// 写死 'nuclei' 会让门禁确定性变红。
	wantPrefix := "'nuclei'"
	tp, terr := exec.LookPath("timeout")
	if terr == nil && runtime.GOOS != "windows" {
		wantPrefix = quoteShell(tp) + " 600 'nuclei'"
	}
	if !strings.HasPrefix(run, wantPrefix) {
		t.Fatalf("命令应以 %q 开头, got %q", wantPrefix, run)
	}
	if n := strings.Count(run, "'-proxy'"); n != 1 {
		t.Fatalf("-proxy 应恰好出现一次, got %d: %q", n, run)
	}
	if !strings.Contains(run, "'-proxy' 'http://127.0.0.1:8788'") {
		t.Fatalf("缺少 -proxy 与其值相邻两段: %q", run)
	}
	if !strings.Contains(run, "'https://t/api?a=1&b=2'") {
		t.Fatalf("target 应整体单引号包裹: %q", run)
	}

	// timeout 包裹与 -proxy 的组合路径：30m 必须推导成 1800 秒，不能写死 600。
	// Windows 没有 GNU timeout 分支，推导规则由 vulnintel.TestEffectiveTimeout 覆盖。
	if terr == nil && runtime.GOOS != "windows" {
		run30, err := nucleiBashCommand(dir, vulnintel.ScanArgs{Target: "https://t/", TimeoutTotal: 30 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(run30, quoteShell(tp)+" 1800 ") {
			t.Fatalf("30m 应推导为 timeout 1800 秒前缀, got %q", run30)
		}
	}

	run, err = nucleiBashCommand(dir, vulnintel.ScanArgs{Target: "https://t/", TimeoutTotal: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(run, "-proxy") {
		t.Fatalf("无代理命令不应含 -proxy: %q", run)
	}

	if _, err := nucleiBashCommand(dir, vulnintel.ScanArgs{
		Target:       "https://t/",
		TimeoutTotal: 10 * time.Minute,
		Proxy:        "http://a,b:1",
	}); err == nil {
		t.Fatal("含逗号代理应返回错误")
	}
}

// TestNucleiEgressNote 锁住出口排查提示：只有配置代理时才前置，
// 且必须能引导到 proxy_status。
func TestNucleiEgressNote(t *testing.T) {
	if got := nucleiEgressNote(""); got != "" {
		t.Fatalf("空代理应返回空串, got %q", got)
	}
	if got := nucleiEgressNote("   "); got != "" {
		t.Fatalf("空白代理应返回空串, got %q", got)
	}
	got := nucleiEgressNote("http://127.0.0.1:8788")
	if !strings.Contains(got, "-proxy") || !strings.Contains(got, "proxy_status") {
		t.Fatalf("非空代理提示应含 -proxy 与 proxy_status, got %q", got)
	}
}
