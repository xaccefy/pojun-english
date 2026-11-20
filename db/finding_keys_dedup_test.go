package db

import (
	"strings"
	"testing"
)

// 位置键不能充当身份：endpoint / param 必须是弱键（rank 99），
// 否则同一资产上的不同漏洞会被判为同一漏洞并合并进同一行。
func TestStrongFindingKeyRankEndpointAndParamAreWeak(t *testing.T) {
	for _, kind := range []string{FindingKeyEndpoint, FindingKeyParam} {
		if got := strongFindingKeyRank(kind); got != 99 {
			t.Fatalf("strongFindingKeyRank(%q)=%d，期望 99（弱键）", kind, got)
		}
	}
	for kind, want := range map[string]int{
		FindingKeyRoot:   1,
		FindingKeyCVE:    2,
		FindingKeyLegacy: 5,
	} {
		if got := strongFindingKeyRank(kind); got != want {
			t.Fatalf("strongFindingKeyRank(%q)=%d，期望 %d", kind, got, want)
		}
	}
}

// 裸资产基址不产出端点键：不能因为「都在这个站点」就把不同漏洞并到一起。
func TestFindingDedupKeysDropsRootEndpoint(t *testing.T) {
	in := RecordFindingInput{
		VulnClass: "信息泄露",
		Name:      "订单越权",
		Summary:   "目标 http://203.0.113.10:8080 上可越权读取他人订单",
	}
	for _, k := range FindingDedupKeys(in, "") {
		if k.Kind == FindingKeyEndpoint {
			t.Fatalf("根路径不应生成端点键，得到 %q", k.Key)
		}
		if k.Kind == FindingKeyParam {
			t.Fatalf("根路径不应生成参数键，得到 %q", k.Key)
		}
	}
}

// 非根路径仍生成端点键，但只用于重复提示（弱键）。
func TestFindingDedupKeysKeepsNonRootEndpoint(t *testing.T) {
	in := RecordFindingInput{
		VulnClass: "信息泄露",
		Name:      "调试端点泄露",
		Summary:   "GET http://203.0.113.10:8080/debug 未授权返回数据库凭据",
	}
	var found bool
	for _, k := range FindingDedupKeys(in, "") {
		if k.Kind == FindingKeyEndpoint && k.Key == "endpoint:203.0.113.10:8080/debug" {
			found = true
		}
	}
	if !found {
		t.Fatalf("非根路径应生成端点键，得到 %+v", FindingDedupKeys(in, ""))
	}
}

// 无法解析的「URL」不构成身份，也不回退成原文小写。
func TestNormalizeFindingEndpointRejectsMalformed(t *testing.T) {
	if got := normalizeFindingEndpoint("http://203.0.113.10:8080（说明文字"); got != "" {
		t.Fatalf("解析失败的 URL 应返回空，得到 %q", got)
	}
	// 合法 URL 仍正常归一
	if got := normalizeFindingEndpoint("http://203.0.113.10:8080/debug/"); got != "203.0.113.10:8080/debug" {
		t.Fatalf("合法 URL 归一错误，得到 %q", got)
	}
}

// URL 提取必须排除全角标点，不能把说明文字吞进 URL。
func TestFindingDedupKeysFullWidthPunctuation(t *testing.T) {
	cases := []struct{ evidence, want string }{
		{
			evidence: "目标 http://203.0.113.10:8080/debug（说明文字）返回凭据",
			want:     "endpoint:203.0.113.10:8080/debug",
		},
		{
			evidence: "目标 http://203.0.113.10:8080/debug，随后",
			want:     "endpoint:203.0.113.10:8080/debug",
		},
	}
	for _, c := range cases {
		in := RecordFindingInput{VulnClass: "信息泄露", Name: "x", Evidence: c.evidence}
		var got string
		for _, k := range FindingDedupKeys(in, "") {
			if k.Kind == FindingKeyEndpoint {
				got = k.Key
			}
		}
		if got != c.want {
			t.Fatalf("evidence=%q 得到端点键 %q，期望 %q", c.evidence, got, c.want)
		}
	}
}

// 根因键是显式身份声明：过短或通用词不接受（宁缺毋滥）。
func TestNormalizeRootCauseKeyRejectsGeneric(t *testing.T) {
	for _, raw := range []string{"", "x", "ssrf", "xss", "vuln", "unknown"} {
		if got := normalizeRootCauseKey(raw); got != "" {
			t.Fatalf("normalizeRootCauseKey(%q)=%q，期望空", raw, got)
		}
	}
	for _, raw := range []string{"jwt-alg-none", "idor-order-owner", "ssrf-menu-image-url"} {
		if got := normalizeRootCauseKey(raw); got == "" {
			t.Fatalf("normalizeRootCauseKey(%q) 不应为空", raw)
		}
	}
}

// findingLocator（指纹的位置成分）同样不能把标点说明写进去。
func TestFindingLocatorRejectsMalformedURL(t *testing.T) {
	in := RecordFindingInput{
		VulnClass: "信息泄露",
		Name:      "x",
		Evidence:  "http://203.0.113.10:8080（说明",
	}
	if got := findingLocator(in); strings.Contains(got, "（") || strings.Contains(got, "说明") {
		t.Fatalf("findingLocator 不应把标点说明写进指纹位置，得到 %q", got)
	}
}
