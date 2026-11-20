package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// brandTokens 是不得出现在 **target-facing 产物** 里的平台/能力标识。
//
// 为什么需要这条守卫：这些字符串不是日志、不是内部注释——它们会变成发给目标的
// HTTP 请求（SSRF 参数值、multipart boundary、上传正文）、写进目标业务库的测试
// 对象名，或落成 agent 手里的脚本，而被模型抄进后续命令。客户侧蓝队会把它当成
// 攻击者的签名，产生指向本产品的假 IoC。
//
// 范围刻意限定在 target-facing 与模型可见的产物，**不扫全仓**：日志、错误文案、
// CLI 名、报告导出、发往 GitHub/GHSA 等第三方的 UA 都不在内——那些要么到不了
// 目标，要么自报身份反而是正常且有益的。一个会误报的 lint 最后一定会被关掉。
var brandTokens = []string{"pojun", "破军", "spa-api-recon"}

func assertNoBrand(t *testing.T, what, body string) {
	t.Helper()
	low := strings.ToLower(body)
	for _, tok := range brandTokens {
		if strings.Contains(low, strings.ToLower(tok)) {
			t.Fatalf("%s 含平台/能力标识 %q —— 它会随请求或脚本到达目标侧", what, tok)
		}
	}
}

// PoC 脚手架的模板正文会原样进入发给目标的请求：
// SSRF 的参数值、上传请求的 multipart boundary、写进目标磁盘的文件正文。
func TestPocScaffoldHasNoBrand(t *testing.T) {
	assertNoBrand(t, "pocCommon", pocCommon)
	if len(pocTemplates) == 0 {
		t.Fatal("pocTemplates 为空，这条守卫失去意义")
	}
	for class, body := range pocTemplates {
		assertNoBrand(t, "pocTemplates["+class+"]", body)
	}
}

// 落盘脚本的正文会出现在 agent 的工作目录里，返回值把路径与命令原样交给模型。
func TestGeneratedScriptsHaveNoBrand(t *testing.T) {
	assertNoBrand(t, "httpProbeScript", httpProbeScript)
	assertNoBrand(t, "jsAuditScript", jsAuditScript)
	assertNoBrand(t, "contractScriptSource", contractScriptSource)
	assertNoBrand(t, "diffScriptSource", diffScriptSource)
}

// 脚本文件名同样会在工具返回值里回显。
func TestGeneratedScriptNamesHaveNoBrand(t *testing.T) {
	names := []string{probeScriptName, jsAuditScriptName, contractScriptName, diffScriptName}
	for _, name := range names {
		assertNoBrand(t, "script name "+name, name)
	}
}

// 代码内置、每轮追加到 agent 系统提示的段落。
//
// 它们不是发给目标的字节，但它们是模型的写作素材：段落里反复出现的品牌词，
// 模型会顺手复用到载荷里。减少供给比事后拦截可靠。
func TestInjectedPromptFragmentsHaveNoBrand(t *testing.T) {
	frags := map[string]string{
		"engagementFraming":             engagementFraming,
		"impactVerificationGuidance":    impactVerificationGuidance,
		"impactOrchestrationGuidance":   impactOrchestrationGuidance,
		"srcReportAnnex":                srcReportAnnex,
		"srcTaskBookGuidance":           srcTaskBookGuidance,
		"goalsVerificationTail":         goalsVerificationTail,
		"scannerFirstGuidance":          scannerFirstGuidance,
		"skillRoutingGuidance":          skillRoutingGuidance,
		"coverageMatrixPlannerGuidance": coverageMatrixPlannerGuidance,
		"scopeVerifyPlannerGuidance":    scopeVerifyPlannerGuidance,
		"execFaceWorkerGuidance":        execFaceWorkerGuidance,
		"execFacePlannerGuidance":       execFacePlannerGuidance,
	}
	for name, body := range frags {
		if strings.TrimSpace(body) == "" {
			t.Fatalf("%s 为空，守卫失去意义", name)
		}
		assertNoBrand(t, name, body)
	}
}

// 技能脚本随技能分发到 agent 的工作目录，模型会直接执行它们；
// 里面的 UA 等字面量会出现在目标侧的访问日志里。
func TestSkillScriptsHaveNoBrand(t *testing.T) {
	files, err := filepath.Glob("../skills/*/scripts/*.py")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Skip("没有技能脚本，跳过")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读取 %s: %v", f, err)
		}
		assertNoBrand(t, f, string(b))
	}
}
