package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// 审计 F4：cmdi 骨架的 uid 判据正则此前被双重转义（r"uid=\\d+\\("），
// 在 Python 里匹配「字面反斜杠+数字」——永远命不中 uid=0(root)，产出假阴性。
func TestPocScaffoldCmdiRegexNotDoubleEscaped(t *testing.T) {
	ts := &ToolSet{runDir: t.TempDir()}
	res, err := ts.pocScaffold().Call(context.Background(), json.RawMessage(
		`{"vulnclass":"cmdi","target":"http://target.invalid/ping","param":"host","name":"cmdi-check.py"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("poc_scaffold 返回错误：%s", res.Flatten())
	}
	body := res.Flatten()
	i := strings.Index(body, `"path":"`)
	if i < 0 {
		t.Fatalf("返回缺少 path：%s", body[:300])
	}
	rest := body[i+len(`"path":"`):]
	j := strings.Index(rest, `"`)
	path := rest[:j]
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if strings.Contains(content, `uid=\\d`) {
		t.Fatal("cmdi 判据仍是双重转义正则（永不匹配 uid=0(root)）")
	}
	if !strings.Contains(content, `uid=\d+\(`) {
		t.Fatalf("cmdi 判据缺少正确正则 uid=\\d+\\(，脚本：\n%s", content)
	}
}
