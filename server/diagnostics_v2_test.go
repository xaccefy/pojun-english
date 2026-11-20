package server

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

// 诊断包 v2 必须能真正导出 findings（v1 的 COALESCE(bigint,”) 会让它恒为 []）。
func TestDiagnosticsV2IncludesFindingsAndEntities(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("diag-v2", "验证诊断包", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	if _, err := store.AddNode(db.KindGoal, map[string]any{"text": "拿到 root", "criteria": "whoami uid=0"}, 0, "open", "goals", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddNode(db.KindIntent, map[string]any{"summary": "探测登录口"}, 5, "exhausted", "planner", nil); err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(task.ID, 0, "SQL注入", "登录口 SQLi", "high", "summary", "curl -d x=1 http://t/?id=1 HTTP/1.1 200", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if fid == 0 {
		t.Fatal("finding 未写入")
	}

	s := &Server{m: &Manager{pg: d}, engine: &Engine{}}
	b := s.collectDiagnostics(diagnosticsOptions{Since: time.Now().Add(-24 * time.Hour)})

	findings, ok := b.sections["findings"]
	if !ok {
		t.Fatal("缺少 findings 节")
	}
	if findings.Error != "" {
		t.Fatalf("findings 节报错: %s", findings.Error)
	}
	if findings.Rows == 0 {
		t.Fatalf("findings 节为空（BIGINT 类型 bug 可能复发）")
	}
	if _, ok := b.sections["findings_debug"]; !ok {
		t.Fatal("缺少 findings_debug 对账节")
	}
	tasks := b.sections["tasks"]
	if tasks.Error != "" || tasks.Rows == 0 {
		t.Fatalf("tasks 节异常: err=%q rows=%d", tasks.Error, tasks.Rows)
	}
	goals := b.sections["goals"]
	if goals.Rows == 0 {
		t.Fatal("goals 节为空")
	}
	intents := b.sections["intents"]
	if intents.Rows == 0 {
		t.Fatal("intents 节为空")
	}
	for _, key := range []string{"integrity", "llm_usage", "logs", "timeline", "proxy_pool", "engine"} {
		if _, ok := b.sections[key]; !ok {
			t.Fatalf("缺少 %s 节", key)
		}
	}
}

// v0.8：诊断包不再脱敏，代理设置按全量导出（用户明确要求全量诊断）。
func TestDiagSettingsMasksProxyCredentials(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	m := &Manager{pg: d}
	m.globalProxy = "http://alice:secret@127.0.0.1:8888"
	s := &Server{m: m}
	v, _ := s.diagSettings()["global_proxy"].(string)
	if v == "" {
		t.Fatal("global_proxy 丢字段")
	}
	if strings.Contains(v, "secret") || strings.Contains(v, "alice") {
		t.Fatalf("诊断包必须掩码代理凭据，得到 %q", v)
	}
}

// 导出的 zip 必须真的包含 findings/manifest，且 manifest 标注每节状态。
func TestDiagnosticsExportZip(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	s := &Server{m: &Manager{pg: d}, engine: &Engine{}}
	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/export?detail=1", nil)
	rec := httptest.NewRecorder()
	s.handleDiagnosticsExport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip 解析失败: %v", err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, want := range []string{"manifest.json", "findings.json", "tasks.json", "intents.json", "logs.json", "traffic.json"} {
		if !names[want] {
			t.Fatalf("zip 缺 %s（实际: %v）", want, names)
		}
	}
}
