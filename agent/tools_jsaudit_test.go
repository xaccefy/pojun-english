package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.4.59: js_audit SPA/webpack source-leak audit — only drops a script + builds a command, never sends requests itself.
func TestJsAuditComposesCommand(t *testing.T) {
	dir := t.TempDir()
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(dir)
	tool := ts.jsAudit()
	in, _ := json.Marshal(map[string]any{"urls": []string{
		"https://a.example.com/", "https://a.example.com/static/js/app.9f2c1d.js", "bad", "https://a.example.com/",
	}})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var out struct {
		RunWithBash string `json:"run_with_bash"`
		Count       int    `json:"count"`
	}
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, toolResultText(t, res))
	}
	if out.Count != 2 {
		t.Fatalf("count=%d want 2 (invalid URLs and dupes should be filtered)", out.Count)
	}
	if !strings.Contains(out.RunWithBash, "js_audit.py") ||
		!strings.Contains(out.RunWithBash, "--out") ||
		!strings.Contains(out.RunWithBash, "app.9f2c1d.js") {
		t.Fatalf("command=%q", out.RunWithBash)
	}
	// the script lands and is valid python (py_compile verified externally in CI; here just non-empty).
	p := filepath.Join(dir, jsAuditScriptName)
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("script missing: %v", err)
	}
	if info.Size() < 2000 {
		t.Fatalf("script too small: %d", info.Size())
	}
}

// Without runDir it must error clearly, not silently succeed.
func TestJsAuditRequiresRunDir(t *testing.T) {
	ts := NewToolSet(nil, "reporter")
	tool := ts.jsAudit()
	in, _ := json.Marshal(map[string]any{"urls": []string{"https://a.example.com/"}})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.Contains(toolResultText(t, res), "not enabled") {
		t.Fatalf("expected not-enabled error, got: %s", toolResultText(t, res))
	}
}
