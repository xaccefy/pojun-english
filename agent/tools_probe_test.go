package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.4.27: http_probe batch liveness tool — only drops a script + builds a command, never sends requests itself.
func TestHTTPProbeComposesCommand(t *testing.T) {
	dir := t.TempDir()
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(dir)
	tool := ts.httpProbe()
	in, _ := json.Marshal(map[string]any{"urls": []string{
		"https://a.example.com/x", "https://b.example.com/y?q=1", "not-a-url", "https://a.example.com/x",
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
	if !strings.Contains(out.RunWithBash, "pojun-probe.sh") || !strings.Contains(out.RunWithBash, "https://b.example.com/y?q=1") {
		t.Fatalf("command=%q", out.RunWithBash)
	}
	// script landed on disk (invocation is `bash <script>` — doesn't rely on the exec bit; Windows has none).
	script := filepath.Join(dir, "pojun-probe.sh")
	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("script missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("script empty")
	}
	// second call reuses the same script (idempotent write).
	res2, _ := tool.Call(context.Background(), in, nil)
	var out2 struct {
		RunWithBash string `json:"run_with_bash"`
	}
	_ = json.Unmarshal([]byte(toolResultText(t, res2)), &out2)
	if out2.RunWithBash != out.RunWithBash {
		t.Fatalf("command not stable across calls:\n%s\n%s", out.RunWithBash, out2.RunWithBash)
	}
}

// Without runDir (e.g. the reporter chat toolset) it must error clearly, not silently succeed.
func TestHTTPProbeRequiresRunDir(t *testing.T) {
	ts := NewToolSet(nil, "reporter")
	tool := ts.httpProbe()
	in, _ := json.Marshal(map[string]any{"urls": []string{"https://a.example.com/"}})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.Contains(toolResultText(t, res), "unavailable") {
		t.Fatalf("expected not-enabled error, got: %s", toolResultText(t, res))
	}
}
