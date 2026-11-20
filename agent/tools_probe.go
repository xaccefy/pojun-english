package agent

// http_probe: batch-probing domain tool (v0.4.27).
//
// ## Why it exists
//
// Task-5 measurement: Bash was 57% of all tool_use (6833 calls) — 2750 curl probes, 2105 python3
// glue — workers hand-wrote curl one at a time, each full response entering the conversation (≈3M
// input per intent avg). Batch probing is the highest-frequency most-patterned action — worth a domain tool:
// one call → one command → one compact JSON line per URL (status/bytes/title/server/type/redirect/time),
// compressing N Bash round-trips into 1 and response bodies from 'whole HTML page' to 'one-line summary'.
//
// ## Design principles (same as auth_request / diff_responses)
//
// **Only drops a script + builds a command — never sends requests itself** — traffic recording, approval
// gates and audit all auto-apply via Bash; the platform sending requests itself would bypass the whole chain.
//
// The script lands idempotently (runDir/probe.sh); later calls pass only URL lists — minimal commands.
// No --noproxy: when the environment has a recording proxy (http(s)_proxy env vars), curl automatically
// goes through it and traffic lands in the viewer as usual; without one it connects directly — same as handwritten curl -k.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// probeScriptName 是探活脚本在 Agent 工作目录里的文件名。
const probeScriptName = "probe.sh"

const httpProbeScript = `#!/usr/bin/env bash
# probe: emits one compact JSON line per URL (url/status/bytes/time_ms/title/server/content_type/redirect)
for u in "$@"; do
  f=$(mktemp); h=$(mktemp)
  out=$(curl -sS -k -L --max-time 10 -w '%{http_code} %{time_total}' -o "$f" -D "$h" "$u" 2>/dev/null)
  code=${out%% *}; tt=${out##* }
  bytes=$(wc -c < "$f" | tr -d ' ')
  ms=$(awk -v t="$tt" 'BEGIN{printf "%d", t*1000}')
  python3 - "$u" "${code:-000}" "${bytes:-0}" "${ms:-0}" "$f" "$h" <<'PYEOF'
import sys, json, re
u, code, bs, ms, body, hdr = sys.argv[1:7]
title = srv = ct = loc = ""
try:
    s = open(body, 'rb').read(65536).decode('utf-8', 'replace')
    m = re.search(r'<title[^>]*>(.*?)</title>', s, re.S | re.I)
    if m:
        title = re.sub(r'\s+', ' ', m.group(1)).strip()[:120]
except Exception:
    pass
try:
    for line in open(hdr, encoding='utf-8', errors='replace'):
        k = line.split(':', 1)
        if len(k) == 2:
            key = k[0].strip().lower()
            if key == 'server':
                srv = k[1].strip()[:80]
            elif key == 'content-type':
                ct = k[1].strip()[:80]
            elif key == 'location':
                loc = k[1].strip()[:200]
except Exception:
    pass
print(json.dumps({"url": u, "status": code, "bytes": int(bs) if bs.isdigit() else 0,
                  "time_ms": int(ms) if ms.isdigit() else 0, "title": title, "server": srv,
                  "content_type": ct, "redirect": loc}, ensure_ascii=False))
PYEOF
  rm -f "$f" "$h"
done
`

// ensureProbeScript idempotently drops the probe script; returns empty on failure (caller degrades to hand-writing).
func (t *ToolSet) ensureProbeScript() string {
	if strings.TrimSpace(t.runDir) == "" {
		return ""
	}
	// 每次覆盖写，不复用既有同名文件：runDir 同时是模型写中间产物的目录，
	// 若模型先创建了同名文件，复用会让工具执行模型的脚本而不是平台脚本。
	p := filepath.Join(t.runDir, probeScriptName)
	if err := os.WriteFile(p, []byte(httpProbeScript), 0o755); err != nil {
		return ""
	}
	return p
}

// httpProbe batch-probes: given a URL list, returns a ready-to-run Bash command.
func (t *ToolSet) httpProbe() actool.CoreTool {
	return readTool(
		"http_probe",
		"Batch HTTP liveness probing (recommended over hand-written curl): probes a batch of URLs, emitting one compact "+
			"((status/bytes/time_ms/title/server/content_type/redirect).)\n"+
			"This tool returns a run_with_bash command — hand it to Bash (traffic recording/approvals apply as usual). "+
			"Good for: batch-confirming untested endpoints are alive, quick fingerprinting (server/title/content_type), "+
			"differential probing (same path across hosts). For full response bodies and deep analysis, still curl manually — "+
			"this tool gives summaries only.",
		obj(map[string]any{
			"urls": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "URL list to probe (1-40 absolute addresses)",
			},
		}, "urls"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URLs []string `json:"urls"`
			}
			_ = json.Unmarshal(in, &a)
			urls := make([]string, 0, len(a.URLs))
			seen := map[string]bool{}
			for _, u := range a.URLs {
				u = strings.TrimSpace(u)
				if u == "" || seen[u] || (!strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://")) {
					continue
				}
				seen[u] = true
				urls = append(urls, u)
				if len(urls) >= 40 {
					break
				}
			}
			if len(urls) == 0 {
				return actool.Errorf("urls needs at least one valid http(s) absolute address"), nil
			}
			script := t.ensureProbeScript()
			if script == "" {
				return actool.Errorf("http_probe unavailable: this run has no usable work dir"), nil
			}
			quoted := make([]string, len(urls))
			for i, u := range urls {
				quoted[i] = "'" + strings.ReplaceAll(u, "'", `'\''`) + "'"
			}
			return jsonResult(map[string]any{
				"run_with_bash": fmt.Sprintf("bash %s %s", script, strings.Join(quoted, " ")),
				"count":         len(urls),
				"note":          "output is one JSON per line: url/status/bytes/time_ms/title/server/content_type/redirect. Record conclusions via record_fact as usual (auto-anchors hit assets).",
			})
		})
}
