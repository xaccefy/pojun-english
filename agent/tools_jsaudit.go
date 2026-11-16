package agent

// js_audit: SPA/webpack frontend source-leak audit domain tool (v0.4.59).
//
// ## Why it exists
//
// Task 18 (Vue site) measurement: the worker only had api-recon's JS-reverse notes for the frontend — no
// systematic sourcemap check. If the .map that `//# sourceMappingURL=x.js.map` points to is public (webpack
// productionSourceMap left on), sourcesContent holds the **complete original source** (Vue SFC/endpoints/
// keys/intranet addresses) — CWE-540 source info disclosure, reportable high at L3; a real key hit = critical.
// Depending on the model 'remembering' to curl .map is unreliable — make it a domain tool: one call, whole-chain conclusion.
//
// ## Detection chain (implemented in-script, stdlib only)
//
// 1. Entry HTML → extract <script src> / modulepreload;
// 2. Per JS: read trailing sourceMappingURL (external or data:base64 inline); even without the hint,
//    fall back to probing <js>.map; mine hash-named chunks from the bundle (enqueue within cap);
// 3. .map is JSON with sources → restore the directory tree to disk (.vue/.env/config counted), plus key and
//    endpoint/route scanning (AKIA/private keys/JWT/AK-SK kv/intranet ranges/URL/API paths/router paths);
// 4. One JSON event per line, summary at the end — worker still record_facts / report_findings as usual.
//
// ## Design principles (same as http_probe)
//
// **Lands the script + builds the command only — never sends requests itself** — traffic recording, approval
// controls and audit all apply automatically via Bash (http(s)_proxy env vars route python urllib through the recording proxy).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

const jsAuditScript = `#!/usr/bin/env python3
"""pojun js_audit: SPA/webpack frontend source-leak audit.

Usage: python3 pojun-jsaudit.py --out <outdir> <url1> [url2 ...]
url can be an entry HTML (extracts <script src>) or a .js file itself.
Outputs one JSON event per line; final line type=summary. Stdlib only;
http(s)_proxy env vars take effect automatically (traffic through the recording proxy); TLS verification off (like curl -k).
"""
import sys, os, json, re, base64, ssl, urllib.request, urllib.parse

MAX_BYTES = 3_000_000
MAX_MAP_BYTES = 12_000_000
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
      "Accept-Encoding": "identity"}

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx))

def fetch(url, cap=MAX_BYTES):
    req = urllib.request.Request(url, headers=UA)
    with _opener.open(req, timeout=15) as r:
        return r.getcode(), r.read(cap + 1), r.geturl()

def emit(obj):
    print(json.dumps(obj, ensure_ascii=False))
    sys.stdout.flush()

SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
PRELOAD_RE = re.compile(r'<link[^>]+(?:modulepreload|preload)[^>]+href=["\']([^"\']+\.js[^"\']*)["\']', re.I)
SMU_RE = re.compile(r'[#@]\s*sourceMappingURL=([^\s\'"]+)')
URL_RE = re.compile(r'https?://[^\s"\'<>()\\{}\[\]]{4,120}')
API_RE = re.compile(r'["\'](/(?:api|v[0-9]|rest|gateway|service|prod-api|dev-api)[A-Za-z0-9_\-/.]{2,80})["\']')
ROUTER_RE = re.compile(r'path:\s*["\'](/[^"\']{1,60})["\']')
CHUNK_RE = re.compile(r'["\']([A-Za-z0-9_\-./]{2,100}?[0-9a-f]{6,8}\.js)["\']')
SECRET_PATTERNS = [
    ("private_key", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("aws_ak", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("aliyun_ak", re.compile(r'LTAI[0-9A-Za-z]{12,}')),
    ("akid", re.compile(r'AKID[A-Za-z0-9]{10,}')),
    ("jwt", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.')),
    ("ak_sk_kv", re.compile(r'(?:access[_-]?key|secret[_-]?key|api[_-]?key|apikey|app[_-]?secret|client[_-]?secret|private[_-]?key|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{10,64})["\']', re.I)),
    ("internal_ip", re.compile(r'(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)')),
]

def secret_scan(text, src):
    hits = {}
    for label, pat in SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            s = m.group(0)[:120]
            hits[label] = s
    if hits:
        emit({"type": "secrets", "source": src, "hits": hits,
              "note": "confirm it's a real credential (can call an endpoint/decrypt data) before upgrading the report — record_fact first"})
    return len(hits)

def endpoint_scan(js, url):
    urls = []
    for m in URL_RE.findall(js):
        if m not in urls:
            urls.append(m)
        if len(urls) >= 30:
            break
    apis = []
    for m in API_RE.findall(js):
        if m not in apis:
            apis.append(m)
        if len(apis) >= 30:
            break
    routes = []
    for m in ROUTER_RE.findall(js):
        if m not in routes:
            routes.append(m)
        if len(routes) >= 20:
            break
    if urls or apis or routes:
        emit({"type": "endpoints", "url": url, "urls": urls, "api_paths": apis, "router_paths": routes})
    return len(urls) + len(apis) + len(routes)

def chunk_candidates(js, base):
    out = []
    for m in CHUNK_RE.findall(js):
        if m in out or len(out) >= 8:
            continue
        u = urllib.parse.urljoin(base, m)
        if u.startswith("http"):
            out.append(u)
    return out

def safe_name(src, i):
    # webpack:///./src/views/Login.vue -> src/views/Login.vue; traversal-proof, length-capped.
    p = urllib.parse.urlparse(src).path if "://" in src else src
    p = p.lstrip("/")
    p = re.sub(r"(\.\./)+", "_up/", p)
    parts = [re.sub(r'[<>:"|?*\x00-\x1f]', "_", seg) for seg in p.split("/") if seg and seg not in (".", "..")]
    name = os.path.join(*parts) if parts else ("file_%d" % i)
    if len(name) > 180:
        name = name[-180:]
    return "%04d_%s" % (i, name)

def write_sources(m, outdir, tag):
    sources = m.get("sources") or []
    contents = m.get("sourcesContent") or []
    written = 0
    vue = envf = 0
    for i, src in enumerate(sources):
        c = contents[i] if i < len(contents) and contents[i] else None
        low = src.lower()
        if low.endswith(".vue"):
            vue += 1
        if low.endswith(".env") or "config" in low and low.endswith((".ts", ".js")):
            envf += 1
        if c is None:
            continue
        rel = safe_name(src, i)
        path = os.path.join(outdir, tag, rel)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(c)
            written += 1
            if written >= 300:
                break
        except OSError:
            continue
    return {"sources": len(sources), "with_content": sum(1 for c in contents if c), "written": written,
            "vue_files": vue, "env_or_config": envf}

def analyze_map(raw, js_url, map_url, outdir, tag):
    # Returns (real hit, secret hit count): SPA fallback serves 200 on 404 pages — 'reachable' ≠ 'hit'.
    try:
        m = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        emit({"type": "sourcemap", "found": False, "js": js_url, "map_url": map_url,
              "note": "map reachable but not JSON"})
        return False, 0
    if not isinstance(m, dict) or "sources" not in m:
        emit({"type": "sourcemap", "found": False, "js": js_url, "map_url": map_url,
              "note": "JSON but no sources field"})
        return False, 0
    info = write_sources(m, outdir, tag)
    try:
        with open(os.path.join(outdir, tag, "__map__.json"), "wb") as f:
            f.write(raw)
    except OSError:
        pass
    emit({"type": "sourcemap", "found": True, "js": js_url, "map_url": map_url, **info,
          "dir": os.path.join(outdir, tag),
          "note": "CWE-540 source leak: sourcesContent IS the original source; .vue/.env counts above.
                  "A real key → critical; structure-only leak → high (L3)"})
    n = secret_scan(raw.decode("utf-8", "replace"), "map:" + map_url)
    return True, n

def audit_js(url, outdir, seen_dirs):
    try:
        code, body, final = fetch(url)
    except Exception as e:
        emit({"type": "js", "url": url, "error": str(e)[:120]})
        return 0, []
    js = body.decode("utf-8", "replace")
    emit({"type": "js", "url": final, "status": code, "bytes": len(body)})
    hits = secret_scan(js, "js:" + final)
    n_ep = endpoint_scan(js, final)
    secrets_n = hits
    eps_n = 1 if n_ep else 0
    found = False
    total = hits
    m_smu = SMU_RE.search(js)
    tag = re.sub(r"[^A-Za-z0-9._-]", "_", urllib.parse.urlparse(final).path.replace("/", "_"))[-60:] or "js"
    if tag in seen_dirs:
        tag = tag + "_%d" % len(seen_dirs)
    seen_dirs.add(tag)
    if m_smu:
        mu = m_smu.group(1)
        if mu.startswith("data:application/json;base64,"):
            try:
                raw = base64.b64decode(mu.split(",", 1)[1])
                ok, total_s = analyze_map(raw, final, "(inline)", outdir, tag)
                total += total_s
                found = found or ok
            except Exception:
                pass
        else:
            map_url = urllib.parse.urljoin(final, mu)
            try:
                code, raw, _ = fetch(map_url, MAX_MAP_BYTES)
                if code == 200:
                    ok, total_s = analyze_map(raw, final, map_url, outdir, tag)
                    total += total_s
                    found = found or ok
                else:
                    emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                          "status": code})
            except Exception as e:
                emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                      "error": str(e)[:120]})
    if not found:
        map_url = final + ".map"
        try:
            code, raw, _ = fetch(map_url, MAX_MAP_BYTES)
            if code == 200:
                ok, total_s = analyze_map(raw, final, map_url, outdir, tag)
                total += total_s
                found = found or ok
            else:
                emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                      "status": code, "note": "no sourceMappingURL hint — fall-back probing <js>.map"})
        except Exception as e:
            emit({"type": "sourcemap", "found": False, "js": final, "map_url": map_url,
                  "error": str(e)[:120]})
    return (1 if found else 0), chunk_candidates(js, final), secrets_n + total, eps_n

def main():
    args = sys.argv[1:]
    outdir = os.path.join(os.getcwd(), "jsmap")
    urls = []
    i = 0
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            outdir = args[i + 1]
            i += 2
            continue
        urls.append(args[i])
        i += 1
    if not urls:
        emit({"type": "summary", "error": "no URL given"})
        return
    os.makedirs(outdir, exist_ok=True)
    queue, fetched, seen_dirs = [], set(), set()
    queue.extend(urls[:6])
    maps = js_n = secrets_total = ep_total = 0
    html_urls = set(u for u in queue if not u.endswith(".js"))
    while queue and js_n < 12:
        url = queue.pop(0)
        if url in fetched:
            continue
        fetched.add(url)
        if url in html_urls or url.endswith((".html", ".htm")) or ".js" not in url:
            try:
                code, body, final = fetch(url)
            except Exception as e:
                emit({"type": "html", "url": url, "error": str(e)[:120]})
                continue
            html = body.decode("utf-8", "replace")
            emit({"type": "html", "url": final, "status": code, "bytes": len(body)})
            found = 0
            for m in SCRIPT_RE.findall(html) + PRELOAD_RE.findall(html):
                u = urllib.parse.urljoin(final, m)
                if u not in fetched and u not in queue and len(queue) < 14:
                    queue.append(u)
                    found += 1
            emit({"type": "html_scripts", "url": final, "queued": found})
            continue
        found_n, chunks, sec_n, ep_n = audit_js(url, outdir, seen_dirs)
        maps += found_n
        secrets_total += sec_n
        ep_total += ep_n
        js_n += 1
        for cu in chunks:
            if cu not in fetched and cu not in queue and len(queue) < 14:
                queue.append(cu)
    emit({"type": "summary", "js_audited": js_n, "sourcemaps_found": maps,
          "secret_signals": secrets_total, "endpoint_signals": ep_total, "dir": outdir,
          "next": "sites with sourcemap found=true → report high per CWE-540 (real keys → critical); "
                  "endpoint/route lists → record_fact and continue per api-security-testing"})

if __name__ == "__main__":
    main()
`

// ensureJsAuditScript idempotently lands the audit script; returns "" on failure (caller degrades to letting the model hand-write).
func (t *ToolSet) ensureJsAuditScript() string {
	if strings.TrimSpace(t.runDir) == "" {
		return ""
	}
	p := filepath.Join(t.runDir, "pojun-jsaudit.py")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if err := os.WriteFile(p, []byte(jsAuditScript), 0o755); err != nil {
		return ""
	}
	return p
}

// jsAudit SPA/webpack source-leak audit: give entry URL(s), get a ready-to-run command.
func (t *ToolSet) jsAudit() actool.CoreTool {
	return readTool(
		"js_audit",
		"SPA/webpack frontend source-leak audit (must-run for Vue/React single-page apps): give entry URL(s) (HTML or JS) — "+
			"the script extracts <script> tags and chunks, checks sourceMappingURL, falls back to probing <js>.map, "+
			"restores sourcesContent original source to disk, scans keys (AK/SK/private keys/JWT/intranet ranges) and extracts "+
			"endpoint & route lists. This tool returns a command for Bash to run (traffic recording/approvals still apply).\n"+
			"Verdict framing: sourcemap hit = CWE-540 source leak high (L3); a real credential restored = critical; "+
			"endpoint/route lists → record_fact then continue per api-security-testing.",
		obj(map[string]any{
			"urls": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "entry URL list (1-6: entry HTML or concrete .js files)",
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
				if len(urls) >= 6 {
					break
				}
			}
			if len(urls) == 0 {
				return actool.Errorf("urls needs at least one valid absolute http(s) address"), nil
			}
			script := t.ensureJsAuditScript()
			if script == "" {
				return actool.Errorf("js_audit not enabled: no usable work dir for this run"), nil
			}
			quoted := make([]string, len(urls))
			for i, u := range urls {
				quoted[i] = "'" + strings.ReplaceAll(u, "'", `'\''`) + "'"
			}
			out := filepath.Join(t.runDir, "jsmap")
			return jsonResult(map[string]any{
				"run_with_bash": fmt.Sprintf("python3 %s --out %s %s", script, out, strings.Join(quoted, " ")),
				"count":         len(urls),
				"note": "output is one JSON event per line (html/js/sourcemap/secrets/endpoints/summary). " +
					"sourcemap found=true → CWE-540: restored source lands in the --out dir; save_evidence then report high; " +
					"real credentials in secrets → critical; endpoints get record_fact'd and continue per api-security-testing.",
			})
		})
}
