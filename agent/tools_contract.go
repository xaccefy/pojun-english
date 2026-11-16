package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/intercept"
)

// API contract enumeration tool: reads the **endpoint list** (paths, methods, params,
// whether auth is required) out of an OpenAPI/Swagger/Postman contract file exposed by the target.
//
// ## Why it exists
//
// We currently discover endpoints two ways:
//   - crawlers (katana) — they guess paths and miss endpoints the frontend never links to;
//   - frontend JS static/runtime analysis (api-recon skill) — accurate, but depends on readable
//     frontend code and only sees 'what the frontend called', not 'what the backend supports'.
//
// **A contract file is the third route — and often the most accurate**: it directly answers 'which endpoints,
// which params, which methods, which need auth'. Strix (the open-source peer) takes this route — reads it straight.
// OpenAPI/Swagger/Postman.
//
// Common case: the target has `/swagger-ui/`, `/api-docs`, `/openapi.json`,
// `/v2/api-docs` (Swagger 2.0), `/v3/api-docs` (OpenAPI 3), etc. These paths are
// **conventional** — probing a handful covers most sites.
//
// ## Why parsing happens in a script
//
// Contract files routinely run thousands of lines. Dumping raw content into model context
// both burns tokens and invites missed items — and 'missing an authed endpoint' is exactly what
// privesc mining most easily loses. The parsed list is **structured and enumerable** — what the model needs.
//
// But parsing is pure local compute (download goes via Bash → through the recording proxy and approval
// controls; parsing runs locally). Same pattern as diff_responses: the script lands in this run's work dir, the command goes to Bash.
//
// ## Boundary
//
// Only **reads contracts** (GETs the contract file). No fuzzing, no request rewriting, no business requests.
// Whether/how to hit the listed endpoints is a later mining action (vuln-hunting's job).

// apiContractTool assembles the API contract enumeration tool.
func (t *ToolSet) apiContractTool() actool.CoreTool {
	return readTool(
		"api_contract",
		"Reads the endpoint list (paths, methods, params, auth-required) out of an [API contract file] exposed by the target.\n"+
			"Usage: give base_url (the target site root, e.g. https://t.example.com); the tool probes common contract paths "+
			"(/openapi.json, /swagger.json, /v3/api-docs, /api-docs etc.) and parses out the endpoint list.\n"+
			"**Why it's worth doing**: crawlers guess paths and miss endpoints; frontend JS analysis only sees 'what the frontend called'; "+
			"a contract file states 'what the backend supports' directly — a more accurate endpoint source.\n"+
			"Output: each endpoint's path / method / params (with required flags) / auth-required (security field), "+
			"plus the 'auth-marked endpoints' listed separately — the batch privesc mining should look at first.\n"+
			"Hand the list to vuln-hunting's methodology for privesc/enumerable/state-machine judgment.\n"+
			"**This tool only builds the command — it doesn't execute** (downloads go through the recording proxy and approval controls).",
		obj(map[string]any{
			"base_url": str("target site root, e.g. https://t.example.com (no path)"),
			"paths":    str("custom contract paths (optional), comma-separated; probes common paths when omitted"),
		}, "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				BaseURL string `json:"base_url"`
				Paths   string `json:"paths"`
			}
			_ = json.Unmarshal(in, &a)
			base := strings.TrimSpace(a.BaseURL)
			if base == "" {
				return actool.Errorf("base_url must not be empty"), nil
			}
			if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
				return actool.Errorf("base_url must be absolute (start with http:// or https://)"), nil
			}
			base = strings.TrimRight(base, "/")

			// The parse script must land in this run's work dir (platform rule: no intermediate artifacts in /tmp).
			workDir := intercept.ReviewWorkingDirectory(ctx)
			if workDir == "" {
				return actool.Errorf("this run has no bound working directory — can't write the contract parse script; " +
					"use katana path-crawling or the api-recon skill instead"), nil
			}
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				return actool.Errorf("failed to create the working directory: " + err.Error()), nil
			}
			scriptPath, err := WriteContractScript(workDir)
			if err != nil {
				return actool.Errorf("failed to write the contract parse script: " + err.Error()), nil
			}
			paths := resolveContractPaths(a.Paths)
			cmd := buildContractCmd(base, paths, scriptPath, workDir)
			return jsonResult(map[string]any{
				"run_with_bash": cmd,
				"script_path":   scriptPath,
				"probing":       paths,
				"note": "run the command above with the Bash tool (it probes contract paths, downloads, and parses). Output is JSON: " +
					"the contract file path found + the endpoint list (path/method/params/auth-required). " +
					"No contract file found is common (many sites don't expose one) — fall back to katana path-crawling or the api-recon skill. " +
					"**The list itself isn't a vuln**, but it's the object list for privesc/enumerability judgment.",
			})
		},
	)
}

// contractPaths lists common API contract file paths.
//
// Covering three families:
//   - OpenAPI 3:/openapi.json, /openapi.yaml, /v3/api-docs
//   - Swagger 2:/swagger.json, /v2/api-docs, /api-docs, /api/swagger.json
//   - Postman:/postman_collection.json
//
// Order matters: probe JSON first (easy to parse), YAML later.
var contractPaths = []string{
	"/openapi.json",
	"/v3/api-docs",
	"/api-docs",
	"/swagger.json",
	"/v2/api-docs",
	"/api/swagger.json",
	"/api/openapi.json",
	"/docs/openapi.json",
	"/openapi.yaml",
	"/postman_collection.json",
}

// resolveContractPaths handles the custom-paths param; the default list is used when empty.
func resolveContractPaths(custom string) []string {
	parts := strings.Split(custom, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return contractPaths
	}
	return out
}

// buildContractCmd builds the 'probe + download + parse' command.
//
// Flow: curl-probe each path (only 200 counts) → download the first hit → hand it to the parse script.
// The contract file lands in the work dir (not /tmp — platform rule).
func buildContractCmd(base string, paths []string, scriptPath, workDir string) string {
	quoted := make([]string, 0, len(paths))
	for _, p := range paths {
		quoted = append(quoted, quoteShell(base+p))
	}
	contractFile := filepath.Join(workDir, "api_contract.json")
	// Step 1: probe one by one; on a hit, download into the work dir and stop.
	probe := fmt.Sprintf(
		"for u in %s; do code=$(curl -sS -o %s -w '%%{http_code}' --max-time 20 \"$u\"); "+
			"if [ \"$code\" = \"200\" ]; then echo \"CONTRACT $u\"; break; fi; done",
		strings.Join(quoted, " "), quoteShell(contractFile))
	// Step 2: hand it to the parse script.
	return probe + " ; " + fmt.Sprintf("python3 %s %s", quoteShell(scriptPath), quoteShell(contractFile))
}

// contractScriptName is the contract parse script's filename.
const contractScriptName = "api_contract.py"

// WriteContractScript writes the contract parse script into the work dir and returns its path.
func WriteContractScript(dir string) (string, error) {
	path := filepath.Join(dir, contractScriptName)
	if err := os.WriteFile(path, []byte(contractScriptSource), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// contractScriptSource is the contract parse script's source (stdlib only, no third-party deps).
//
// Output structure:
//   {
//     "contract": "https://t/openapi.json",   // the contract file hit (empty if none)
//     "found": true/false,
//     "api_count": 12,                          // total endpoint count
//     "endpoints": [ {path, method, summary, auth_required, params:[{name,in,required}]} ],
//     "auth_endpoints": [ ... ],                // the auth-required batch (privesc mining looks here first)
//     "auth_schemes": ["bearer","apiKey"],     // auth schemes declared in the contract
//   }
//
// Why single out 'auth-required endpoints': they're the entry point for privesc/unauthorized mining.
// Mixed into hundreds of endpoints, the model would probably only look at the first few.
const contractScriptSource = `#!/usr/bin/env python3
"""API contract parsing (the execution side of the POJUN agent tool api_contract).

Usage: api_contract.py <contract file>
Supports OpenAPI 3 / Swagger 2.0 (JSON); YAML isn't parsed (extra deps needed);
Postman collections get best-effort parsing.
Outputs JSON: the contract hit, the endpoint list, auth-required endpoints.
"""
import json, sys


def load(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def params_of(op):
    """Returns one operation's param list (OpenAPI3: parameters + requestBody; Swagger2: parameters)."""
    out = []
    for p in (op.get("parameters") or []):
        name = p.get("name")
        if not name:
            continue
        sch = p.get("schema") or {}
        out.append({
            "name": name,
            "in": p.get("in", ""),
            "required": bool(p.get("required", False)),
            "type": sch.get("type", "") or p.get("type", ""),
        })
    rb = op.get("requestBody") or {}
    for name, sch in (rb.get("content") or {}).items():
        if isinstance(sch, dict):
            for pn in (sch.get("properties") or {}):
                out.append({
                    "name": pn,
                    "in": "body:" + name,
                    "required": bool(((sch.get("properties") or {}).get(pn) or {}).get("required", False)),
                    "type": (((sch.get("properties") or {}).get(pn) or {}).get("type", "")),
                })
    return out


def auth_required(op, spec):
    """Whether this operation requires auth.

    Rule: the operation's own security wins; fall back to global security when absent.
    An empty security array [] means [explicitly declared public] — that doesn't count as auth-required.
    """
    sec = op.get("security", spec.get("security"))
    if sec is None:
        return False
    if isinstance(sec, list) and len(sec) == 0:
        return False
    return bool(sec)


def auth_schemes(spec):
    out = []
    comps = ((spec.get("components") or {}).get("securitySchemes")
             or spec.get("securityDefinitions") or {})
    for name, sch in comps.items():
        t = (sch or {}).get("type", "")
        if t:
            out.append(t if t != "apiKey" else "apiKey:" + str((sch or {}).get("name", "")))
    return out


def parse_openapi(spec):
    endpoints = []
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        common = item.get("parameters") or []
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch",
                                      "head", "options", "trace"):
                continue
            if not isinstance(op, dict):
                continue
            op = dict(op)
            op["parameters"] = (op.get("parameters") or []) + common
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "summary": (op.get("summary") or op.get("description") or "")[:120],
                "auth_required": auth_required(op, spec),
                "params": params_of(op),
                "tags": op.get("tags") or [],
            })
    return endpoints


def parse_postman(spec):
    endpoints = []
    def walk(items, prefix=""):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if "item" in it:
                walk(it.get("item"), prefix)
            else:
                req = it.get("request") or {}
                url = req.get("url")
                if isinstance(url, dict):
                    raw = url.get("raw") or ""
                else:
                    raw = url or ""
                path = raw.split("?")[0]
                # Absolute URLs must have the origin stripped too — the list wants the path, not the whole URL.
                if path.startswith("http://") or path.startswith("https://"):
                    rest = path.split("://", 1)[1]
                    slash = rest.find("/")
                    path = rest[slash:] if slash >= 0 else "/"
                if path and not path.startswith("http"):
                    path = prefix + path
                endpoints.append({
                    "path": path,
                    "method": (req.get("method") or "GET").upper(),
                    "summary": (it.get("name") or "")[:120],
                    "auth_required": bool(req.get("auth")),
                    "params": [],
                    "tags": [],
                })
    walk(spec.get("item"))
    return endpoints


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: api_contract.py <contract file>"}))
        return 1
    raw = load(sys.argv[1])
    out = {
        "contract": sys.argv[1],
        "found": False,
        "api_count": 0,
        "endpoints": [],
        "auth_endpoints": [],
        "auth_schemes": [],
    }
    if not raw.strip():
        out["error"] = "contract file is empty or unreadable"
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    try:
        spec = json.loads(raw)
    except ValueError as e:
        out["error"] = "not JSON format (if it's a YAML contract, read it manually): %s" % e
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if "paths" in spec:
        eps = parse_openapi(spec)
        out["auth_schemes"] = auth_schemes(spec)
    elif "item" in spec:
        eps = parse_postman(spec)
    else:
        eps = []
        out["error"] = "unrecognized contract format (has neither paths nor item)"
    out["found"] = bool(eps)
    out["api_count"] = len(eps)
    out["endpoints"] = eps
    out["auth_endpoints"] = [e for e in eps if e.get("auth_required")]
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
`
