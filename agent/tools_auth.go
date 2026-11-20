package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/db"
	"os"
	"path/filepath"
)

// Credential-reuse tool: turns 'credentials registered on an asset' into 'executable authenticated requests'.
//
// ## Why it exists
//
// The asset table has an `auth` field (username / password / token / type / description),
// and `list_assets` can read it. But **reading it out is just text** — the model must judge itself which
// credential matches which site, whether it's a login pair or a token, whether it goes in a Cookie or
// an Authorization header — then hand-write curl. One format slip (`token` in `Cookie: token=xxx` vs
// `Authorization: Bearer xxx`) returns 401 and the model misjudges it as 'credential invalid'.
//
// And for lateral testing, **privesc mining's premise is 'two identities'**: take A's credential to access B's object.
// Without this tool the model hand-carries credential strings — error-prone and leaves no evidence.
//
// ## Design principles
//
// **Builds the command only — never sends the request itself** — same pattern as scan_with_nuclei. The command
// goes to the Bash tool, so traffic recording, approval controls and audit all apply automatically; the platform
// sending requests itself would bypass the whole control chain.
//
// **Credential values are never returned.** The tool returns an **executable command**; the credential appears
// inside it as shell variables (the model sees it — it has to run it) but never in the structured
// return fields — keeping credentials out of facts/reports/the graph.
//
// **No guessing, no completion**: for credentials an asset doesn't have, the tool generates none and doesn't
// prompt the user to guess — it honestly says 'this asset has no registered credentials'.

// authEntry is one credential record on an asset (structure matches db.Asset.Auth).
type authEntry struct {
	Type        string `json:"type"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Token       string `json:"token"`
	Description string `json:"description"`
}

// authRequest builds one authenticated request command.
func (t *ToolSet) authRequest() actool.CoreTool {
	return readTool(
		"auth_request",
		"Builds an authenticated HTTP request command from [credentials registered on the asset], handed to Bash "+
			"(this tool only builds — never executes).\n"+
			"Use case: lateral testing and privesc verification — holding one identity, use **another** (registered on an asset) "+
			"to access the same resource for comparison; or reuse a discovered token to check if a session is still alive.\n"+
			"Inputs: asset_id (which asset the credential is registered on) + url (address to hit) + optional method/"+
			"body/header/auth_index (which credential to use).\n"+
			"Returns a curl command paste-ready for Bash. **The command contains the plaintext credential** — after running, "+
			"don't write the raw command into facts or reports (refer to it as 'asset#123's token').\n"+
			"Credential-less assets get a clear 'no credentials registered' — it won't guess for you.",
		obj(map[string]any{
			"asset_id":   intp("which asset the credential is registered on (a service-class asset id from list_assets)"),
			"url":        str("URL to hit (absolute)"),
			"method":     str("HTTP method, default GET"),
			"body":       str("request body (optional, POST/PUT etc.)"),
			"header":     str("extra request headers (optional, 'Key: Value' format, multiple separated by \\n)"),
			"auth_index": intp("which credential on the asset to use (0-based; defaults to the first usable one)"),
		}, "asset_id", "url"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("auth_request not enabled: AssetStore not initialized"), nil
			}
			var a struct {
				AssetID   int64  `json:"asset_id"`
				URL       string `json:"url"`
				Method    string `json:"method"`
				Body      string `json:"body"`
				Header    string `json:"header"`
				AuthIndex int    `json:"auth_index"`
			}
			_ = json.Unmarshal(in, &a)
			if a.AssetID <= 0 {
				return actool.Errorf("asset_id must be a positive integer"), nil
			}
			if strings.TrimSpace(a.URL) == "" {
				return actool.Errorf("url must not be empty"), nil
			}
			if !strings.HasPrefix(a.URL, "http://") && !strings.HasPrefix(a.URL, "https://") {
				return actool.Errorf("url must be absolute (start with http:// or https://)"), nil
			}

			// Fetch the asset (restricted to this task's scope — can't grab other tasks' credentials).
			assets, err := t.as.GetByIDsInScope(t.taskID, []int64{a.AssetID})
			if err != nil {
				return actool.Errorf("failed to read asset: " + err.Error()), nil
			}
			if len(assets) == 0 {
				return actool.Errorf(fmt.Sprintf("asset %d is outside this task's scope (or doesn't exist)", a.AssetID)), nil
			}
			asset := assets[0]

			entries := parseAuthEntries(asset.Auth)
			if len(entries) == 0 {
				return actool.Errorf(fmt.Sprintf(
					"asset %d has no registered credentials — first confirm whether auth info was collected; this tool doesn't guess or generate credentials",
					a.AssetID)), nil
			}
			idx := a.AuthIndex
			if idx < 0 {
				// 审计 F1：未传索引时选第一条【有效】凭据（保持旧行为的便利性）。
				first := -1
				for i, e := range entries {
					if e.valid() {
						first = i
						break
					}
				}
				if first < 0 {
					return actool.Errorf(fmt.Sprintf(
						"asset %d has no valid credential entry (%d placeholders)", a.AssetID, len(entries))), nil
				}
				idx = first
			}
			if idx >= len(entries) {
				return actool.Errorf(fmt.Sprintf(
					"asset %d only has %d credentials, auth_index=%d out of range", a.AssetID, len(entries), idx)), nil
			}
			entry := entries[idx]
			if !entry.valid() {
				return actool.Errorf(fmt.Sprintf(
					"auth_index=%d on asset %d is not a valid credential entry; valid indices: %s", a.AssetID, idx, validAuthIndices(entries))), nil
			}

			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = "GET"
			}
			cmd, err := buildAuthCurl(a.URL, method, a.Body, a.Header, entry)
			if err != nil {
				return actool.Errorf("failed to build command: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"run_with_bash": cmd,
				"auth_kind":     authKind(entry),
				"auth_source":   fmt.Sprintf("credential %d on asset#%d", idx, a.AssetID),
				"note": "run the command above with the Bash tool. **It contains a plaintext credential** — don't write the raw " +
					"command into facts/reports; refer to it as 'asset#<id>'s <type> credential'. A 401/403 response means " +
					"the credential or auth scheme is wrong — try another credential on the asset (auth_index).",
			})
		},
	)
}

// parseAuthEntries turns an asset's auth field into a structured credential list.
//
// Asset auth is []map[string]any (key names aren't fixed — historically username/
// password/token/type/description). Lenient parse: use recognized keys, ignore the rest,
// but **at least one usable field** is required to count as a credential.
// parseAuthEntries turns an asset's auth array into a credential list of the same length and order.
//
// Audit F1: it used to drop empty entries and reorder tokens first — list_assets shows the model the raw
// array order, while session_login/auth_request index via parseAuthEntries, so the two drifted apart and
// the model's chosen credential differed from the one actually sent (false "invalid credential", wrong
// login-breaker counting). Original order is kept now: invalid entries hold a zero value and the caller
// checks authEntry.valid() and reports it.
func parseAuthEntries(raw []map[string]any) []authEntry {
	out := make([]authEntry, 0, len(raw))
	for _, m := range raw {
		var e authEntry
		if m == nil {
			out = append(out, e)
			continue
		}
		for k, v := range m {
			s, _ := v.(string)
			s = strings.TrimSpace(s)
			switch strings.ToLower(k) {
			case "type", "kind", "auth_type":
				e.Type = s
			case "username", "user", "account", "login":
				e.Username = s
			case "password", "pass", "pwd":
				e.Password = s
			case "token", "session", "cookie", "jwt", "bearer":
				e.Token = s
			case "description", "desc", "note", "comment":
				e.Description = s
			}
		}
		out = append(out, e)
	}
	return out
}

// valid reports whether this credential has at least one usable field.
func (e authEntry) valid() bool {
	return e.Username != "" || e.Password != "" || e.Token != ""
}

// validAuthIndices returns the indices of the valid credentials (matching the asset auth array's
// original indices), so an error message can steer the model to one of them.
func validAuthIndices(entries []authEntry) string {
	ids := make([]string, 0, len(entries))
	for i, e := range entries {
		if e.valid() {
			ids = append(ids, strconv.Itoa(i))
		}
	}
	return strings.Join(ids, ",")
}

// authKind describes this credential's form (for the result's note — no credential values).
func authKind(e authEntry) string {
	switch {
	case e.Token != "":
		if e.Type != "" {
			return e.Type + "(token)"
		}
		return "token"
	case e.Username != "" && e.Password != "":
		if e.Type != "" {
			return e.Type + "(user+pass)"
		}
		return "user+pass"
	case e.Username != "":
		return "username only"
	default:
		return "unknown form"
	}
}

// buildAuthCurl builds an authenticated curl command.
//
// Auth-scheme selection:
//   - has token: default `Authorization: Bearer <token>`; if type contains
//     "cookie" use `Cookie: <token>` (some systems' session value IS the cookie value).
//   - only user+pass: `-u user:pass` (curl negotiates Basic/Digest/NTLM itself).
//
// Escaping: quotes, backslashes, $ in credentials and the URL all need handling — `'` or `$` in
// credentials is the norm (from password generators); unescaped commands run wrong.
func buildAuthCurl(rawURL, method, body, extraHeader string, e authEntry) (string, error) {
	// All values single-quoted with internal single-quotes escaped (the POSIX sh standard:
	// ' -> '\''). That way $ ` " \ in credentials never get interpreted by the shell.
	q := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	parts := []string{"curl", "-sS", "-i", "--max-time", "20"}
	parts = append(parts, "-X", q(method))
	parts = append(parts, q(rawURL))

	if e.Token != "" {
		lowerType := strings.ToLower(e.Type)
		if strings.Contains(lowerType, "cookie") || strings.Contains(lowerType, "session") {
			parts = append(parts, "-H", q("Cookie: "+e.Token))
		} else if strings.Contains(lowerType, "basic") {
			parts = append(parts, "-u", q(e.Token))
		} else {
			parts = append(parts, "-H", q("Authorization: Bearer "+e.Token))
		}
	} else if e.Username != "" && e.Password != "" {
		parts = append(parts, "-u", q(e.Username+":"+e.Password))
	} else if e.Username != "" {
		parts = append(parts, "-u", q(e.Username))
	}

	if strings.TrimSpace(extraHeader) != "" {
		for _, line := range strings.Split(extraHeader, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts = append(parts, "-H", q(line))
		}
	}
	if strings.TrimSpace(body) != "" {
		parts = append(parts, "--data-raw", q(body))
	}
	return strings.Join(parts, " "), nil
}

// Compile-time confirmation that the db package is used (authEntry's fields mirror db.Asset.Auth).
var _ = db.Asset{}

// sessionJarPath returns the task-level cookie jar path (tasks/<id>/shared/sessions/<name>.jar).
// Empty runDir / illegal session name return empty string. The same task dir is reused across intents — log in once, use everywhere.
// (Same implementation as red-team v0.7.0, shipped together with http_request/session_login.)
func (t *ToolSet) sessionJarPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || t.runDir == "" {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return -1
	}, name)
	if clean == "" || len(clean) > 64 {
		return ""
	}
	root := filepath.Dir(t.runDir)
	if filepath.Base(root) == "shared" {
		root = filepath.Dir(root)
	}
	dir := filepath.Join(root, "shared", "sessions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	return filepath.Join(dir, clean+".jar")
}
