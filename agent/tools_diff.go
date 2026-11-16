package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/intercept"
)

// Response-diff tool: computes the **structural differences** between two HTTP responses.
//
// ## Why it's needed
//
// Three core vuln-hunting dimensions all rest on the same action — **comparison**:
//
//   - **Privesc**: access object X as identity A and as identity B, compare responses
//     (A gets 200 + data, B gets 403/empty → privesc holds)
//   - **Enumerable**: request id=1..N one by one, compare 'exists' vs 'doesn't' responses
//     (status/length/JSON key-set differ → enumerable)
//   - **State machine**: call the same endpoint in different states, compare responses (missing precondition checks)
//
// The status quo is the model **hand-writing python diffs** every time — must get it right (JSON key order, nulls,
// nested structures, timestamp noise all need filtering), costs tokens, and produces nothing reusable.
//
// ## Two usages
//
//   A) **File mode**: the model already saved both responses as files (relative paths under the work dir);
//      the tool **reads the files and diffs directly** — no network, no scripts, no requests.
//   B) **URL mode**: responses not fetched yet. The tool writes a diff script into **this run's work dir**
//      and returns a 'fetch both responses + diff' command for Bash to execute.
//      Routing through Bash is deliberate: requests pass through the recording proxy, approval controls, and
//      leave a trail — the same semantics as every other egress on the platform. Self-issuing requests would bypass the whole control chain.
//
// ## Criteria
//
// A difference **isn't a vuln by itself** — timestamps, request ids, random nonces, minor length deltas are all noise.
// The tool **filters noise and keeps only structural differences**, letting the model judge 'is this difference meaningful'.
//
// What's filtered (the explicit noise list):
//   - key **order** differences (semantically identical JSON)
//   - values differing only in **non-structural positions**: timestamps, trace ids, request ids, random strings
//   - key **add/remove** is preserved (the most informative difference — an extra field is often privesc)
//
// Not filtered: status codes, JSON key sets, value types, overall body length.

// diffArgs are the tool's input params.
type diffArgs struct {
	FileA   string `json:"file_a"`
	FileB   string `json:"file_b"`
	URLA    string `json:"url_a"`
	URLB    string `json:"url_b"`
	HeaderA string `json:"header_a"`
	HeaderB string `json:"header_b"`
	StatusA int    `json:"status_a"`
	StatusB int    `json:"status_b"`
}

// responseDiff is the structural difference between two responses.
type responseDiff struct {
	// StatusA / StatusB are the two responses' HTTP status codes (0 = unknown).
	StatusA int `json:"status_a"`
	StatusB int `json:"status_b"`
	// StatusKnown=true means the status codes were genuinely obtained (not 'both missing').
	// When false, SameStatus is meaningless — can't pass 0==0 off as 'statuses equal'.
	StatusKnown bool `json:"status_known"`
	// SameStatus=true means the status codes are equal (only meaningful when StatusKnown is true).
	SameStatus bool `json:"same_status"`
	// LenA / LenB are the response body byte counts.
	LenA int `json:"len_a"`
	LenB int `json:"len_b"`
	// KeysOnlyInA / KeysOnlyInB are JSON top-level keys appearing on only one side.
	KeysOnlyInA []string `json:"keys_only_in_a"`
	KeysOnlyInB []string `json:"keys_only_in_b"`
	// SameShape=true means both sides' JSON top-level key sets are identical (same structure).
	SameShape bool `json:"same_shape"`
	// ValueDiffs holds same-name fields whose values differ (values truncated).
	ValueDiffs []ValueDiff `json:"value_diffs"`
	// NoiseKeys holds fields skipped as noise (values shaped like timestamps/ids/random strings).
	NoiseKeys []string `json:"noise_keys"`
	// Enumerable=true means this set of differences **supports an 'enumerable' judgment** —
	// status codes differ or key sets differ, and it's not a pure length delta.
	Enumerable bool `json:"enumerable"`
	// Note is a one-line hint for the model (what to look at).
	Note string `json:"note"`
}

// ValueDiff is a same-name field's value difference.
type ValueDiff struct {
	Key string `json:"key"`
	// KindA / KindB are the value's type names (string/number/bool/null/object/array).
	KindA string `json:"kind_a"`
	KindB string `json:"kind_b"`
	// PreviewA / PreviewB are truncated value previews (since v0.4.37 raw values are kept — no more masking sensitive fields).
	PreviewA string `json:"preview_a"`
	PreviewB string `json:"preview_b"`
	// Sensitive marks field names that look credential-ish (hint only — values no longer masked).
	Sensitive bool `json:"sensitive"`
}

// diffResponse computes the structural diff of two responses.
func diffResponse(statusA, statusB int, bodyA, bodyB string) responseDiff {
	d := responseDiff{
		StatusA: statusA, StatusB: statusB,
		StatusKnown: statusA != 0 || statusB != 0,
		SameStatus: statusA == statusB,
		LenA:       len(bodyA), LenB: len(bodyB),
	}
	objA, okA := parseJSONObject(bodyA)
	objB, okB := parseJSONObject(bodyB)

	if okA && okB {
		keysA := sortedKeys(objA)
		keysB := sortedKeys(objB)
		setA := map[string]bool{}
		for _, k := range keysA {
			setA[k] = true
		}
		setB := map[string]bool{}
		for _, k := range keysB {
			setB[k] = true
		}
		for _, k := range keysA {
			if !setB[k] {
				d.KeysOnlyInA = append(d.KeysOnlyInA, k)
			}
		}
		for _, k := range keysB {
			if !setA[k] {
				d.KeysOnlyInB = append(d.KeysOnlyInB, k)
			}
		}
		d.SameShape = len(d.KeysOnlyInA) == 0 && len(d.KeysOnlyInB) == 0

		// Compare values key by key.
		for _, k := range keysA {
			if !setB[k] {
				continue
			}
			va, vb := objA[k], objB[k]
			if sameJSONValue(va, vb) {
				continue
			}
			if looksLikeNoise(va) && looksLikeNoise(vb) {
				d.NoiseKeys = append(d.NoiseKeys, k)
				continue
			}
			vd := ValueDiff{
				Key:      k,
				KindA:    jsonKind(va),
				KindB:    jsonKind(vb),
				PreviewA: valuePreview(va),
				PreviewB: valuePreview(vb),
				Sensitive: isSensitiveKey(k),
			}
			d.ValueDiffs = append(d.ValueDiffs, vd)
		}
	} else {
		// Non-JSON (HTML/text): can only compare length and equality.
		d.SameShape = strings.TrimSpace(bodyA) == strings.TrimSpace(bodyB)
	}

	sort.Strings(d.KeysOnlyInA)
	sort.Strings(d.KeysOnlyInB)
	sort.Strings(d.NoiseKeys)

	// Enumerable judgment: status codes differ, or key sets differ — a pure minor length delta doesn't count.
	// Unknown status doesn't participate (can't pass 0==0 off as 'statuses equal').
	d.Enumerable = (d.StatusKnown && !d.SameStatus) ||
		len(d.KeysOnlyInA) > 0 || len(d.KeysOnlyInB) > 0

	switch {
	case !d.StatusKnown:
		d.Note = "**Status code unknown** (not provided and no HTTP header in the response) — check key-set differences first; " +
			"to judge enumerability, supply the status code or save the full response with curl -i."
	case !d.SameStatus:
		d.Note = "Status codes differ — if one is 200 and the other 403/404 and **the same identity** made both requests, " +
			"the object's visibility differs for the current identity (lateral privesc or enumerable)."
	case len(d.KeysOnlyInA) > 0 || len(d.KeysOnlyInB) > 0:
		d.Note = "Key sets differ — the extra fields are often **fields you shouldn't see** (data obtained via privesc). " +
			"Look at what the extra keys are."
	case len(d.ValueDiffs) > 0:
		d.Note = "Same structure, different values — if the differing field is permission/status-ish (role/status/owner/level), " +
			"the same endpoint returns different content for different objects (privesc). Business data values are normal."
	default:
		d.Note = "No structural differences (all differences live in noise fields) — the two responses are semantically equivalent."
	}
	return d
}

// parseJSONObject tries to parse a body into a JSON object.
func parseJSONObject(body string) (map[string]any, bool) {
	body = strings.TrimSpace(body)
	if body == "" || (body[0] != '{' && body[0] != '[') {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return nil, false
	}
	return m, true
}

// sortedKeys returns the keys sorted.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sameJSONValue judges whether two JSON values are equal.
//
// **Type-sensitive**: number 1 ≠ string "1" (an fmt.Sprintf comparison would wrongly judge them equal —
// the model would miss the 'field type changed' structural difference). Objects/arrays use DeepEqual
// (map fmt output order is random — byte comparison would misfire).
func sameJSONValue(a, b any) bool {
	if jsonKind(a) != jsonKind(b) {
		return false
	}
	switch av := a.(type) {
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case nil:
		return true
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	default:
		return reflect.DeepEqual(a, b)
	}
}

// noiseValuePatterns are the criteria for 'value looks like noise'.
//
// They match the **value's shape**, not the key name — because timestamp/id fields have endlessly varied
// key names (created_at / ts / requestId / _id / trace…) — filtering by key name would miss them.
var noiseValuePatterns = []string{
	`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`, // ISO timestamp
	`^\d{10,13}$`, // millis/seconds timestamp
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, // UUID
	`^[0-9a-f]{16,}$`,            // long hex (trace id / hash)
	`^[A-Za-z0-9+/]{20,}={0,2}$`, // base64 string
}

// noiseValueRe is compiled from noiseValuePatterns (package-level init — avoids recompiling per call).
var noiseValueRe = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(noiseValuePatterns))
	for _, p := range noiseValuePatterns {
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}()

// looksLikeNoise judges whether a value 'looks noise-shaped'.
//
// Only when **both sides** look like noise is it a noise difference (one-sided noise means the other side's value is meaningful).
func looksLikeNoise(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, re := range noiseValueRe {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// sensitiveWords are 'this word alone suffices to judge it a credential'.
//
// Deliberately **excludes** `key` and `session`:
//   - bare `key` is mostly a business field (cache_key / sort_key / object_key / key_id)
//   - bare `session` likewise (session_count / session_duration)
// A false positive's cost is **harmful**: a real value gets masked and the model can't judge the difference.
// Those two words are handled by the qualifier rules below (api_key / session_id).
var sensitiveWords = map[string]bool{
	"token": true, "jwt": true, "password": true, "passwd": true, "pwd": true,
	"passphrase": true, "secret": true, "credential": true, "credentials": true,
	"cookie": true, "authorization": true,
	// All-caps run-together forms (APIKEY / SECRETKEY) — tokenize into one whole word.
	"apikey": true, "secretkey": true, "privatekey": true, "accesskey": true,
	"authkey": true, "sessionkey": true, "clientsecret": true,
}

// keyQualifiers are the qualifiers for 'key preceded by these words counts as a credential'.
var keyQualifiers = map[string]bool{
	"api": true, "secret": true, "private": true, "access": true,
	"encryption": true, "signing": true, "master": true, "client": true,
	"app": true, "csrf": true, "xsrf": true, "auth": true,
}

// sensitiveSuffixes are the suffixes for 'session/auth followed by these words counts as a credential'.
// session_count / session_duration aren't in it — those are business counters, not credentials.
var sensitiveSuffixes = map[string]bool{
	"id": true, "key": true, "token": true, "value": true,
	"secret": true, "header": true, "credential": true,
}

// isSensitiveKey judges whether a key name looks credential-ish.
func isSensitiveKey(k string) bool {
	words := splitKeyWords(k)
	for i, w := range words {
		if sensitiveWords[w] {
			return true
		}
		if w == "key" && i > 0 && keyQualifiers[words[i-1]] {
			return true
		}
		if (w == "session" || w == "auth") && i+1 < len(words) && sensitiveSuffixes[words[i+1]] {
			return true
		}
	}
	return false
}

// splitKeyWords splits a key name into lowercase words.
//
// Three kinds of split points, all required:
//   - separators: access_token → [access, token]
//   - camelCase turns: accessToken → [access, token]
//   - an all-caps run followed by lowercase: APIKey → [api, key]
//
// Trailing digits are stripped (token2 → token) — many backends number their fields.
func splitKeyWords(k string) []string {
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, strings.TrimRight(string(cur), "0123456789"))
			cur = cur[:0]
		}
	}
	runes := []rune(k)
	for i, ch := range runes {
		if ch == '_' || ch == '-' || ch == '.' || ch == ' ' {
			flush()
			continue
		}
		if unicode.IsUpper(ch) && len(cur) > 0 {
			prev := cur[len(cur)-1]
			var next rune
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			// an all-caps run followed by lowercase → split before the current letter (APIKey → API | Key)
			if unicode.IsUpper(prev) && unicode.IsLower(next) {
				flush()
			} else if !unicode.IsUpper(prev) {
				// normal camelCase (accessToken → access | Token)
				flush()
			}
		}
		cur = append(cur, ch)
	}
	flush()
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, strings.ToLower(p))
	}
	return out
}

// jsonKind returns a JSON value's type name.
func jsonKind(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return "unknown"
	}
}

// valuePreview renders a truncated preview of a value (60 chars).
func valuePreview(v any) string {
	s := fmt.Sprintf("%v", v)
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// diffResponses assembles a diff command (or computes the diff directly) for the model.
//
// **Only assembles commands / reads files — never sends requests itself** — the same
// pattern as scan_with_nuclei and auth_request. All requests go out via Bash, so traffic recording,
// approval controls and auditing all apply automatically; self-issuing requests would bypass the whole control chain.
//
// Two modes:
//   a) file mode (file_a/file_b): the tool reads the files and diffs directly — zero network, zero scripts.
//   b) URL mode (url_a/url_b): the tool writes the diff script into the work dir and returns a
//      'fetch both responses and diff' command.
func (t *ToolSet) diffResponses() actool.CoreTool {
	return readTool(
		"diff_responses",
		"Compares the **structural differences** between two HTTP responses (the common base for privesc/enumerable/state-machine judgments).\n"+
			"Usage — pick one:\n"+
			"  A) Both responses already saved as files → pass file_a / file_b (relative paths resolve against this run's work dir; "+
			"absolute paths also accepted; a full response saved via curl -i is auto-stripped of HTTP headers and its status code extracted)\n"+
			"  B) Not fetched yet → pass url_a / url_b (+ optional header_a/header_b); the tool generates a "+
			"'fetch both responses and diff' command for Bash to run\n"+
			"Output: whether status codes match, the JSON top-level key-set difference (**keys on only one side are often privesc-obtained fields**), "+
			"value differences on same-name fields (timestamp/id-shaped values are marked noise and skipped), "+
			"and whether this difference set supports an 'enumerable' judgment.\n"+
			"**A difference isn't a vuln by itself** — timestamp/trace-id/random-string noise is already filtered; judge the rest against semantics.",
		obj(map[string]any{
			"file_a":   str("file path of response A (an already-fetched response body; relative paths resolve against this run's work dir)"),
			"file_b":   str("file path of response B"),
			"url_a":    str("URL of response A (when not yet fetched)"),
			"url_b":    str("URL of response B"),
			"header_a": str("auth header for request A (e.g. 'Authorization: Bearer xxx', optional)"),
			"header_b": str("auth header for request B (optional)"),
			"status_a": intp("status code of response A (if known, optional)"),
			"status_b": intp("status code of response B (optional)"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a diffArgs
			_ = json.Unmarshal(in, &a)

			hasFiles := strings.TrimSpace(a.FileA) != "" && strings.TrimSpace(a.FileB) != ""
			hasURLs := strings.TrimSpace(a.URLA) != "" && strings.TrimSpace(a.URLB) != ""
			if !hasFiles && !hasURLs {
				return actool.Errorf("provide file_a+file_b (response files already fetched) or url_a+url_b (not fetched yet)"), nil
			}

			workDir := intercept.ReviewWorkingDirectory(ctx)

			if hasFiles {
				// Files at hand: read them and diff directly (no network, no scripts).
				bodyA, statusA, err := readResponseFile(workDir, a.FileA)
				if err != nil {
					return actool.Errorf("failed to read response A: " + err.Error()), nil
				}
				bodyB, statusB, err := readResponseFile(workDir, a.FileB)
				if err != nil {
					return actool.Errorf("failed to read response B: " + err.Error()), nil
				}
				// A model-provided status code wins (the file header's may be rewritten by middleware).
				if a.StatusA != 0 {
					statusA = a.StatusA
				}
				if a.StatusB != 0 {
					statusB = a.StatusB
				}
				d := diffResponse(statusA, statusB, bodyA, bodyB)
				return jsonResult(map[string]any{
					"diff":   d,
					"source": fmt.Sprintf("read files %s / %s", a.FileA, a.FileB),
					"note": "output is JSON: status codes, key-set differences, value diffs (noise filtered, credentials kept raw), " +
						"enumerable support. **A difference isn't a vuln by itself** — judge against semantics " +
						"(extra keys are often privesc-obtained data).",
				})
			}

			// Responses not fetched: need the work dir to place the diff script.
			if workDir == "" {
				return actool.Errorf("this run has no work dir bound — can't write the diff script; " +
					"use file mode instead (fetch both responses via Bash and save as files, then pass file_a/file_b)"), nil
			}
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				return actool.Errorf("failed to create work dir: " + err.Error()), nil
			}
			scriptPath, err := WriteDiffScript(workDir)
			if err != nil {
				return actool.Errorf("failed to write the diff script: " + err.Error()), nil
			}
			cmd := buildDiffScript(a, scriptPath, workDir)
			return jsonResult(map[string]any{
				"run_with_bash": cmd,
				"script_path":   scriptPath,
				"note": "run the command above with the Bash tool (it fetches both responses and does the structural diff). Output is JSON. " +
					"**A difference isn't a vuln by itself** — judge against semantics.",
			})
		},
	)
}

// maxResponseFileBytes is the per-file read cap for diff file mode (16MB).
const maxResponseFileBytes = 16 << 20

// readResponseFile reads a response file, returning (body, status code).
//
// Tolerant: a file saved by `curl -i` (full response with HTTP headers) gets its headers stripped
// and the status code taken from the status line. An explicit model-provided status code wins.
func readResponseFile(workDir, p string) (string, int, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", 0, fmt.Errorf("empty path")
	}
	full := p
	if !filepath.IsAbs(p) {
		if workDir == "" {
			return "", 0, fmt.Errorf("no work dir bound — can't resolve relative path %q; pass an absolute path", p)
		}
		full = filepath.Join(workDir, p)
	}
	// Stat for type before opening: open(2) on a FIFO with no writer blocks until a writer appears —
	// Stat would never return. The anti-hang check must happen before opening.
	if st, err := os.Stat(full); err == nil && !st.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%q is not a regular file — read refused", p)
	}
	f, err := os.Open(full)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if !st.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%q is not a regular file — read refused", p)
	}
	if st.Size() > maxResponseFileBytes {
		return "", 0, fmt.Errorf("response file too large (%d bytes, cap %d): trim to the relevant part and compare again", st.Size(), maxResponseFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxResponseFileBytes+1))
	if err != nil {
		return "", 0, err
	}
	if len(b) > maxResponseFileBytes {
		return "", 0, fmt.Errorf("response file exceeds the %d-byte cap", maxResponseFileBytes)
	}
	body, status := stripHTTPHeader(string(b))
	return body, status, nil
}

// stripHTTPHeader strips HTTP headers at the start of a response file, returning (body, status code).
//
// When the status code can't be determined, 0 (= unknown) is returned — never guessed.
func stripHTTPHeader(raw string) (string, int) {
	trimmed := strings.TrimLeft(raw, " \t\r\n")
	if !strings.HasPrefix(trimmed, "HTTP/") {
		return raw, 0
	}
	// status line: HTTP/1.1 200 OK
	firstNL := strings.IndexAny(trimmed, "\r\n")
	if firstNL < 0 {
		return raw, 0
	}
	statusLine := trimmed[:firstNL]
	fields := strings.Fields(statusLine)
	status := 0
	if len(fields) >= 2 {
		if n, err := strconv.Atoi(fields[1]); err == nil {
			status = n
		}
	}
	rest := trimmed[firstNL:]
	// find the header/body separator (blank line)
	for _, sep := range []string{"\r\n\r\n", "\n\n", "\r\r"} {
		if i := strings.Index(rest, sep); i >= 0 {
			return rest[i+len(sep):], status
		}
	}
	return raw, status
}

// diffScriptName is the diff script's filename inside the agent work dir.
//
// The platform writes the script at runtime (see WriteDiffScript); the agent only executes it.
const diffScriptName = "resp_diff.py"

// buildDiffScript builds the shell command 'fetch both responses + diff'.
//
// Three key points:
//   - Response bodies land in files under the **work dir** (not /tmp — platform rule: intermediates never go to /tmp).
//   - The status code comes from curl's -w '%{http_code}', passed in as a script arg.
//   - URL/auth headers get POSIX single-quote escaping — auth headers often contain quotes.
func buildDiffScript(a diffArgs, scriptPath, workDir string) string {
	bodyA := filepath.Join(workDir, "resp_a_body")
	bodyB := filepath.Join(workDir, "resp_b_body")
	fetch := func(url, header, out string) string {
		parts := []string{"curl", "-sS", "--max-time", "20", "-o", quoteShell(out), "-w", "%{http_code}", quoteShell(url)}
		if strings.TrimSpace(header) != "" {
			parts = append(parts, "-H", quoteShell(header))
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprintf(
		"S=$(%s) ; T=$(%s) ; python3 %s %s %s \"$S\" \"$T\"",
		fetch(a.URLA, a.HeaderA, bodyA),
		fetch(a.URLB, a.HeaderB, bodyB),
		quoteShell(scriptPath), quoteShell(bodyA), quoteShell(bodyB))
}

// quoteShell wraps a value in POSIX single quotes (inner single quotes escaped as '\'').
func quoteShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// WriteDiffScript writes the diff script into the work dir, returning its path.
//
// The script uses stdlib json (no third-party deps) and does the same thing as the Go-side diffResponse:
// computes status/key-set/value diffs, filters noise fields, and keeps credential-class field values intact.
//
// The two implementations must be equivalent — agent/tools_diff_test.go has a real-python comparison test.
func WriteDiffScript(dir string) (string, error) {
	path := filepath.Join(dir, diffScriptName)
	if err := os.WriteFile(path, []byte(diffScriptSource), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// diffScriptSource is the diff script's source code (equivalent to the Go-side logic).
const diffScriptSource = `#!/usr/bin/env python3
"""Structured response diff (the executor side of the POJUN agent tool diff_responses).

Usage: resp_diff.py <fileA> <fileB> [statusA] [statusB]
File contents are response bodies (or a curl -i full response — headers are stripped automatically); status codes optional.
JSON output: status codes, key-set differences, value diffs (timestamp/id noise filtered), enumerable support.
"""
import json, re, sys

NOISE = [
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    re.compile(r"^\d{10,13}$"),
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    re.compile(r"^[0-9a-f]{16,}$"),
    re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),
]
SENSITIVE_WORDS = {
    "token", "jwt", "password", "passwd", "pwd", "passphrase", "secret",
    "credential", "credentials", "cookie", "authorization",
    "apikey", "secretkey", "privatekey", "accesskey", "authkey",
    "sessionkey", "clientsecret",
}
KEY_QUALIFIERS = {
    "api", "secret", "private", "access", "encryption", "signing",
    "master", "client", "app", "csrf", "xsrf", "auth",
}
SENSITIVE_SUFFIXES = {
    "id", "key", "token", "value", "secret", "header", "credential",
}


def split_words(k):
    """Split a key name into lowercase words: separators / camelCase turns / all-caps-run-followed-by-lowercase are all breakpoints."""
    parts, cur = [], []

    def flush():
        if cur:
            parts.append("".join(cur).rstrip("0123456789"))
            del cur[:]

    runes = list(k)
    for i, ch in enumerate(runes):
        if ch in "_-. ":
            flush()
            continue
        if ch.isupper() and cur:
            prev = cur[-1]
            nxt = runes[i + 1] if i + 1 < len(runes) else ""
            if prev.isupper() and nxt.islower():
                flush()
            elif not prev.isupper():
                flush()
        cur.append(ch)
    flush()
    return [p.lower() for p in parts if p]


def is_sensitive_key(k):
    words = split_words(k)
    for i, w in enumerate(words):
        if w in SENSITIVE_WORDS:
            return True
        if w == "key" and i > 0 and words[i - 1] in KEY_QUALIFIERS:
            return True
        if w in ("session", "auth") and i + 1 < len(words) and words[i + 1] in SENSITIVE_SUFFIXES:
            return True
    return False


def load(p):
    try:
        with open(p, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def strip_http_header(raw):
    t = raw.lstrip(" \t\r\n")
    if not t.startswith("HTTP/"):
        return raw, 0
    i = t.find("\n")
    if i < 0:
        return raw, 0
    fields = t[:i].split()
    status = 0
    if len(fields) >= 2:
        try:
            status = int(fields[1])
        except ValueError:
            status = 0
    rest = t[i:]
    for sep in ("\r\n\r\n", "\n\n", "\r\r"):
        j = rest.find(sep)
        if j >= 0:
            return rest[j + len(sep):], status
    return raw, status


def as_obj(s):
    s = s.strip()
    if not s or s[0] not in "{[":
        return None
    try:
        v = json.loads(s)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def kind(v):
    if v is None: return "null"
    if isinstance(v, bool): return "bool"
    if isinstance(v, (int, float)): return "number"
    if isinstance(v, str): return "string"
    if isinstance(v, dict): return "object"
    if isinstance(v, list): return "array"
    return "unknown"


def same_value(a, b):
    if kind(a) != kind(b):
        return False
    if kind(a) == "number":
        return float(a) == float(b)
    return a == b


def is_noise(v):
    if not isinstance(v, str):
        return False
    s = v.strip()
    if not s:
        return False
    return any(r.match(s) for r in NOISE)


def preview(v, limit=60):
    s = str(v)
    return s if len(s) <= limit else s[:limit] + "…"


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: resp_diff.py <fileA> <fileB> [statusA] [statusB]"}))
        return 1
    sa = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    sb = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    raw_a, raw_b = load(sys.argv[1]), load(sys.argv[2])
    a, st_a = strip_http_header(raw_a)
    b, st_b = strip_http_header(raw_b)
    if sa == 0:
        sa = st_a
    if sb == 0:
        sb = st_b
    status_known = sa != 0 or sb != 0
    out = {
        "status_a": sa, "status_b": sb,
        "status_known": status_known,
        "same_status": sa == sb,
        "len_a": len(a), "len_b": len(b),
        "keys_only_in_a": [], "keys_only_in_b": [],
        "same_shape": False, "value_diffs": [], "noise_keys": [],
    }
    oa, ob = as_obj(a), as_obj(b)
    if oa is not None and ob is not None:
        ka, kb = set(oa), set(ob)
        out["keys_only_in_a"] = sorted(ka - kb)
        out["keys_only_in_b"] = sorted(kb - ka)
        out["same_shape"] = not out["keys_only_in_a"] and not out["keys_only_in_b"]
        for k in sorted(ka & kb):
            va, vb = oa[k], ob[k]
            if same_value(va, vb):
                continue
            if is_noise(va) and is_noise(vb):
                out["noise_keys"].append(k)
                continue
            d = {"key": k, "kind_a": kind(va), "kind_b": kind(vb),
                 "preview_a": preview(va), "preview_b": preview(vb),
                 "sensitive": is_sensitive_key(k)}
            out["value_diffs"].append(d)
    else:
        out["same_shape"] = a.strip() == b.strip()
    out["enumerable"] = ((status_known and not out["same_status"])
                         or bool(out["keys_only_in_a"]) or bool(out["keys_only_in_b"]))
    if not status_known:
        out["note"] = "status code unknown — check key-set differences first; for enumerability, supply the status code or save the full response with curl -i"
    elif not out["same_status"]:
        out["note"] = "status codes differ — if the same identity accessed different objects, possibly privesc or enumerable"
    elif out["keys_only_in_a"] or out["keys_only_in_b"]:
        out["note"] = "key sets differ — extra fields are often data you shouldn't see (privesc)"
    elif out["value_diffs"]:
        out["note"] = "same structure, different values — check whether the differing field is permission/status-ish"
    else:
        out["note"] = "no structural differences"
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
`
