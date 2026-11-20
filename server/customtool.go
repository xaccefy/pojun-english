package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/intercept"
)

// This file implements the custom-tool executor (docs/Custom Tool Design.md). tools rows
// with system=false are dispatched by kind: command (render command → reuse Bash's
// underlying run), script (Python only; writes a temp file, stdin=param JSON + env
// TOOL_*, uses the configured interpreter), http (native request + optional proxy).
// These tools need no seeding like traffic/orchestration tools (they already live in
// the tools table) — injected via hostTools and filtered by binding.

// ---------- custom-tool CRUD ----------

type customToolReq struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Enabled     bool            `json:"enabled"`
	Kind        string          `json:"kind"` // command | script | http
	Exec        json.RawMessage `json:"exec"`
	Deferred    bool            `json:"deferred"`
}

var reToolKey = reAgentKey // same rules as agent keys: lowercase start + lowercase letters/digits/underscores

func (s *Server) pgCreateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if !reToolKey.MatchString(req.Key) {
		writeErr(w, 400, "key must start with a lowercase letter and contain only lowercase letters/digits/underscores")
		return
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		writeErr(w, 400, "kind must be command / script / http / shell")
		return
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		writeErr(w, 400, "http tools must provide a parameter JSON Schema (cannot be empty)")
		return
	}
	if exist, _ := pg.GetTool(req.Key); exist != nil {
		writeErr(w, 409, "key already exists (built-in or custom tool)")
		return
	}
	if err := pg.CreateCustomTool(&db.Tool{
		Key: req.Key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if req.Kind != "shell" {
		s.ensureInterceptToolEnabled(req.Key)
	}
	writeJSON(w, 200, map[string]any{"key": req.Key})
}

func (s *Server) pgUpdateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	existing, err := pg.GetTool(key)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if existing == nil || existing.System {
		writeErr(w, 400, "only custom tools can be edited")
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		writeErr(w, 400, "kind must be command / script / http / shell")
		return
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		writeErr(w, 400, "http tools must provide a parameter JSON Schema (cannot be empty)")
		return
	}
	if err := pg.UpdateCustomTool(&db.Tool{
		Key: key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if req.Kind != "shell" {
		s.ensureInterceptToolEnabled(key)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) pgDeleteCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	if err := pg.DeleteCustomTool(key); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": key})
}

// testToolReq is a dry-run request from the editor: run the given (possibly unsaved)
// exec spec with sample params, without persisting the tool. Same executor path as a
// real tool call — it runs arbitrary command/script/http on the server, which the
// custom-tool feature already allows, so no new capability is granted.
type testToolReq struct {
	Kind   string          `json:"kind"` // command | script | http
	Exec   json.RawMessage `json:"exec"`
	Params map[string]any  `json:"params"`
}

// pgTestCustomTool executes an exec spec once and returns its raw output + error
// flag, so the editor can debug a tool before saving it. Per-kind timeouts still
// apply from the exec spec (with defaults); the outer ceiling is a hard backstop.
func (s *Server) pgTestCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req testToolReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid request body")
		return
	}
	params := req.Params
	if params == nil {
		params = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	tc := &actool.ToolContext{WorkingDir: s.m.dir} // run in the project dir, like a real call
	var res actool.Result
	switch req.Kind {
	case "command":
		res, _ = s.runCommandTool(ctx, req.Exec, params, tc)
	case "script":
		res, _ = s.runScriptTool(ctx, "test", req.Exec, params, tc)
	case "http":
		res, _ = s.runHTTPTool(ctx, req.Exec, params, tc)
	case "shell":
		writeErr(w, 400, "shell tools are bash environment declarations — nothing executable")
		return
	default:
		writeErr(w, 400, "unknown tool kind: "+req.Kind)
		return
	}
	writeJSON(w, 200, map[string]any{"output": res.Flatten(), "is_error": res.IsError})
}

// ---------- Python interpreter (detect + persist + override) ----------

const settingPythonInterp = "python_interpreter"

// detectPython finds a python interpreter absolute path (python3 preferred).
func detectPython() string {
	for _, c := range []string{"python3", "python"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// pythonInterpreter resolves the interpreter: user-set > stored auto-detect > live
// detect. "" only when truly none found.
func (s *Server) pythonInterpreter() string {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return detectPython()
}

// seedPythonInterpreter stores the auto-detected interpreter on startup if unset
// (never clobbers a user-set value).
func (s *Server) seedPythonInterpreter() {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return
	}
	if p := detectPython(); p != "" {
		if err := s.m.pg.SetSetting(settingPythonInterp, p); err != nil {
			log.Printf("[custom-tool] detected python interpreter %s but failed to persist: %v (will re-detect per call)", p, err)
		} else {
			log.Printf("[custom-tool] auto-detected python interpreter: %s", p)
		}
	}
}

// ---------- exec spec ----------

type commandExec struct {
	Command   string `json:"command"`
	TimeoutMs int    `json:"timeout_ms"`
}
type scriptExec struct {
	Code      string `json:"code"`
	TimeoutMs int    `json:"timeout_ms"`
}
type httpExec struct {
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	TimeoutMs         int               `json:"timeout_ms"`
	Proxy             string            `json:"proxy"`
	UseRecordingProxy bool              `json:"use_recording_proxy"`
}

func timeoutOr(ms, def int) time.Duration {
	if ms <= 0 {
		return time.Duration(def) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

// ---------- generic tool construction ----------

// customTools builds CoreTools for every user-defined (system=false) tool row.
// shell-kind tools are environment hints only — they surface in the Bash tool
// description via ToolResolve and do NOT create callable tool entries here.
func (s *Server) customTools() ([]actool.CoreTool, error) {
	rows, err := s.m.pg.ListCustomTools()
	if err != nil {
		return nil, err
	}
	out := make([]actool.CoreTool, 0, len(rows))
	for _, t := range rows {
		if t.Kind == "shell" {
			continue // shell hints are handled by ToolResolve → Bash description
		}
		out = append(out, s.buildCustomTool(t))
	}
	return out, nil
}

// buildCustomTool turns one custom-tool row into a CoreTool. Empty schema → a thin
// {args:string} (thin-shell tools), so command/http templates can use {args}.
func (s *Server) buildCustomTool(t *db.Tool) actool.CoreTool {
	schema := ensureSchema(t.Schema)
	key, kind, execRaw := t.Key, t.Kind, t.Exec
	run := func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
		var params map[string]any
		if len(in) > 0 {
			_ = json.Unmarshal(in, &params)
		}
		if params == nil {
			params = map[string]any{}
		}
		switch kind {
		case "command":
			return s.runCommandTool(ctx, execRaw, params, tc)
		case "script":
			return s.runScriptTool(ctx, key, execRaw, params, tc)
		case "http":
			return s.runHTTPTool(ctx, execRaw, params, tc)
		default:
			return actool.Errorf("unknown custom-tool kind: " + kind), nil
		}
	}
	return actool.Build(actool.Spec{
		Name: key, Description: t.Description, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: run,
	})
}

// hasSchemaProps reports whether raw is a JSON-Schema object with ≥1 property.
// http tools require an explicit schema (the auto {args} shell can't name the
// {param} placeholders in URL/headers/body), so an empty schema is rejected.
func hasSchemaProps(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	props, _ := m["properties"].(map[string]any)
	return len(props) > 0
}

// ensureSchema returns the tool's schema, or a thin {args:string} when none given.
func ensureSchema(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	props, _ := m["properties"].(map[string]any)
	if len(props) > 0 {
		return m
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"args": map[string]any{"type": "string", "description": "command/arguments (free text)"},
		},
	}
}

// ---------- command: render command → reuse Bash's underlying run ----------

func (s *Server) runCommandTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec commandExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Command) == "" {
		return actool.Errorf("command is empty"), nil
	}
	cmd := renderTemplate(spec.Command, params, shellQuote)
	// reuse the same underlying run Bash uses (via Bash CoreTool.Call): inherits the
	// safety floor / timeouts / proxy env / output overflow for free. The tool sits
	// beside Bash sharing the substrate — the model doesn't go through Bash.
	// Interception: the PreToolUse hook sees this call under the custom tool's own
	// name+params — deny/ask rules on the *rendered command* (rm -rf, exfil pipes)
	// would never see the actual shell text, so evaluate it here as Bash too.
	if msg := s.evalInterceptForCustomCommand(ctx, cmd); msg != "" {
		return actool.Errorf(msg), nil
	}
	bashIn, _ := json.Marshal(map[string]any{"command": cmd})
	if spec.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 120000))
		defer cancel()
	}
	return actool.NewBash().Call(ctx, bashIn, tc)
}

// ---------- script (Python only): temp file + stdin JSON + env ----------

func (s *Server) runScriptTool(ctx context.Context, key string, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec scriptExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Code) == "" {
		return actool.Errorf("script code is empty"), nil
	}
	interp := s.pythonInterpreter()
	if interp == "" {
		return actool.Errorf("no python interpreter configured or detected (set one in system settings)"), nil
	}
	workDir := s.m.dir
	var sessionEnv []string
	if tc != nil {
		if tc.WorkingDir != "" {
			workDir = tc.WorkingDir
		}
		sessionEnv = tc.Env
	}
	body, err := execPython(ctx, interp, key, spec.Code, params, workDir, sessionEnv, timeoutOr(spec.TimeoutMs, 120000))
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(actool.Capture(tc, body)), nil
}

// execPython writes the code to a temp .py under workDir/.tools, runs it via interp
// with the params JSON on stdin + scalar params mirrored to TOOL_<NAME> env, and
// returns combined stdout+stderr (with a timeout/exit note). Standalone + testable.
func execPython(ctx context.Context, interp, key, code string, params map[string]any, workDir string, sessionEnv []string, timeout time.Duration) (string, error) {
	toolsDir := filepath.Join(workDir, ".tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(toolsDir, key+"-*.py")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.WriteString(code); err != nil {
		f.Close()
		return "", err
	}
	f.Close()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(runCtx, interp, tmp)
	c.Dir = workDir
	c.Env = append(os.Environ(), sessionEnv...) // session proxy env
	for k, v := range params {                  // scalar params mirrored to TOOL_<NAME>
		if sv, ok := scalarStr(v); ok {
			c.Env = append(c.Env, "TOOL_"+strings.ToUpper(k)+"="+sv)
		}
	}
	pj, _ := json.Marshal(params)
	c.Stdin = bytes.NewReader(pj) // param JSON over stdin
	out, err := c.CombinedOutput()
	body := string(out)
	if runCtx.Err() == context.DeadlineExceeded {
		body += "\n... [killed on timeout] ..."
	} else if err != nil {
		body += "\n[exit: " + err.Error() + "]"
	}
	return body, nil
}

// ---------- http: native request + proxy ----------

func (s *Server) runHTTPTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec httpExec
	_ = json.Unmarshal(execRaw, &spec)
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}
	rawURL := renderTemplate(spec.URL, params, identity)
	if strings.TrimSpace(rawURL) == "" {
		return actool.Errorf("http url is empty"), nil
	}
	var bodyReader io.Reader
	if spec.Body != "" {
		bodyReader = strings.NewReader(renderTemplate(spec.Body, params, identity))
	}
	runCtx, cancel := context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 30000))
	defer cancel()
	req, err := http.NewRequestWithContext(runCtx, method, rawURL, bodyReader)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	for k, v := range spec.Headers {
		req.Header.Set(k, renderTemplate(v, params, identity))
	}
	client := &http.Client{Timeout: timeoutOr(spec.TimeoutMs, 30000)}
	tr := s.httpProxyTransport(spec)
	if tr == nil {
		// 没有显式代理配置时走平台出口，而不是从平台真实 IP 直连目标。
		tr = s.platformProxyTransport()
	}
	if tr != nil {
		client.Transport = tr
	}
	resp, err := client.Do(req)
	if err != nil {
		return actool.Errorf("request failed: " + err.Error()), nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := map[string]any{"status": resp.StatusCode, "body": string(respBody)}
	b, _ := json.Marshal(out)
	return actool.Text(actool.Capture(tc, string(b))), nil
}

// platformProxyTransport returns the platform's default egress path: the
// recording proxy while traffic capture is on, else the proxy pool or a
// configured global proxy. Nil means no egress proxy is configured (direct) —
// or the Server carries no manager (tests).
func (s *Server) platformProxyTransport() *http.Transport {
	if s.m == nil {
		return nil
	}
	return proxyTransport(s.m.ProxyAddr(), s.m.ProxyCACert())
}

// httpProxyTransport builds a Transport for the http tool's explicit proxy
// config, or nil when the tool sets none. use_recording_proxy forces the
// recording proxy (and trusts its CA); an explicit proxy URL is used as given.
func (s *Server) httpProxyTransport(spec httpExec) *http.Transport {
	if spec.UseRecordingProxy && s.m != nil {
		if addr := s.m.ProxyAddr(); addr != "" {
			return proxyTransport(addr, s.m.ProxyCACert())
		}
	}
	if p := strings.TrimSpace(spec.Proxy); p != "" {
		return proxyTransport(p, "")
	}
	return nil
}

// proxyTransport routes requests through addr, accepting both "host:port" and
// "scheme://host:port" spellings. caFile is trusted when the proxy re-signs TLS
// (recording MITM). Nil when addr is empty or unusable.
func proxyTransport(addr, caFile string) *http.Transport {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	pu, err := url.Parse(addr)
	if err != nil || pu.Host == "" {
		return nil
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu)}
	if caFile != "" {
		if pem, err := os.ReadFile(caFile); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	return tr
}

// ---------- helpers ----------

func identity(s string) string { return s }

// shellQuote single-quotes a value for safe shell interpolation.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// renderTemplate replaces {name} placeholders with each param's rendered value.
func renderTemplate(tmpl string, params map[string]any, quote func(string) string) string {
	out := tmpl
	for k, v := range params {
		out = strings.ReplaceAll(out, "{"+k+"}", quote(valToStr(v)))
	}
	return out
}

// valToStr renders a param value: scalars as-is, arrays/objects as compact JSON.
func valToStr(v any) string {
	if sv, ok := scalarStr(v); ok {
		return sv
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// scalarStr returns (string, true) for scalar values, ("", false) for arrays/objects.
func scalarStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return fmt.Sprintf("%t", x), true
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x)), true
		}
		return fmt.Sprintf("%g", x), true
	case nil:
		return "", true
	default:
		return "", false
	}
}

// ---------- interception wiring ----------

// ensureInterceptToolEnabled merges names into the intercept-enabled set so the
// new custom tool's calls face rule matching + judge. A command/script/http
// custom tool that never enters interception is a silent bypass — creation is
// the right moment to wire it in. With no persisted list the code defaults are
// materialized first so the resulting set stays complete rather than holding
// only the new key. Best-effort: a failed merge logs and continues (the tool
// still works; an operator can add the key manually in tool-config).
func (s *Server) ensureInterceptToolEnabled(names ...string) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	raw, ok, err := pg.GetSetting("intercept_enabled_tools")
	if err != nil {
		log.Printf("[custom-tool] enabled-tools read failed: %v", err)
		return
	}
	if !ok {
		b, _ := json.Marshal(intercept.DefaultEnabledTools())
		raw = string(b)
	}
	merged, changed := pg.MergeEnabledInterceptTools(raw, names...)
	if !changed {
		return
	}
	if err := pg.SetSetting("intercept_enabled_tools", merged); err != nil {
		log.Printf("[custom-tool] enabled-tools persist failed: %v", err)
		return
	}
	s.m.interceptor.Invalidate()
}

// evalInterceptForCustomCommand runs the rendered command through interception
// under the "Bash" name. A command-kind custom tool reaches the PreToolUse hook
// under its own key+params — deny/ask rules on command *content* (rm -rf, exfil
// pipes, destructive ops) would never see the actual shell text, so the rendered
// command is evaluated here exactly as a real Bash call would be. Honors the
// operator's tool-config: if Bash interception is disabled, evaluation is
// skipped. Returns "" to proceed, or the block message to surface as a tool
// error. Mirrors guard.applyIntercept's decision flow.
func (s *Server) evalInterceptForCustomCommand(ctx context.Context, cmd string) string {
	ic := s.m.interceptor
	if ic == nil || !ic.IsToolEnabled("Bash") {
		return ""
	}
	bashIn, _ := json.Marshal(map[string]any{"command": cmd})
	ctx = intercept.WithCall(ctx, "Bash", bashIn)
	dec, matched := ic.Match("Bash", bashIn)
	if !matched {
		d, judged := ic.Judge(ctx, "Bash", bashIn)
		if !judged {
			return ""
		}
		dec = d
	} else if dec.Action == "judge" {
		ruleID := dec.RuleID
		rt := intercept.RuleTimeout{}
		if dec.TimeoutEnabled {
			rt = intercept.RuleTimeout{Enabled: true, Seconds: dec.TimeoutSeconds, Action: dec.TimeoutAction}
		}
		d, judged := ic.JudgeRuleWithTimeout(ctx, "Bash", bashIn, rt)
		if !judged {
			return ""
		}
		d.RuleID = ruleID
		dec = d
	}
	switch dec.Action {
	case "deny":
		ic.Log(ctx, intercept.ConvIDFromContext(ctx), dec, "Bash", bashIn, "denied")
		return "[POJUN PLATFORM CONTROL·NOT TARGET DEFENSE] This call was blocked by the platform. Reason: " + dec.Message + ". This operation is forbidden."
	case "allow":
		ic.Log(ctx, intercept.ConvIDFromContext(ctx), dec, "Bash", bashIn, "allowed")
		return ""
	case "ask":
		if ctx.Err() != nil {
			return "[POJUN PLATFORM CONTROL·NOT TARGET DEFENSE] Work cancelled, platform security controls blocked execution"
		}
		if !ic.HandleAsk(ctx, intercept.ConvIDFromContext(ctx), dec, "Bash", bashIn) {
			return "[POJUN PLATFORM CONTROL·NOT TARGET DEFENSE] Manual approval not granted (user rejected or approval timed out)"
		}
	}
	return ""
}
