package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/intercept"
)

// Real OpenAPI 3 contract sample (structure follows the Swagger/OpenAPI 3 spec).
//
// A real structure rather than a 'pretty' sample: the parser must handle the spec's actual shapes —
// parameters at both operation and path level, requestBody under content,
// security overriding globals at operation level.
const openapi3Sample = `{
  "openapi": "3.0.0",
  "info": {"title": "Demo API", "version": "1.0.0"},
  "components": {
    "securitySchemes": {
      "bearerAuth": {"type": "http", "scheme": "bearer"},
      "apiKeyAuth": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
    }
  },
  "security": [{"bearerAuth": []}],
  "paths": {
    "/api/users": {
      "get": {
        "summary": "List users",
        "parameters": [
          {"name": "page", "in": "query", "required": false, "schema": {"type": "integer"}},
          {"name": "size", "in": "query", "required": true, "schema": {"type": "integer"}}
        ],
        "responses": {"200": {"description": "ok"}}
      },
      "post": {
        "summary": "Create user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string"},
                  "email": {"type": "string", "required": true}
                }
              }
            }
          }
        },
        "responses": {"201": {"description": "created"}}
      }
    },
    "/api/users/{id}": {
      "parameters": [
        {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
      ],
      "get": {
        "summary": "Get user",
        "security": [],
        "responses": {"200": {"description": "ok"}}
      },
      "delete": {
        "summary": "Delete user",
        "responses": {"204": {"description": "deleted"}}
      }
    },
    "/api/health": {
      "get": {"summary": "Health", "responses": {"200": {"description": "ok"}}}
    }
  }
}`

// The parser must read out the endpoint list, params, and required flags.
func TestContractScriptParsesOpenAPI3(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteContractScript(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(f, []byte(openapi3Sample), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(python, scriptPath, f).Output()
	if err != nil {
		t.Fatalf("script execution failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("output isn't JSON: %v\n%s", err, raw)
	}
	if out["found"] != true {
		t.Fatalf("should have detected a contract: %v", out)
	}
	if n, _ := out["api_count"].(float64); n != 5 {
		t.Errorf("api_count should be 5 (2+2+1), got %v", out["api_count"])
	}
	eps, _ := out["endpoints"].([]any)
	if len(eps) != 5 {
		t.Fatalf("endpoints should have 5 entries, got %d", len(eps))
	}

	// Locate specific endpoints by path+method.
	find := func(path, method string) map[string]any {
		for _, e := range eps {
			em, _ := e.(map[string]any)
			if em["path"] == path && em["method"] == method {
				return em
			}
		}
		return nil
	}

	// GET /api/users: query params + required flags.
	e := find("/api/users", "GET")
	if e == nil {
		t.Fatal("should find GET /api/users")
	}
	params, _ := e["params"].([]any)
	if len(params) != 2 {
		t.Errorf("should have 2 query params, got %d", len(params))
	}
	var sawSize bool
	for _, p := range params {
		pm, _ := p.(map[string]any)
		if pm["name"] == "size" {
			sawSize = true
			if pm["required"] != true {
				t.Error("size should be marked required")
			}
		}
	}
	if !sawSize {
		t.Error("should detect the size param")
	}

	// Path-level params must merge into the operation (id in /api/users/{id}).
	e2 := find("/api/users/{id}", "GET")
	if e2 == nil {
		t.Fatal("should find GET /api/users/{id}")
	}
	p2, _ := e2["params"].([]any)
	if len(p2) != 1 {
		t.Errorf("path-level params should merge into the operation, got %d", len(p2))
	}

	// Global security in effect → requires auth.
	if e["auth_required"] != true {
		t.Error("with global security in effect this endpoint should require auth")
	}
	// Operation-level security: [] → explicitly public.
	if e2["auth_required"] != false {
		t.Error("operation-level security:[] means public — shouldn't be marked auth-required")
	}
	// Auth-required endpoints must be listed separately (the entry point for privesc mining).
	authEps, _ := out["auth_endpoints"].([]any)
	if len(authEps) != 4 {
		t.Errorf("auth-required endpoints should be 4 (/api/health isn't), got %d", len(authEps))
	}
	// Auth schemes must be listed.
	schemes, _ := out["auth_schemes"].([]any)
	if len(schemes) != 2 {
		t.Errorf("should list 2 auth schemes, got %v", schemes)
	}
}

// Swagger 2.0 must also parse (its parameters are top-level; definitions isn't called components).
func TestContractScriptParsesSwagger2(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteContractScript(dir)
	if err != nil {
		t.Fatal(err)
	}
	swagger2 := `{
      "swagger": "2.0",
      "info": {"title": "Old API", "version": "1.0"},
      "securityDefinitions": {"apiKey": {"type": "apiKey", "name": "key", "in": "header"}},
      "paths": {
        "/v1/items": {
          "get": {
            "summary": "List items",
            "parameters": [{"name": "q", "in": "query", "type": "string", "required": true}],
            "responses": {"200": {"description": "ok"}}
          }
        }
      }
    }`
	f := filepath.Join(dir, "swagger.json")
	if err := os.WriteFile(f, []byte(swagger2), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(python, scriptPath, f).Output()
	if err != nil {
		t.Fatalf("script execution failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("output isn't JSON: %v\n%s", err, raw)
	}
	if out["found"] != true {
		t.Fatalf("should have detected a Swagger 2.0 contract: %v", out)
	}
	if n, _ := out["api_count"].(float64); n != 1 {
		t.Errorf("api_count should be 1, got %v", out["api_count"])
	}
	// Swagger 2.0 params are top-level (not in schema) — the type must be readable.
	eps, _ := out["endpoints"].([]any)
	e, _ := eps[0].(map[string]any)
	params, _ := e["params"].([]any)
	if len(params) != 1 {
		t.Fatalf("should have 1 param, got %d", len(params))
	}
	pm, _ := params[0].(map[string]any)
	if pm["type"] != "string" {
		t.Errorf("Swagger2 param type should come from top-level type, got %v", pm["type"])
	}
	if pm["required"] != true {
		t.Error("required flag should be preserved")
	}
}

// Postman collections get best-effort parsing.
func TestContractScriptParsesPostman(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteContractScript(dir)
	if err != nil {
		t.Fatal(err)
	}
	postman := `{
      "info": {"name": "Demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
      "item": [
        {"name": "Get user", "request": {"method": "GET", "url": {"raw": "https://t.example.com/api/user/1?x=1"}}}
      ]
    }`
	f := filepath.Join(dir, "postman.json")
	if err := os.WriteFile(f, []byte(postman), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(python, scriptPath, f).Output()
	if err != nil {
		t.Fatalf("script execution failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("output isn't JSON: %v\n%s", err, raw)
	}
	if n, _ := out["api_count"].(float64); n != 1 {
		t.Errorf("api_count should be 1, got %v", out["api_count"])
	}
	eps, _ := out["endpoints"].([]any)
	e, _ := eps[0].(map[string]any)
	// The query string must be stripped.
	if e["path"] != "/api/user/1" {
		t.Errorf("path should have the query string stripped, got %v", e["path"])
	}
	if e["method"] != "GET" {
		t.Errorf("method should be GET, got %v", e["method"])
	}
}

// Non-JSON (e.g. a YAML contract) must report the error honestly — no fake success.
func TestContractScriptReportsNonJSON(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteContractScript(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "contract.yaml")
	if err := os.WriteFile(f, []byte("openapi: 3.0.0\npaths: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(python, scriptPath, f).Output()
	if err != nil {
		t.Fatalf("script execution failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("output isn't JSON: %v\n%s", err, raw)
	}
	if out["found"] == true {
		t.Error("non-JSON must not report found=true")
	}
	if out["error"] == nil {
		t.Error("should give an error explanation")
	}
}

// Tool behavior: URL mode needs a work dir; the command must probe contract paths; the contract file lands in the work dir.
func TestApiContractTool(t *testing.T) {
	dir := t.TempDir()
	ts := &ToolSet{}
	tool := ts.apiContractTool()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})

	in, _ := json.Marshal(map[string]any{"base_url": "https://t.example.com/"})
	res, err := tool.Call(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	out := toolResultJSON(t, res)
	cmd, _ := out["run_with_bash"].(string)
	if cmd == "" {
		t.Fatalf("should return a command, got %v", out)
	}
	// Common contract paths must appear in the probe list.
	for _, p := range []string{"/openapi.json", "/v3/api-docs", "/swagger.json"} {
		if !strings.Contains(cmd, p) {
			t.Errorf("command should probe %s: %s", p, cmd)
		}
	}
	// The contract file lands in the work dir — not a fixed /tmp path.
	if !strings.Contains(cmd, "api_contract.json") {
		t.Errorf("command should reference the contract file: %s", cmd)
	}
	for _, fixed := range []string{"/tmp/api_contract.json", "/tmp/api_contract.py"} {
		if strings.Contains(cmd, fixed) {
			t.Errorf("intermediate artifacts must not land on fixed path %s: %s", fixed, cmd)
		}
	}
	// The script must have been written out.
	scriptPath, _ := out["script_path"].(string)
	if scriptPath == "" {
		t.Fatal("should return a script path")
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("script should have been written: %v", err)
	}
}

// Without a work dir it must error clearly and offer an alternative.
func TestApiContractToolRequiresWorkingDir(t *testing.T) {
	ts := &ToolSet{}
	tool := ts.apiContractTool()
	in, _ := json.Marshal(map[string]any{"base_url": "https://t.example.com"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("should error without a work dir, got %v", res.Content)
	}
	if !strings.Contains(toolResultText(t, res), "working directory") {
		t.Errorf("error should explain the working-directory problem, got %q", toolResultText(t, res))
	}
}

// An illegal base_url must error.
func TestApiContractToolValidatesURL(t *testing.T) {
	ts := &ToolSet{}
	tool := ts.apiContractTool()
	ctx := intercept.WithReviewContext(context.Background(), t.TempDir(), intercept.ReviewBackground{})
	for _, bad := range []string{"", "t.example.com", "ftp://t.example.com"} {
		in, _ := json.Marshal(map[string]any{"base_url": bad})
		res, err := tool.Call(ctx, in, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Errorf("base_url=%q should error", bad)
		}
	}
}

// Custom paths: use the default list when not given; use the custom ones when given.
func TestResolveContractPaths(t *testing.T) {
	if len(resolveContractPaths("")) != len(contractPaths) {
		t.Error("should use the default list when no custom paths given")
	}
	got := resolveContractPaths("/a.json, b.json ,")
	if len(got) != 2 {
		t.Fatalf("should parse out 2 paths, got %d: %v", len(got), got)
	}
	if got[0] != "/a.json" || got[1] != "/b.json" {
		t.Errorf("paths should be normalized (leading slash added, trimmed), got %v", got)
	}
}

// The tool must register into all three toolsets.
func TestApiContractRegisteredInAllToolSets(t *testing.T) {
	ts := NewToolSet(nil, "")
	has := func(list []actool.CoreTool) bool {
		for _, c := range list {
			if c.Name() == "api_contract" {
				return true
			}
		}
		return false
	}
	if !has(ts.WorkerTools()) {
		t.Error("api_contract missing from the worker toolset")
	}
	if !has(ts.PlannerTools()) {
		t.Error("api_contract missing from the planner toolset")
	}
	if !has(ts.MainAgentTools()) {
		t.Error("api_contract missing from the mainagent toolset")
	}
}

// End-to-end: spin up a real HTTP service serving an OpenAPI contract,
// run the full 'tool → command → real curl → real parse script' chain.
func TestApiContractEndToEndWithRealServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(openapi3Sample))
		case "/v3/api-docs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(openapi3Sample))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	ts := &ToolSet{}
	tool := ts.apiContractTool()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})
	in, _ := json.Marshal(map[string]any{"base_url": srv.URL})
	res, err := tool.Call(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	out := toolResultJSON(t, res)
	cmd, _ := out["run_with_bash"].(string)
	if cmd == "" {
		t.Fatalf("should return a command: %v", out)
	}
	t.Logf("cmd = %s", cmd)

	// Actually run the command (via bash — production is Linux bash -c).
	sh, err := exec.LookPath("bash")
	if err != nil {
		sh, err = exec.LookPath("sh")
		if err != nil {
			t.Skip("shell not found")
		}
	}
	run := exec.Command(sh, "-c", cmd)
	run.Dir = dir
	raw, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("command execution failed: %v\n%s", err, raw)
	}
	t.Logf("output = %s", string(raw))

	// Parse the script's JSON output (the command's first half is probing — it prints CONTRACT lines first).
	text := string(raw)
	idx := strings.Index(text, "{")
	if idx < 0 {
		t.Fatalf("no JSON in output: %s", text)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text[idx:]), &parsed); err != nil {
		t.Fatalf("output isn't JSON: %v\n%s", err, text[idx:])
	}
	if parsed["found"] != true {
		t.Fatalf("should have detected a contract: %v", parsed)
	}
	if n, _ := parsed["api_count"].(float64); n != 5 {
		t.Errorf("api_count should be 5, got %v", parsed["api_count"])
	}
	authEps, _ := parsed["auth_endpoints"].([]any)
	if len(authEps) != 4 {
		t.Errorf("auth-required endpoints should be 4, got %d", len(authEps))
	}
	// The contract file should land in the work dir.
	if _, err := os.Stat(filepath.Join(dir, "api_contract.json")); err != nil {
		t.Errorf("contract file should land in the work dir: %v", err)
	}
}
