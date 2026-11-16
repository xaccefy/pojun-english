package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/intercept"
)

// The diff's core criterion: keep only **structural** differences, filter out noise.
func TestDiffResponseDetectsKeySetDifference(t *testing.T) {
	bodyA := `{"id":1,"name":"a","secret_field":"x"}`
	bodyB := `{"id":1,"name":"a"}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if len(d.KeysOnlyInA) != 1 || d.KeysOnlyInA[0] != "secret_field" {
		t.Errorf("keys only on side A should be identified, got %v", d.KeysOnlyInA)
	}
	if d.SameShape {
		t.Error("key sets differ — SameShape should be false")
	}
	if !d.Enumerable {
		t.Error("differing key sets should support an enumerable judgment")
	}
}

// Different key order is semantically identical JSON — not a difference.
func TestDiffResponseIgnoresKeyOrder(t *testing.T) {
	bodyA := `{"a":1,"b":2,"c":3}`
	bodyB := `{"c":3,"b":2,"a":1}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if !d.SameShape {
		t.Error("different key order shouldn't change the shape")
	}
	if len(d.ValueDiffs) != 0 {
		t.Errorf("different key order shouldn't produce value diffs, got %v", d.ValueDiffs)
	}
	if d.Enumerable {
		t.Error("key-order-only differences shouldn't support enumerable")
	}
}

// Timestamp/trace-id noise must be filtered — otherwise every request 'has differences'.
func TestDiffResponseFiltersNoiseValues(t *testing.T) {
	bodyA := `{"created_at":"2026-10-22T10:00:00Z","trace":"a1b2c3d4e5f60718293a4b5","id":1}`
	bodyB := `{"created_at":"2026-10-22T10:00:03Z","trace":"f6e5d4c3b2a1908776655443","id":1}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if len(d.ValueDiffs) != 0 {
		t.Errorf("noise fields shouldn't produce value diffs, got %v", d.ValueDiffs)
	}
	if len(d.NoiseKeys) != 2 {
		t.Errorf("2 noise fields should be marked, got %v", d.NoiseKeys)
	}
}

// **One-sided** noise isn't noise — it means the other side's value is a meaningful difference.
func TestDiffResponseOneSidedNoiseIsRealDifference(t *testing.T) {
	bodyA := `{"id":"2026-10-22T10:00:00Z"}`
	bodyB := `{"id":"42"}`
	d := diffResponse(200, 200, bodyA, bodyB)

	if len(d.ValueDiffs) != 1 {
		t.Errorf("one-sided noise should count as a real difference, got %d: %v", len(d.ValueDiffs), d.ValueDiffs)
	}
	if len(d.NoiseKeys) != 0 {
		t.Errorf("one-sided noise shouldn't enter the noise list, got %v", d.NoiseKeys)
	}
}

// A type change is a structural difference — the model must see it (number 1 became string "1").
func TestDiffResponseTypeChangeIsDifference(t *testing.T) {
	d := diffResponse(200, 200, `{"id":1}`, `{"id":"1"}`)
	if len(d.ValueDiffs) != 1 {
		t.Fatalf("a type change should produce value diffs, got %d", len(d.ValueDiffs))
	}
	vd := d.ValueDiffs[0]
	if vd.KindA != "number" || vd.KindB != "string" {
		t.Errorf("type labels wrong: %s -> %s", vd.KindA, vd.KindB)
	}
}

// Nested object/array values must be compared correctly — byte-comparing maps misfires on iteration order.
func TestDiffResponseComparesNestedStructures(t *testing.T) {
	same := diffResponse(200, 200, `{"o":{"x":1,"y":2}}`, `{"o":{"y":2,"x":1}}`)
	if len(same.ValueDiffs) != 0 {
		t.Errorf("nested objects with different key order shouldn't count as a difference, got %v", same.ValueDiffs)
	}
	diff := diffResponse(200, 200, `{"o":{"x":1}}`, `{"o":{"x":2}}`)
	if len(diff.ValueDiffs) != 1 {
		t.Errorf("nested objects with different values should count as 1 difference, got %d", len(diff.ValueDiffs))
	}
}

// v0.4.37: credential-class fields still get the Sensitive mark, but values are shown raw (first-party evidence must be traceable).
func TestDiffResponseKeepsSensitiveValuesPlaintext(t *testing.T) {
	d := diffResponse(200, 200, `{"access_token":"aaa111","id":1}`, `{"access_token":"bbb222","id":2}`)

	var found bool
	for _, vd := range d.ValueDiffs {
		if vd.Key == "access_token" {
			found = true
			if !vd.Sensitive {
				t.Error("access_token should be marked sensitive")
			}
			if vd.PreviewA != "aaa111" || vd.PreviewB != "bbb222" {
				t.Errorf("sensitive values should keep plaintext: %q / %q", vd.PreviewA, vd.PreviewB)
			}
		}
	}
	if !found {
		t.Fatalf("access_token should appear in value diffs, got %v", d.ValueDiffs)
	}
}

// Sensitive-key judgment mustn't overreach: business fields containing "key" like monkey / keyword aren't credentials.
func TestSensitiveKeyDoesNotOverMatch(t *testing.T) {
	notSensitive := []string{"monkey", "keyword", "user", "name", "id", "cache_key", "sort_key", "session_count", "session_duration"}
	for _, k := range notSensitive {
		if isSensitiveKey(k) {
			t.Errorf("%q shouldn't be judged a sensitive key", k)
		}
	}
	sensitive := []string{
		"token", "access_token", "accessToken", "refreshToken",
		"password", "passwd", "pwd", "passphrase",
		"api_key", "apiKey", "APIKey", "API_KEY", "secret_key", "client_secret",
		"sessionId", "session_id", "auth_header", "authorization", "cookie",
		"jwt", "credentials", "private_key",
	}
	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("%q should be judged a sensitive key", k)
		}
	}
}

// With unknown status codes you can't pass 0==0 off as 'statuses equal'.
func TestDiffResponseUnknownStatusIsNotSameStatus(t *testing.T) {
	d := diffResponse(0, 0, `{"a":1}`, `{"a":1}`)
	if d.StatusKnown {
		t.Error("StatusKnown should be false when neither side has a status code")
	}
	if d.Enumerable {
		t.Error("unknown status + same structure shouldn't be judged enumerable")
	}
	if !strings.Contains(d.Note, "Status code unknown") {
		t.Errorf("the note should mention unknown status code, got %q", d.Note)
	}
}

// Non-JSON responses (HTML/text) can only compare length and equality.
func TestDiffResponseNonJSON(t *testing.T) {
	d := diffResponse(200, 404, "<html>a</html>", "<html>b</html>")
	if d.SameShape {
		t.Error("non-JSON with different content — SameShape should be false")
	}
	if !d.Enumerable {
		t.Error("differing status codes should support enumerable")
	}
}

// stripHTTPHeader: a full response saved by curl -i must get headers stripped and the status code extracted.
func TestStripHTTPHeader(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	body, status := stripHTTPHeader(raw)
	if status != 200 {
		t.Errorf("status code should be 200, got %d", status)
	}
	if body != `{"a":1}` {
		t.Errorf("response-body strip wrong: %q", body)
	}

	// With no HTTP header (pure body) it's returned as-is, status unknown.
	body2, status2 := stripHTTPHeader(`{"a":1}`)
	if status2 != 0 {
		t.Errorf("status should be 0 without HTTP headers, got %d", status2)
	}
	if body2 != `{"a":1}` {
		t.Errorf("content shouldn't change without HTTP headers: %q", body2)
	}
}

// File mode: the tool reads files and diffs directly — no network, no scripts.
func TestDiffResponsesFileModeComputesDiffInProcess(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":1,"extra":"leak"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"id":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ts := &ToolSet{}
	tool := ts.diffResponses()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})

	in, _ := json.Marshal(map[string]any{"file_a": "a.json", "file_b": "b.json"})
	res, err := tool.Call(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	out := toolResultJSON(t, res)
	diff, ok := out["diff"].(map[string]any)
	if !ok {
		t.Fatalf("return has no diff field: %v", out)
	}
	keys, _ := diff["keys_only_in_a"].([]any)
	if len(keys) != 1 || keys[0] != "extra" {
		t.Errorf("the only-in-A key 'extra' should be identified, got %v", diff["keys_only_in_a"])
	}
	// File mode shouldn't produce a command — no network.
	if _, has := out["run_with_bash"]; has {
		t.Error("file mode shouldn't return run_with_bash (no network)")
	}
}

// URL mode: without a work dir it should error clearly with an alternative, not fail silently.
func TestDiffResponsesURLModeRequiresWorkingDir(t *testing.T) {
	ts := &ToolSet{}
	tool := ts.diffResponses()
	// No work dir bound.
	in, _ := json.Marshal(map[string]any{"url_a": "https://a.test/x", "url_b": "https://a.test/y"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("should error without a work dir, got %v", res.Content)
	}
	msg := toolResultText(t, res)
	if !strings.Contains(msg, "work dir") {
		t.Errorf("the error should mention the work dir, got %q", msg)
	}
}

// URL mode: with a work dir it should write the script and return an executable command.
func TestDiffResponsesURLModeWritesScript(t *testing.T) {
	dir := t.TempDir()
	ts := &ToolSet{}
	tool := ts.diffResponses()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})

	in, _ := json.Marshal(map[string]any{
		"url_a": "https://a.test/x", "url_b": "https://a.test/y",
		"header_a": "Authorization: Bearer tk",
	})
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
	scriptPath, _ := out["script_path"].(string)
	if scriptPath == "" {
		t.Fatal("should return a script path")
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("script should have been written: %v", err)
	}
	// Response bodies land in the work dir, not /tmp.
	if !strings.Contains(cmd, "resp_a_body") || !strings.Contains(cmd, "resp_b_body") {
		t.Errorf("the command should reference response-body files under the work dir: %s", cmd)
	}
	// Artifacts must land in [this run's work dir], not a fixed /tmp path.
	//
	// Assertion style: the response-body path in the command must be under the work dir.
	// Can't assert 'command doesn't contain /tmp' — t.TempDir() on Linux is itself /tmp/...,
	// which would flag the test's own temp dir as a violation (that's exactly how CI failed).
	if !strings.Contains(cmd, dir) {
		t.Errorf("response-body files should land under work dir %s: %s", dir, cmd)
	}
	// It also shouldn't use a fixed /tmp path (exactly the 'intermediates to /tmp' the platform rule forbids).
	for _, fixed := range []string{"/tmp/resp_a_body", "/tmp/resp_b_body", "/tmp/resp_diff.py"} {
		if strings.Contains(cmd, fixed) {
			t.Errorf("intermediates shouldn't land at fixed path %s: %s", fixed, cmd)
		}
	}
	// Auth headers must be escaped.
	if !strings.Contains(cmd, "'Authorization: Bearer tk'") {
		t.Errorf("the auth header should be wrapped in single quotes: %s", cmd)
	}
}

// The two implementations (Go-side diffResponse and the Python script) must be equivalent —
// URL mode actually runs the script while file mode runs Go code; inconsistent behavior would confuse the model.
//
// Assertion style: **really run python**, take its output, and compare field by field against the Go-side result.
func TestDiffScriptMatchesGoImplementation(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteDiffScript(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		a    string
		b    string
		sa   int
		sb   int
	}{
		{"key sets differ", `{"id":1,"extra":"x"}`, `{"id":1}`, 200, 200},
		{"key order differs", `{"a":1,"b":2}`, `{"b":2,"a":1}`, 200, 200},
		{"noise fields", `{"t":"2026-10-22T10:00:00Z","id":1}`, `{"t":"2026-10-22T10:00:09Z","id":1}`, 200, 200},
		{"type change", `{"id":1}`, `{"id":"1"}`, 200, 200},
		{"status codes differ", `{"id":1}`, `{"id":1}`, 200, 403},
		{"credential field", `{"token":"aaa","id":1}`, `{"token":"bbb","id":2}`, 200, 200},
		{"one-sided noise", `{"id":"2026-10-22T10:00:00Z"}`, `{"id":"42"}`, 200, 200},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fa := filepath.Join(dir, "case_a.json")
			fb := filepath.Join(dir, "case_b.json")
			if err := os.WriteFile(fa, []byte(c.a), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fb, []byte(c.b), 0o644); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(python, scriptPath, fa, fb,
				itoa(c.sa), itoa(c.sb))
			raw, err := cmd.Output()
			if err != nil {
				t.Fatalf("python execution failed: %v", err)
			}
			var pyOut map[string]any
			if err := json.Unmarshal(raw, &pyOut); err != nil {
				t.Fatalf("python output isn't JSON: %v\n%s", err, raw)
			}
			goOut := diffResponse(c.sa, c.sb, c.a, c.b)

			// Field-by-field: key sets, noise list, value-diff count and content, enumerable verdict.
			pyKeysA := stringsOf(pyOut["keys_only_in_a"])
			pyKeysB := stringsOf(pyOut["keys_only_in_b"])
			if !equalStrings(pyKeysA, goOut.KeysOnlyInA) {
				t.Errorf("only-in-A mismatch: python=%v go=%v", pyKeysA, goOut.KeysOnlyInA)
			}
			if !equalStrings(pyKeysB, goOut.KeysOnlyInB) {
				t.Errorf("only-in-B mismatch: python=%v go=%v", pyKeysB, goOut.KeysOnlyInB)
			}
			pyNoise := stringsOf(pyOut["noise_keys"])
			if !equalStrings(pyNoise, goOut.NoiseKeys) {
				t.Errorf("noise list mismatch: python=%v go=%v", pyNoise, goOut.NoiseKeys)
			}
			pyDiffs, _ := pyOut["value_diffs"].([]any)
			if len(pyDiffs) != len(goOut.ValueDiffs) {
				t.Errorf("value-diff count mismatch: python=%d go=%d", len(pyDiffs), len(goOut.ValueDiffs))
			} else {
				for i := range pyDiffs {
					pd, _ := pyDiffs[i].(map[string]any)
					gd := goOut.ValueDiffs[i]
					if pd["key"] != gd.Key {
						t.Errorf("diff %d key mismatch: python=%v go=%v", i, pd["key"], gd.Key)
					}
					if pd["kind_a"] != gd.KindA || pd["kind_b"] != gd.KindB {
						t.Errorf("diff %d type mismatch: python=%v/%v go=%s/%s",
							i, pd["kind_a"], pd["kind_b"], gd.KindA, gd.KindB)
					}
					if pd["preview_a"] != gd.PreviewA || pd["preview_b"] != gd.PreviewB {
						t.Errorf("diff %d preview mismatch: python=%v/%v go=%q/%q",
							i, pd["preview_a"], pd["preview_b"], gd.PreviewA, gd.PreviewB)
					}
				}
			}
			if pyOut["enumerable"] != goOut.Enumerable {
				t.Errorf("enumerable verdict mismatch: python=%v go=%v", pyOut["enumerable"], goOut.Enumerable)
			}
			if pyOut["same_shape"] != goOut.SameShape {
				t.Errorf("shape verdict mismatch: python=%v go=%v", pyOut["same_shape"], goOut.SameShape)
			}
		})
	}
}

// The Python side must also strip HTTP headers and extract the status code.
func TestDiffScriptStripsHTTPHeader(t *testing.T) {
	python := pythonCommand(t)
	dir := t.TempDir()
	scriptPath, err := WriteDiffScript(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw := "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	f := filepath.Join(dir, "h.txt")
	if err := os.WriteFile(f, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "h2.txt")
	if err := os.WriteFile(other, []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(python, scriptPath, f, other).Output()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output isn't JSON: %v\n%s", err, out)
	}
	if m["status_a"] != float64(201) {
		t.Errorf("status 201 should come from the HTTP header, got %v", m["status_a"])
	}
	if m["same_shape"] != true {
		t.Errorf("identical content after header strip — same_shape should be true, got %v", m["same_shape"])
	}
}

// diff_responses must be in all three toolsets —
// it's the common base of the three vuln-hunting dimensions; one unbound agent = one lost digging path.
func TestDiffResponsesRegisteredInAllToolSets(t *testing.T) {
	ts := NewToolSet(nil, "")
	has := func(list []actool.CoreTool) bool {
		for _, c := range list {
			if c.Name() == "diff_responses" {
				return true
			}
		}
		return false
	}
	if !has(ts.WorkerTools()) {
		t.Error("diff_responses missing from the worker toolset")
	}
	if !has(ts.PlannerTools()) {
		t.Error("diff_responses missing from the planner toolset")
	}
	if !has(ts.MainAgentTools()) {
		t.Error("diff_responses missing from the mainagent toolset")
	}
	if !has(ts.AllDomainTools()) {
		t.Error("diff_responses missing from AllDomainTools")
	}
}

// End-to-end: spin up a real HTTP service (existing/nonexisting endpoints), fetch responses with real curl into files,
// then call diff_responses to verify the whole chain.
//
// Why this one: the earlier tests cover 'constructed input → computed diff';
// they can't catch 'the saved file isn't what the tool thinks it is' — e.g. curl saved a
// full response (with HTTP headers) while the tool treats it as a pure body — the status code would never parse.
func TestDiffResponsesEndToEndWithRealHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/1001": // exists
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			fmt.Fprint(w, `{"id":1001,"name":"bob","email":"bob@x.com","role":"admin"}`)
		case "/user/999999": // doesn't exist
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"not found"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	// Fetch responses with curl (simulating the agent's real action: curl -i saves the full response).
	for _, c := range []struct{ name, id string }{
		{"exists.txt", "1001"},
		{"missing.txt", "999999"},
	} {
		out := filepath.Join(dir, c.name)
		cmd := exec.Command("curl", "-sS", "-i", "-o", out, srv.URL+"/user/"+c.id)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("curl unavailable: %v %s", err, b)
		}
	}

	ts := &ToolSet{}
	tool := ts.diffResponses()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})
	in, _ := json.Marshal(map[string]any{"file_a": "exists.txt", "file_b": "missing.txt"})
	res, err := tool.Call(ctx, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	out := toolResultJSON(t, res)
	diff, _ := out["diff"].(map[string]any)

	// The status code must parse from the HTTP header (curl -i saved the full response).
	if diff["status_a"] != float64(200) {
		t.Errorf("A's status should be 200, got %v", diff["status_a"])
	}
	if diff["status_b"] != float64(404) {
		t.Errorf("B's status should be 404, got %v", diff["status_b"])
	}
	if diff["status_known"] != true {
		t.Error("status should be recognized as known")
	}
	if diff["same_status"] != false {
		t.Error("statuses should differ")
	}
	// Key sets differ → enumerable.
	keysA := stringsOf(diff["keys_only_in_a"])
	if len(keysA) != 4 {
		t.Errorf("side A should have 4 extra keys, got %v", keysA)
	}
	if diff["enumerable"] != true {
		t.Error("should be judged enumerable")
	}
}

// --- helpers ---

// pythonCommand locates python3 (skips tests requiring a real python when not found).
func pythonCommand(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("python not found — skipping the script comparison test")
	return ""
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// toolResultText takes a tool result's text content.
func toolResultText(t *testing.T, res actool.Result) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// toolResultJSON parses a tool result's JSON.
func toolResultJSON(t *testing.T, res actool.Result) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &m); err != nil {
		t.Fatalf("tool result isn't JSON: %v\n%s", err, toolResultText(t, res))
	}
	return m
}

func stringsOf(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
