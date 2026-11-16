package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// spyHook records calls forwarded to inner — verifies the log layer is a [sidecar], not an interceptor.
type spyHook struct {
	preCalls  int
	postCalls int
	stopCalls int
	block     bool
	msg       string
}

func (s *spyHook) PreToolUse(_ context.Context, _ string, _ []byte) (bool, string, []byte) {
	s.preCalls++
	return s.block, s.msg, nil
}

func (s *spyHook) PostToolUse(_ context.Context, _ string, _, _ []byte, _ bool) {
	s.postCalls++
}

func (s *spyHook) Stop(_ context.Context, _ []llm.Message) (bool, []string, string) {
	s.stopCalls++
	return false, nil, ""
}

// The log layer mustn't swallow inner's intercept decisions: worker steer/intercept all relies on inner.
func TestToolLogForwardsBlockDecision(t *testing.T) {
	spy := &spyHook{block: true, msg: "was blocked"}
	h := wrapToolLog(spy, KindWorker, "worker-1 · #1")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 3, IntentID: 7, Kind: KindWorker})

	block, msg, _ := h.PreToolUse(ctx, "Bash", []byte(`{"command":"rm -rf /"}`))
	if !block {
		t.Fatal("log layer swallowed inner's block decision — worker interception would break")
	}
	if msg != "was blocked" {
		t.Fatalf("block message not passed through: got %q", msg)
	}
	if spy.preCalls != 1 {
		t.Fatalf("inner not called: preCalls=%d", spy.preCalls)
	}
}

// The log layer must forward all three events, in order pre→post→stop.
func TestToolLogForwardsAllEvents(t *testing.T) {
	spy := &spyHook{}
	h := wrapToolLog(spy, KindPlanner, "")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 9, Kind: KindPlanner})

	h.PreToolUse(ctx, "Bash", []byte(`{"command":"nmap -sV 10.0.0.1"}`))
	h.PostToolUse(ctx, "Bash", []byte(`{}`), []byte("ok"), false)
	h.Stop(ctx, nil)

	if spy.preCalls != 1 || spy.postCalls != 1 || spy.stopCalls != 1 {
		t.Fatalf("not all events forwarded: pre=%d post=%d stop=%d", spy.preCalls, spy.postCalls, spy.stopCalls)
	}
}

// Platform-blocked calls must get BLOCKED on the pre line — the layer is [forward to inner, then log],
// so it knows inner's intercept decision. The only reliable 'blocked' criterion.
func TestToolLogMarksBlockedPreLine(t *testing.T) {
	spy := &spyHook{block: true, msg: "was blocked"}
	h := wrapToolLog(spy, KindWorker, "")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 3, IntentID: 9, Kind: KindWorker})

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	block, _, _ := h.PreToolUse(ctx, "Bash", []byte(`{"command":"rm -rf /"}`))
	if !block {
		t.Fatal("intercept decision not passed through")
	}
	out := buf.String()
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("blocked call's log line should mark BLOCKED, got: %q", out)
	}
	if !strings.Contains(out, "Bash") {
		t.Fatalf("log line should carry the tool name, got: %q", out)
	}
}

// Unblocked calls must not get BLOCKED — or the blocked count inflates falsely.
func TestToolLogDoesNotMarkBlockedWhenAllowed(t *testing.T) {
	h := wrapToolLog(&spyHook{}, KindWorker, "")
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 3, Kind: KindWorker})

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	h.PreToolUse(ctx, "Bash", []byte(`{"command":"nmap 10.0.0.1"}`))
	if strings.Contains(buf.String(), "BLOCKED") {
		t.Fatalf("allowed calls must not be marked BLOCKED: %q", buf.String())
	}
}

// With no inner this layer is everything: must allow, not misblock.
func TestToolLogWithoutInnerAllowsAll(t *testing.T) {
	h := toolLogSink(KindMain)
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 1, Kind: KindMain})
	block, msg, _ := h.PreToolUse(ctx, "Bash", []byte(`{"command":"ls"}`))
	if block || msg != "" {
		t.Fatalf("must not block with no inner: block=%v msg=%q", block, msg)
	}
}

// Bash command summaries take the first line only, capped — multi-line scripts can't flood the journal.
func TestSummarizeToolInputTrimsCommand(t *testing.T) {
	in, _ := json.Marshal(map[string]string{
		"command": "curl -s http://x/ | sh\nsecond command loooooong loooooong loooooong",
	})
	got := summarizeToolInput("Bash", in)
	if strings.Contains(got, "second") {
		t.Fatalf("command summary should take the first line only: %q", got)
	}
	if len([]rune(got)) > 100 {
		t.Fatalf("command summary too long: %d chars", len([]rune(got)))
	}
}

// Empty input mustn't panic (missing tool input is common).
func TestSummarizeToolInputEmpty(t *testing.T) {
	if got := summarizeToolInput("Bash", nil); got != "" {
		t.Fatalf("empty input should return empty string: %q", got)
	}
	if got := summarizeToolInput("UnknownTool", []byte("{}")); got != "" {
		t.Fatalf("empty JSON should return empty string: %q", got)
	}
}

// Result classification: platform-blocked (exact) vs target-side WAF (heuristic, Bash only) must stay separate —
// mixing them makes the blocked counter meaningless (a measured 'generate vuln report' command got misjudged
// as blocked because its output contained vuln descriptions).
func TestClassifyToolResult(t *testing.T) {
	if got := classifyToolResult("Bash", []byte("boom"), true); got != "error" {
		t.Fatalf("isErr should classify error: %q", got)
	}
	if got := classifyToolResult("Bash", []byte("HTTP 403 Forbidden"), false); got != "waf" {
		t.Fatalf("Bash 403 should classify waf: %q", got)
	}
	if got := classifyToolResult("Bash", []byte("found 3 open ports"), false); got != "ok" {
		t.Fatalf("normal output should classify ok: %q", got)
	}
	if got := classifyToolResult("Bash", []byte(platformBlockMarker+" This operation is forbidden."), false); got != "blocked" {
		t.Fatalf("platform intercept should classify blocked: %q", got)
	}
	// Regression: vuln data returned by list_findings contains 403/denied — not blocked, not WAF.
	data := []byte(`{"findings":[{"title":"CVE-2021-403 privesc"},{"desc":"denied by WAF"}]}`)
	if got := classifyToolResult("list_findings", data, false); got != "ok" {
		t.Fatalf("data-tool output must not classify blocked/waf: %q", got)
	}
	if got := classifyToolResult("list_findings", []byte(platformBlockMarker+" denied"), false); got != "blocked" {
		t.Fatalf("platform-intercept prefix must work for any tool: %q", got)
	}
}

// Log prefix must carry agent role and owner id — otherwise log lines can't be located to a specific intent.
func TestToolLogPrefixCarriesAttribution(t *testing.T) {
	h := toolLogSink(KindWorker)
	ctx := WithRunInfo(context.Background(), RunInfo{
		TaskID: 3, ExplorationID: 3, IntentID: 42, Kind: KindWorker,
	})
	p := h.prefix(ctx)
	for _, want := range []string{"worker", "task=3", "exp=3", "intent=#42"} {
		if !strings.Contains(p, want) {
			t.Fatalf("prefix missing %q: %q", want, p)
		}
	}
}
