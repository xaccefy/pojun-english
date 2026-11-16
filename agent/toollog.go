package agent

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// toolLogHooks writes 'who called which tool under which task, with what result, how it wrapped' into the journal.
//
// Why it exists: worker/planner/main tool calls were previously **completely unobservable** — the journal only had
// planner heartbeats and vulnintel spam; whether a worker was actually working, stuck on which step, or erroring
// could only be confirmed via transcripts/*.jsonl mtimes. Without this signal the tuning loop (grab logs → look
// at tool use → tune params) is flying blind.
//
// Design trade-offs:
//   - **Don't log full commands/outputs**. Bash commands run hundreds of bytes, tool outputs up to tens of KB —
//     logging all of it bloats the journal and slows disk. Only [first-line summary + byte count] + [result class].
//   - **Result classes, not raw text**. ok/error/blocked tri-state is the tuning signal that matters (is the model
//     hitting a WAF, is a tool reporting param errors) — raw text lives in transcripts.
//   - **Two lines per call** (pre + post). The pre line says 'what's about to happen', the post line 'did it work'.
//     Both are needed to separate 'stuck before the call' (model emitted no tool) from 'stuck after' (tool failed).
//
// It's a pure sidecar: doesn't intercept, doesn't change inputs, doesn't affect decisions. Null-check and return.
type toolLogHooks struct {
	// kind is the agent role tag (planner/worker/main/chat) for the log prefix.
	kind string
	// label is a more specific run tag (e.g. "worker-1 · #42"), optional.
	label string
	// inner is the existing hook chain (interception control); this layer only observes then forwards.
	inner harness.HookRunner
}

// toolLogSink builds an observe-only hook chain (no inner).
func toolLogSink(kind string) *toolLogHooks {
	return &toolLogHooks{kind: kind}
}

// wrapToolLog puts the logging layer outside the existing hook chain: log first, then forward to inner.
// When inner is nil this layer is everything.
func wrapToolLog(inner harness.HookRunner, kind string, label string) *toolLogHooks {
	return &toolLogHooks{kind: kind, label: label, inner: inner}
}

// PreToolUse records the start of one tool call.
//
// Order matters: **forward to inner first, then log**. Because inner (intercept/steer) may return
// 'this call was blocked' — the log layer needs that result to label accurately:
//
//	log-then-forward → log only says 'about to call this tool' — whether it got blocked is a guess;
//	forward-then-log → log directly marks BLOCKED.
//
// And the 'blocked' criterion must be [the platform's own intercept decision], not 403/denied
// wording appearing in output — a measured case: a vuln-report-generation command (output containing vuln
// descriptions) got misjudged as blocked.
func (h *toolLogHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	var (
		block   bool
		message string
		updated []byte
	)
	if h.inner != nil {
		block, message, updated = h.inner.PreToolUse(ctx, name, input)
	}
	tag := ""
	if block {
		tag = " BLOCKED"
	}
	log.Printf("%s → %s%s %s", h.prefix(ctx), name, tag, summarizeToolInput(name, input))
	return block, message, updated
}

// PostToolUse records the result of one tool call.
func (h *toolLogHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	h.logPost(ctx, name, input, result, isErr)
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

// Stop records a run's wrap-up.
func (h *toolLogHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	h.logStop(ctx, messages)
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}

// --- Log lines ---

func (h *toolLogHooks) prefix(ctx context.Context) string {
	ri := RunInfoFrom(ctx)
	kind := ri.Kind
	if kind == "" {
		kind = h.kind
	}
	p := "[tool] " + kind
	if h.label != "" {
		p += " " + h.label
	}
	switch {
	case ri.TaskID != 0:
		p += " task=" + strconv.FormatInt(ri.TaskID, 10)
	case ri.SessionID != "":
		p += " session=" + shortID(ri.SessionID)
	}
	if ri.ExplorationID != 0 {
		p += " exp=" + strconv.FormatInt(ri.ExplorationID, 10)
	}
	if ri.IntentID != 0 {
		p += " intent=#" + strconv.FormatInt(ri.IntentID, 10)
	}
	return p
}

func (h *toolLogHooks) logPost(ctx context.Context, name string, input, result []byte, isErr bool) {
	log.Printf("%s ← %s %s out=%dB", h.prefix(ctx), name, classifyToolResult(name, result, isErr), len(result))
}
// logStop prints the wrap-up line: whether the last assistant turn had body/tool calls. This is the
// first-hand signal separating 'finished normally', 'spun out' and 'model errored'.
func (h *toolLogHooks) logStop(ctx context.Context, messages []llm.Message) {
	var textLen int
	var tools int
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		textLen = len(strings.TrimSpace(m.Text()))
		tools = len(m.ToolUses())
		break
	}
	log.Printf("%s ⏹ stop text=%dB tools=%d msgs=%d", h.prefix(ctx), textLen, tools, len(messages))
}

// --- Tool input/result summaries ---

// summarizeToolInput gives a one-line summary of tool input. Commands take the first line (leading whitespace
// stripped) capped in length — no multi-line scripts flooding the journal.
func summarizeToolInput(name string, input []byte) string {
	if len(input) == 0 {
		return ""
	}
	switch name {
	case "Bash":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &in) == nil && in.Command != "" {
			return cmdHead(in.Command)
		}
	case "record_fact", "report_finding", "insert_assets", "record_asset":
		var in struct {
			Type  string `json:"type"`
			Title string `json:"title"`
			Kind  string `json:"kind"`
			Name  string `json:"name"`
		}
		if json.Unmarshal(input, &in) == nil {
			var bits []string
			for _, s := range []string{in.Type, in.Kind, in.Name, in.Title} {
				if s != "" {
					bits = append(bits, trunc(s, 48))
				}
			}
			if len(bits) > 0 {
				return strings.Join(bits, " ")
			}
		}
	}
	// Fallback: squash the whole JSON to one capped line. Empty objects/arrays carry no info — return "" not "{}".
	s := strings.Join(strings.Fields(string(input)), " ")
	if s == "{}" || s == "[]" {
		return ""
	}
	return trunc(s, 96)
}

// cmdHead takes a command's first line, capped at 96 chars.
func cmdHead(cmd string) string {
	line := cmd
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return trunc(strings.TrimSpace(line), 96)
}

// Activity log/tool summaries keep the raw command line (v0.4.37: first-party evidence must be traceable — no masking).

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// reToolBlocked recognizes typical 'target-side block' wording (WAF/403/captcha/rate-limit). Same source
// as guard's attribution regex, but used here only for labeling — not decisions.
var reToolBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied|too many requests)\b`)

// platformBlockMarker is the fixed prefix of platform intercept messages (see guard.systemBlockMessage).
// Its presence = this call was blocked by POJUN itself — a different thing from target-side WAF.
const platformBlockMarker = "[POJUN PLATFORM CONTROL·NOT TARGET DEFENSE]"

// classifyToolResult compresses a tool result into a class label.
//
// Semantic layers — don't mix them:
//   - blocked: the platform **itself** blocked this call. Criterion is POJUN's fixed prefix — precise and reliable.
//     (The PreToolUse line marks BLOCKED; this is the fallback — blocked calls shouldn't have post lines anyway.)
//   - waf: WAF/403/denied wording in output, **Bash only**. Bash hits the target — 403 in command
//     output means the target deflected it — a useful attribution signal for the planner.
//     But in data tools (list_findings/list_assets), 403/denied in output is often just
//     **the vuln description itself** — a measured 30KB vuln list and a vuln report both got misjudged.
//   - error: tool execution error.
//   - ok: everything else.
//
// Why not fold waf into blocked: a measured 'generate vuln report' command (output containing vuln descriptions)
// got judged blocked — while 'blocked by platform' is a completely different semantic: the former is normal
// work, the latter is platform control. Mixing them makes the blocked counter meaningless.
func classifyToolResult(name string, result []byte, isErr bool) string {
	s := string(result)
	if isErr {
		return "error"
	}
	if strings.Contains(s, platformBlockMarker) {
		return "blocked"
	}
	if name == "Bash" && reToolBlocked.MatchString(s) {
		return "waf"
	}
	return "ok"
}
