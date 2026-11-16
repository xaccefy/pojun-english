// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [Built-in] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	"github.com/chu0119/pojun/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	attribSamps map[string][]AttribSample
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
}

// AttribSample is a recent sample of a blocked/error attribution (B6): when the planner
// only looks at counts, it cannot tell "which command was blocked", and reviewing or
// switching tactics needs the real artifacts. Command is truncated to attribSampleMax
// (to defend against overly long commands flooding the situation block); TS uses Unix
// seconds for convenient time display.
type AttribSample struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	TS      int64  `json:"ts"`
}

// attribSampleMax number of samples kept per class (most recent). Counts stay full;
// samples are just the "most recent 3".
const attribSampleMax = 3

// attribSampleMaxBytes truncation length (in bytes) of a single command.
const attribSampleMaxBytes = 200

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, attribSamps: map[string][]AttribSample{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	// Keep only one audit record: a blocked call is recorded as "block" by block(),
	// so we do not first record "allow" here — otherwise the same call would look
	// both allowed and blocked in the audit, making them indistinguishable in review.
	res := g.applyIntercept(ctx, ev)
	if res.Decision != "block" {
		g.record(ev.ToolName, "allow", "", cmd)
	}
	return res
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	} else if dec.Action == "judge" {
		// The rule explicitly requires "Agent adjudication": do not take a fixed
		// action, hand it to the model to decide; the verdict still follows the
		// original allow/deny/ask branches. Keep the rule_id that triggered it so
		// the audit shows which rule handed this call to the model.
		//
		// The rule's own timeout declaration must be passed down too: if the rule
		// author explicitly wrote "what to do when I time out", the rule takes
		// precedence (otherwise timeout_enabled/seconds/action on the rule remain
		// dead fields and the UI shows something different from what actually takes
		// effect). If the rule did not specify one, follow the global setting.
		ruleID := dec.RuleID
		rt := intercept.RuleTimeout{}
		if dec.TimeoutEnabled {
			rt = intercept.RuleTimeout{
				Enabled: true,
				Seconds: dec.TimeoutSeconds,
				Action:  dec.TimeoutAction,
			}
		}
		d, judged := g.interceptor.JudgeRuleWithTimeout(ctx, ev.ToolName, ev.Input, rt)
		if !judged {
			return hook.Result{}
		}
		d.RuleID = ruleID
		dec = d
	}
	switch dec.Action {
	case "deny":
		// Observation: a deny match does not block approval; just record a denied entry (visible on the history/task intercept page).
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("Work cancelled, platform security controls blocked execution"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("Manual approval not granted (user rejected or approval timed out)"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an POJUN platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("tool execution forbidden" / "user rejected") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "[POJUN PLATFORM CONTROL·NOT TARGET DEFENSE] This call was blocked by the platform. " +
		"Reason: " + reason + ". This operation is forbidden."
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	// B6: keep only real samples for blocked/error; ok does not use memory. Each class keeps the most recent 3 in a ring.
	if class != "ok" {
		var input struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &input)
		cmd := input.Command
		if len(cmd) > attribSampleMaxBytes {
			cmd = cmd[:attribSampleMaxBytes]
		}
		samps := append(g.attribSamps[class], AttribSample{Tool: ev.ToolName, Command: cmd, TS: time.Now().Unix()})
		if len(samps) > attribSampleMax {
			samps = samps[len(samps)-attribSampleMax:]
		}
		g.attribSamps[class] = samps
	}
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

// AttributionStats (B6) is the "situation" version of Attributions: on top of the
// counts it attaches recent samples for each class
// (samples."blocked"/"error" = [{tool,command,ts}...], at most 3, command truncated).
// When the planner sees "blocked×7 + recent command list" it can match them up and
// switch tactics, instead of only knowing "it was blocked".
// Intended for direct insertion into the guard_attributions block of graph_overview.
func (g *Guard) AttributionStats() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]any, len(g.attrib)+1)
	for k, v := range g.attrib {
		out[k] = v
	}
	samps := make(map[string]any, len(g.attribSamps))
	for k, v := range g.attribSamps {
		if len(v) > 0 {
			samps[k] = v
		}
	}
	if len(samps) > 0 {
		out["samples"] = samps
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
