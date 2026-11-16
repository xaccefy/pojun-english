package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/harness"
)

// runTrace retains the latest tool call so an interrupted run can identify the
// operation that was still in flight.
type runTrace struct {
	startedAt time.Time
	id        string
	name      string
	input     string
	at        time.Time
	pending   bool
}

func (t *runTrace) start(id, name, input string) {
	t.id, t.name, t.input, t.at, t.pending = id, name, input, time.Now(), true
}

func (t *runTrace) done(id string) {
	if id == t.id {
		t.pending = false
	}
}

var reasonHint = map[harness.TerminalReason]string{
	harness.ReasonCompleted:         "the model ended this round normally but left no text summary; facts and assets follow this round's tool-call records",
	harness.ReasonMaxTurns:          "hit the step cap (MaxTurns): the SDK already wrapped up and wrote back facts and assets; the intent gets marked exhausted so the planner continues from another direction — not treated as failure",
	harness.ReasonTimeout:           "hit the single-run wall-clock budget (MaxDuration): running tools get interrupted on the spot and wrap-up writes back identified facts and assets; the intent gets marked exhausted",
	harness.ReasonModelError:        "model or API call failed (network, auth, rate limit, provider 5xx etc.); after retries exhausted the intent is marked blocked — a transport fault means this intent barely probed; check its execution (get_worker_trace) before re-dispatching or switching approach",
	harness.ReasonBlockingLimit:     "context length hit the hard cap — the request was intercepted before sending; narrow the intent granularity or compress tool returns",
	harness.ReasonPromptTooLong:     "prompt too long and context-compaction retries exhausted — can't continue",
	harness.ReasonImageError:        "the current model doesn't support this round's multimodal content; switch to a vision-capable model or keep images out of tool returns",
	harness.ReasonStopHookPrevented: "a Stop hook prevented the round from ending and it never resumed; check whether task Guard rules are too strict",
	harness.ReasonHookStopped:       "a tool or hook actively stopped execution — e.g. out-of-scope target or forbidden command; check the last tool_result's interception note",
	harness.ReasonAbortedStreaming:  "the run was cancelled during model output streaming",
	harness.ReasonAbortedTools:      "the run was cancelled during tool execution",
}

// terminalText renders a terminal event with no final text into a compact summary
// and a Markdown detail block.
func terminalText(ctx context.Context, term *harness.Terminal, tr *runTrace) (string, string) {
	reason := term.Reason
	aborted := reason == harness.ReasonAbortedStreaming || reason == harness.ReasonAbortedTools
	// Prompt may return ctx.Err directly without a terminal event. Preserve the
	// cancellation cause instead of falling back to an empty/unknown terminal reason.
	if reason == "" && ctx.Err() != nil {
		aborted = true
	}

	var sum string
	if aborted {
		_, short, _, ok := AbortReason(ctx)
		if !ok {
			short = "cancel reason unavailable"
		}
		stage := "during execution"
		switch reason {
		case harness.ReasonAbortedStreaming:
			stage = "during model output"
		case harness.ReasonAbortedTools:
			stage = "during tool execution"
		}
		sum = " (run interrupted: " + short + "; stopped " + stage + progressSuffix(term, tr) + ", unfinished)"
	} else if reason == harness.ReasonMaxTurns || reason == harness.ReasonTimeout {
		sum = " (hit run budget cap (" + string(reason) + "), wrapped up writing back facts" + progressSuffix(term, tr) + "; no text summary this run)"
	} else {
		hint := terminalReasonHint(reason)
		sum = " (no text summary, terminal state " + terminalReasonLabel(reason) + ": " + firstLine(hint, 80) + ")"
	}

	var b strings.Builder
	b.WriteString(sum)
	b.WriteString("\n\n")
	displayReason := terminalReasonLabel(reason)
	fmt.Fprintf(&b, "- **Terminal state**: `%s` - %s\n", displayReason, terminalReasonHint(reason))
	if aborted {
		code, _, why, ok := AbortReason(ctx)
		if ok {
			fmt.Fprintf(&b, "- **Interrupt reason** (`%s`): %s\n", code, why)
		} else {
			b.WriteString("- **Interrupt reason**: unavailable; the cancelling side may not have attached a named cause via context.WithCancelCause\n")
		}
	}
	if term.Err != nil {
		fmt.Fprintf(&b, "- **Underlying error**: `%v`\n", term.Err)
	}
	if aborted && strings.TrimSpace(term.Text) != "" {
		b.WriteString("- **Partial output generated before cancel**:\n\n")
		b.WriteString(term.Text)
		b.WriteString("\n\n")
	}
	if term.Turns > 0 {
		fmt.Fprintf(&b, "- **Executed**: %d model turns\n", term.Turns)
	}
	if !tr.startedAt.IsZero() {
		fmt.Fprintf(&b, "- **Run duration**: %s\n", roundDur(time.Since(tr.startedAt)))
	}
	if u := term.Usage; u.InputTokens+u.OutputTokens+u.CacheReadTokens+u.CacheWriteTokens > 0 {
		fmt.Fprintf(&b, "- **Total tokens**: in %d / out %d / cache-read %d / cache-write %d\n",
			u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	}
	if tr.name == "" {
		b.WriteString("- **Tool calls**: this run ended before issuing any tool call\n")
	} else if tr.pending {
		fmt.Fprintf(&b, "- **Tool executing at interrupt**: `%s` (ran %s, **returned no result**)\n\n  ```json\n  %s\n  ```\n",
			tr.name, roundDur(time.Since(tr.at)), firstLine(tr.input, 300))
	} else {
		fmt.Fprintf(&b, "- **Last tool before interrupt**: `%s` (returned normally)\n", tr.name)
	}
	return sum, b.String()
}

func terminalReasonLabel(reason harness.TerminalReason) string {
	if reason == "" {
		return "context_canceled"
	}
	return string(reason)
}

func terminalReasonHint(reason harness.TerminalReason) string {
	if hint := reasonHint[reason]; hint != "" {
		return hint
	}
	if reason == "" {
		return "the run's context was cancelled but no Terminal event was produced underneath"
	}
	return "unknown terminal state; harness may have added a TerminalReason — extend reasonHint"
}

func progressSuffix(term *harness.Terminal, tr *runTrace) string {
	var parts []string
	if term.Turns > 0 {
		parts = append(parts, fmt.Sprintf("%d turns", term.Turns))
	}
	if !tr.startedAt.IsZero() {
		parts = append(parts, roundDur(time.Since(tr.startedAt)))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", ran " + strings.Join(parts, " / ")
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
