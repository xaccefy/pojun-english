package agent

// Rephrasing (refusal self-heal)
//
// Some models misjudge 'in-scope authorized security testing/protection verification' as a high-risk request
// and end with 'I can't assist' — planner/worker then re-dispatch the intent and a round is wasted. This file
// wraps llm.Provider with a narrow guard:
//
//  1. Triggers only when an explicit refusal appears at the **start** of a reply (not word-list warfare,
//     doesn't change user intent);
//  2. The retry only appends an 'authorization context + required technical output' note to the system
//     section, so the model treats the task as authorized work;
//  3. Retries at most twice by default (the second asks to continue technical output from the interruption);
//     still refused → return as-is — never loops; POJUN_REFUSAL_GUARD=0 disables; POJUN_REFUSAL_RETRIES=0..3 tunes retries.
//
// This doesn't bypass model safety policy: request content, tool permissions and platform intercept rules
// stay unchanged — it just clarifies the authorization info and required output, reducing mis-refusals.

import (
	"context"
	"iter"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/Autumn-27/norma/llm"
	"github.com/chu0119/pojun/llmguard"
)

// LooksLikeRefusal keeps the legacy exported name; implementation delegates to llmguard (for tests/external callers).
func LooksLikeRefusal(text string) bool { return llmguard.LooksLikeRefusal(text) }

var refusalRetries atomic.Int64

// RefusalRetryCount returns the process-wide count of 'mis-refusal → rephrasing retry' events (for logs/debugging).
func RefusalRetryCount() int64 { return refusalRetries.Load() }

type refusalGuard struct {
	inner   llm.Provider
	retries int
}

// GuardRefusal wraps a provider, enabling 'refusal → rephrase retry'. On by default;
// POJUN_REFUSAL_GUARD=0 disables; POJUN_REFUSAL_RETRIES controls retries (default 2).
func GuardRefusal(p llm.Provider) llm.Provider {
	if p == nil {
		return p
	}
	if v := strings.TrimSpace(os.Getenv("POJUN_REFUSAL_GUARD")); v == "0" || strings.EqualFold(v, "off") {
		return p
	}
	retries := 2
	if v := strings.TrimSpace(os.Getenv("POJUN_REFUSAL_RETRIES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n < 0 {
				n = 0
			}
			if n > 3 {
				n = 3
			}
			retries = n
		}
	}
	return &refusalGuard{inner: p, retries: retries}
}

// reframed appends the attempt-th (1-based) retry note to a request. An identical note isn't appended twice
// (edge case: the same request wrapped in two layers).
func reframed(req llm.CompletionRequest, attempt int) llm.CompletionRequest {
	out := req
	hint := llmguard.Hint(attempt)
	for _, s := range req.System {
		if strings.Contains(s, hint) {
			return out
		}
	}
	out.System = append(append([]string{}, req.System...), hint)
	return out
}

func textOfMessage(m llm.Message) string {
	var b strings.Builder
	for _, c := range m.Content {
		if c.Type == llm.BlockText {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// Complete implements the non-streaming path: on refusal, retry with rephrasing — at most g.retries times.
// Auto-retry only happens when the system prompt carries the platform-injected authorized-task framing;
// normal assistant/unknown requests don't auto-retry — avoids treating real boundary requests as mis-refusals.
func (g *refusalGuard) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, text, usage, err := g.inner.Complete(ctx, req)
	if err != nil {
		return msg, text, usage, err
	}
	if !llmguard.HasAuthorizationContext(req.System) {
		return msg, text, usage, nil
	}
	for attempt := 1; attempt <= g.retries; attempt++ {
		kind := llmguard.ClassifyRefusal(text)
		if kind == llmguard.RefusalNone {
			return msg, text, usage, nil
		}
		refusalRetries.Add(1)
		log.Printf("[llm] %s refusal detected — rephrase-retrying 'authorization+technical output' %d/%d", refusalKindLabel(kind), attempt, g.retries)
		msg2, text2, usage2, err2 := g.inner.Complete(ctx, reframed(req, attempt))
		if err2 != nil {
			// Retry failures must pass err2 through: returning the old err (always nil) makes the engine treat
			// refusal text as success — skipping model_error/quota branches (inconsistent with Stream's error pass-through).
			return msg, text, usage, err2
		}
		msg, text, usage = msg2, text2, usage2
	}
	return msg, text, usage, nil
}

func refusalKindLabel(kind llmguard.RefusalKind) string {
	if kind == llmguard.RefusalConditional {
		return "conditional"
	}
	return "explicit"
}

// Stream implements the streaming path: buffer an opening text window, decide — on refusal, discard and retry,
// otherwise replay buffered events and continue passing through — callers never see 'refused then re-answered'.
func (g *refusalGuard) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		authOK := llmguard.HasAuthorizationContext(req.System)
		for attempt := 0; attempt <= g.retries; attempt++ {
			r := req
			if attempt > 0 {
				r = reframed(req, attempt)
			}
			retry, ok := g.streamAttempt(ctx, r, authOK && attempt < g.retries, yield)
			if !ok {
				return
			}
			if !retry {
				return
			}
			refusalRetries.Add(1)
			log.Printf("[llm] streaming reply looks like a mis-refusal — rephrase-retrying 'authorization+technical output' %d/%d", attempt+1, g.retries)
		}
	}
}

// streamAttempt runs one inner stream. retry=true means 'judged refusal, retry allowed' — buffered events
// get discarded; ok=false means the caller stopped consuming (yield returned false).
func (g *refusalGuard) streamAttempt(
	ctx context.Context,
	req llm.CompletionRequest,
	allowRetry bool,
	yield func(llm.StreamEvent, error) bool,
) (retry bool, ok bool) {
	const decideRunes = 160
	var (
		buf     []llm.StreamEvent
		text    strings.Builder
		decided bool
		flushed bool
	)
	flush := func() bool {
		for _, ev := range buf {
			if !yield(ev, nil) {
				return false
			}
		}
		buf = nil
		flushed = true
		return true
	}
	for ev, err := range g.inner.Stream(ctx, req) {
		if err != nil {
			if !flushed {
				flush()
			}
			yield(ev, err)
			return false, false
		}
		if decided {
			if !yield(ev, nil) {
				return false, false
			}
			continue
		}
		// Thinking deltas pass through live (else long-thinking models look 'stuck'); refusal checks body only.
		if ev.Type == llm.SEThinkingDelta || ev.Type == llm.SEThinkingSignature {
			if !yield(ev, nil) {
				return false, false
			}
			continue
		}
		buf = append(buf, ev)
		switch ev.Type {
		case llm.SETextDelta:
			text.WriteString(ev.Text)
		case llm.SEToolUseStart, llm.SEToolInputJSON:
			// Starting to call tools means the model accepted the task — not a refusal.
			decided = true
		}
		if !decided && utf8.RuneCountInString(text.String()) < decideRunes && ev.Type != llm.SEMessageStop {
			continue
		}
		decided = true
		if allowRetry && llmguard.ClassifyRefusal(text.String()) != llmguard.RefusalNone {
			return true, true
		}
		if !flush() {
			return false, false
		}
	}
	if !decided && allowRetry && llmguard.ClassifyRefusal(text.String()) != llmguard.RefusalNone {
		return true, true
	}
	if !flushed {
		if !flush() {
			return false, true
		}
	}
	return false, true
}
