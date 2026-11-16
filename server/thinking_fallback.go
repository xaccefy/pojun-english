package server

import (
	"strings"

	"github.com/Autumn-27/norma/llm"
	"github.com/chu0119/pojun/agent"
)

// Detection of thinking-parameter rejection errors, with automatic downgrade.
//
// ## Why this deserves its own file
//
// Models like MiniMax-M3.1 that **mandate adaptive thinking** flatly reject
// thinking.type="disabled" (and reasoning.effort=none):
//
//	400 {"error":{"type":"server_error","message":"Upstream request failed:
//	 [bad_request_error] invalid params, model \"MiniMax-M3.1-Flash\" requires
//	 adaptive thinking; thinking.type=\"disabled\" (including reasoning.effort=none)
//	 is not allowed (2013)"}}
//
// This trap has been stepped on **three times** in POJUN already: the judge path
// (server/intercept.go), the compaction path (agent/compaction.go), the side-question
// summary path (sidequestion/context.go) — each hardcoded thinking params, each fixed
// once, and any new code carrying thinking would relapse a fourth time.
//
// Measured cost is not light: in the two hours after a live config switch (LongCat →
// minimax-m3.1), 787 judge failures + 130 compaction failures — **all the same 400**.
// Every judge failure fell back to 'apply failure policy', so 787 tool calls were
// silently allowed — the judge gate was effectively dead for those two hours.
//
// ## Why the fallback lives here
//
// llmpool's shouldFailover explicitly classifies 400 as 'don't switch' —
// "a malformed or over-long request fails identically everywhere".
// that call is right for 'the request itself is bad', but a thinking rejection is a
// **parameter-config problem**, not a request problem: drop the thinking field and the
// same request succeeds.
//
// So at the unified entry for task-side LLM calls (taskLLMRuntime.Stream / Complete)
// we do one 'detect → swap provider → retry verbatim' — errors self-heal, and no caller
// has to remember not to write thinking.
//
// ## Why the downgrade must swap provider, not the request
//
// The thinking parameter is injected at the **provider config layer**
// (llm.Config.ThinkingType — see NewProvider in agent/provider.go), **not in
// llm.CompletionRequest**. req.Thinking is always empty (it's the per-call override for
// profile settings — not the same thing as profile-level thinking_type).
//
// So the first implementation (mutating req.Thinking) **never fired** — the
// requestHasThinking(req) condition is always false. Measured: with profile
// thinking_type=disabled, the 2013 error appeared 23 times as expected while the
// downgrade log stayed 0.
//
// The correct downgrade is **rebuilding a provider that sends no thinking.type**
// (agent.Config.SuppressThinking) and retrying within the same call.

// thinkingRejectedMarkers are the signature strings an upstream emits when rejecting
// thinking params.
//
// Matched lowercase since gateways' casing varies (observed both "requires adaptive
// thinking" and "thinking.type=\"disabled\" is not allowed"; the 2013 code comes from
// the gateway, not the model).
var thinkingRejectedMarkers = []string{
	"requires adaptive thinking",
	"thinking.type=\"disabled\"",
	"thinking.type='disabled'",
	"is not allowed (2013)",
	"2013)", // catch-all: some gateways return only the error code
}

// isThinkingRejected reports whether err is a 'model rejected thinking params' error.
//
// It looks only for signatures in the error text, not HTTP status: upstreams wrap the
// 400 inside server_error, stdlib statusOf may never see the 400, while the text
// signature appeared reliably in all three real incidents.
func isThinkingRejected(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, m := range thinkingRejectedMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// providerSendsThinking reports whether the provider's config sends thinking.type.
//
// Judged by **config** (agent.Config.ThinkingType), not the request — requests never
// carry this param (see file header).
func providerSendsThinking(cfg agent.Config) bool {
	if cfg.SuppressThinking {
		return false
	}
	return cfg.ThinkingType != ""
}

// keep the llm import (the downgraded provider is still an llm.Provider).
var _ llm.Provider = (llm.Provider)(nil)
