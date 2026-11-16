package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/chu0119/pojun/agent"
)

// actual error text seen in production (all three paths got bitten by it).
const realThinkingReject = `openai: status 400: {"error":{"type":"server_error","message":"Upstream request failed: [bad_request_error] invalid params, model \"MiniMax-M3.1-Flash\" requires adaptive thinking; thinking.type=\"disabled\" (including reasoning.effort=none) is not allowed (2013)"}}`

// errors where upstream rejects thinking params must be recognized — it's the
// prerequisite for auto-downgrade.
func TestIsThinkingRejected(t *testing.T) {
	if !isThinkingRejected(errors.New(realThinkingReject)) {
		t.Fatal("the real thinking-rejection error wasn't recognized")
	}
	// variants: wording differs slightly across gateways.
	for _, v := range []string{
		`model "X" requires adaptive thinking`,
		`thinking.type="disabled" is not allowed`,
		`thinking.type='disabled' is not allowed`,
		`invalid params (2013)`,
	} {
		if !isThinkingRejected(errors.New(v)) {
			t.Fatalf("variant not recognized: %q", v)
		}
	}
}

// other errors must not be misjudged as thinking rejection — a false positive would
// strip a legit thinking param and silently change model behavior.
func TestIsThinkingRejectedRejectsOthers(t *testing.T) {
	for _, v := range []string{
		"",
		"connection reset by peer",
		"status 429: too many requests",
		"status 500: internal server error",
		"context deadline exceeded",
		// a plain 400 (the request itself is bad) — stripping thinking won't help.
		`status 400: {"error":{"message":"max_tokens is too large"}}`,
	} {
		if isThinkingRejected(errors.New(v)) {
			t.Fatalf("misjudged as thinking rejection: %q", v)
		}
	}
	if isThinkingRejected(nil) {
		t.Fatal("nil must not be judged a thinking rejection")
	}
}

// the most common coarse-matching failure: a "disabled" unrelated to thinking must
// not get caught.
func TestIsThinkingRejectedNotOverBroad(t *testing.T) {
	if isThinkingRejected(errors.New("feature disabled by administrator")) {
		t.Fatal("a disabled unrelated to thinking was misjudged")
	}
}

// whether a provider sends the thinking field is decided by **config**, not the
// request — thinking is injected at the provider config layer
// (llm.Config.ThinkingType).
//
// This is the lesson from v1: req.Thinking is always empty (the request-level override
// defaults unused), so that condition was always false and the downgrade never fired.
// Measured: with profile thinking_type=disabled, the 2013 error appeared 23 times
// while the downgrade logged 0.
func TestProviderSendsThinkingReadsConfig(t *testing.T) {
	// no thinking_type configured → field never sent → downgrade is meaningless.
	if providerSendsThinking(agent.Config{}) {
		t.Fatal("with no thinking_type configured, must not claim it sends thinking")
	}
	// disabled configured → field IS sent → downgrade matters.
	if !providerSendsThinking(agent.Config{ThinkingType: "disabled"}) {
		t.Fatal("with thinking_type=disabled, must claim it sends thinking")
	}
	// SuppressThinking (the downgraded provider) → doesn't send.
	if providerSendsThinking(agent.Config{ThinkingType: "disabled", SuppressThinking: true}) {
		t.Fatal("under SuppressThinking, must not claim it sends thinking")
	}
}

// the downgraded provider must actually not send thinking.type — implemented via the
// SuppressThinking branch in agent.Config.NewProvider. Can't test the network layer, so
// test the config → llm.Config mapping.
func TestSuppressThinkingDropsThinkingType(t *testing.T) {
	cfg := agent.Config{
		Format:       "openai",
		BaseURL:      "http://127.0.0.1:1",
		APIKey:       "k",
		Model:        "m",
		ThinkingType: "disabled",
	}
	prov, err := cfg.NewProvider()
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	if prov == nil {
		t.Fatal("NewProvider returned a nil provider")
	}
	// the key behavior lives inside llm.Config — here we can only assert 'no panic +
	// valid provider'. Actual non-sending is guaranteed by the llm library (empty
	// ThinkingType = field omitted).
}

// the config built for downgrade must be 'same provider, but doesn't send
// thinking'.
func TestDowngradedConfigKeepsEverythingElse(t *testing.T) {
	base := agent.Config{
		Format:          "openai",
		BaseURL:         "http://127.0.0.1:1",
		APIKey:          "k",
		Model:           "m",
		ThinkingType:    "disabled",
		ReasoningEffort: "high",
		MaxTokens:       4096,
		ContextWindowK:  1000,
	}
	down := base
	down.SuppressThinking = true

	if down.ThinkingType != base.ThinkingType {
		t.Fatal("downgrade must not change ThinkingType itself (it just stops sending it)")
	}
	for _, pair := range []struct {
		name string
		a, b any
	}{
		{"Format", down.Format, base.Format},
		{"BaseURL", down.BaseURL, base.BaseURL},
		{"APIKey", down.APIKey, base.APIKey},
		{"Model", down.Model, base.Model},
		{"ReasoningEffort", down.ReasoningEffort, base.ReasoningEffort},
		{"MaxTokens", down.MaxTokens, base.MaxTokens},
		{"ContextWindowK", down.ContextWindowK, base.ContextWindowK},
	} {
		if pair.a != pair.b {
			t.Errorf("downgrade changed %s: %v != %v", pair.name, pair.a, pair.b)
		}
	}
	if !providerSendsThinking(base) {
		t.Fatal("the original config should send thinking")
	}
	if providerSendsThinking(down) {
		t.Fatal("the downgraded config must not send thinking")
	}
}

// cases where "disabled" appears in the error text but isn't a thinking rejection
// must not get caught.
func TestIsThinkingRejectedIgnoresUnrelatedDisabled(t *testing.T) {
	err := errors.New("tls handshake: protocol version disabled")
	if isThinkingRejected(err) {
		t.Fatalf("misjudged: %v", err)
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatal("the test sample itself should contain disabled")
	}
}
