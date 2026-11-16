package server

import (
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// Server-side retry-policy resolution, see docs/LLM Retry Design.md. Of the five layers:
//   - connect / empty-response / same-provider safe window are 'per-endpoint': each LLM
//     profile may override the global default (a blank profile field inherits global;
//     unset globally uses the built-in default);
//   - circuit-break / intent rerun are process-wide, single global copy.
//
// The global policy reads one settings row from the DB; call sites are all low-frequency
// (building providers, work wrap-up, saving config) — not worth another cache layer. The
// circuit-break params are the exception: read on every failure path, so
// applyRetryPolicy pushes them into Registry for storage.

// retryPolicy reads the global policy; a nil DB yields the zero policy (all
// layers on their built-in defaults).
func (s *Server) retryPolicy() db.LLMRetryPolicy {
	if s.m == nil || s.m.pg == nil {
		return db.LLMRetryPolicy{}
	}
	return s.m.pg.LLMRetryPolicy()
}

// resolveRetry layers one profile's override on top of the global policy and
// converts the result into the form agent.Config carries. Rules combine field by
// field, so a profile that only pins an interval still inherits the global count.
func resolveRetry(o db.RetryOverride, pol db.LLMRetryPolicy) agent.RetryConfig {
	connect := o.Connect.Or(pol.Connect)
	empty := o.Empty.Or(pol.Empty)
	stream := o.Stream.Or(pol.Stream)
	return agent.RetryConfig{
		// counts keep the raw '0=default / negative=off' semantics here: the SDK's
		// MaxRetries / EmptyResponseRetries are fully isomorphic — let it resolve them.
		ConnectAttempts: connect.Attempts, ConnectInterval: connect.Interval(),
		EmptyAttempts: empty.Attempts, EmptyInterval: empty.Interval(),
		StreamAttempts: stream.Attempts, StreamInterval: stream.Interval(),
	}
}

// applyProfileRetry fills cfg.Retry for a profile read from the DB.
func (s *Server) applyProfileRetry(cfg *agent.Config, p *db.LLMProfile) {
	if p == nil {
		return
	}
	cfg.Retry = resolveRetry(p.Retry, s.retryPolicy())
}

// circuit-break (polling cooldown) defaults match llmpool's built-ins — overridden only
// when the user configured a value. Intent-rerun defaults live in engine.go's
// modelErrorRetries / modelErrorRetryBackoff.

// applyRetryPolicy pushes the process-wide layers of the policy into the objects
// that consume them on a hot path: the circuit-breaker registry. Called at
// startup and whenever the policy is saved.
func (s *Server) applyRetryPolicy() {
	pol := s.retryPolicy()
	if s.llmHealth != nil {
		s.llmHealth.SetPolicy(pol.Breaker.Attempts, pol.Breaker.Interval())
	}
}

// modelErrorRetryPolicy resolves the intent-level replay knobs (layer ⑤): how
// many times a model_error work is re-run and how long to back off between runs.
func (e *Engine) modelErrorRetryPolicy() (retries int, backoff time.Duration) {
	retries, backoff = modelErrorRetries, modelErrorRetryBackoff
	if e == nil || e.m == nil || e.m.pg == nil {
		return retries, backoff
	}
	rule := e.m.pg.LLMRetryPolicy().Intent
	if rule.Attempts != 0 {
		retries = max(rule.Attempts, 0)
	}
	if d := rule.Interval(); d > 0 {
		backoff = d
	}
	return retries, backoff
}

// emptyTurnNudgeLimit resolves how many empty-turn continuations one work may
// inject (see steerHooks.Stop). It deliberately reuses layer ②'s knob — 'empty-response
// retries': the two are two means to one end. The SDK layer handles 'not a single content
// block', by resending the same request verbatim; this one handles 'thinking only, no
// body, no tools', by appending an instruction so the model continues from its existing
// thinking (verbatim resend is useless for this context-shaped idling). The emptiness
// criteria differ because the SDK counts 'any event yielded' and thinking deltas are
// events — but a user configuring 'empty-response retries' means 'the model produced no
// substance, try again'; sharing one count across both layers matches that mental
// model.
//
// Reads the global policy, not a profile override: a run may switch profiles mid-flight
// via failover, and this is the whole intent's total gate — it must not change with the
// endpoint. Semantics isomorphic to the SDK's emptyRetries():
// 0 = default defaultEmptyTurnNudges; -1 (negative) = disable idle-turn continuation;
// >0 = use that value.
func (e *Engine) emptyTurnNudgeLimit() int {
	if e == nil || e.m == nil || e.m.pg == nil {
		return defaultEmptyTurnNudges
	}
	switch n := e.m.pg.LLMRetryPolicy().Empty.Attempts; {
	case n == 0:
		return defaultEmptyTurnNudges
	case n < 0:
		return 0
	default:
		return n
	}
}
