package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/llmrec"
)

type taskAgentBundle struct {
	runtime        *taskLLMRuntime // goal decomposition runtime
	plannerRuntime *taskLLMRuntime
	workerRuntime  *taskLLMRuntime
	mainRuntime    *taskLLMRuntime
	pl             *agent.Planner
	wk             *agent.Worker
	main           *agent.MainAgent
}

type llmAuditProfile struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Format string `json:"format"`
	Model  string `json:"model"`
}

type llmTransitionAudit struct {
	Mode     string           `json:"mode"` // automatic | manual | exhausted
	Reason   string           `json:"reason"`
	Previous *llmAuditProfile `json:"previous,omitempty"`
	Next     *llmAuditProfile `json:"next,omitempty"`
}

type llmActivityMetadata struct {
	LLMTransition llmTransitionAudit `json:"llm_transition"`
}

type taskLLMRuntime struct {
	s        *Server
	taskID   string
	agentKey string
	// pin > 0 pins this runtime to that profile forever (B10: fixed-purpose users like
	// the compactor), overriding agent binding and the task chain; a dead profile
	// (deleted / no key) falls back to the original chain. It doesn't advance the task
	// chain's failover state (binding semantics) and doesn't join chain rotation.
	pin int64
}

type taskLLMError struct {
	taskID         string
	chainExhausted bool
	cause          error
}

func (e *taskLLMError) Error() string {
	if e.chainExhausted {
		return fmt.Sprintf("task %s LLM profile chain exhausted: %v", e.taskID, e.cause)
	}
	return e.cause.Error()
}

func (e *taskLLMError) Unwrap() error { return e.cause }

func isTaskLLMRuntimeError(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target)
}

func isTaskLLMChainExhausted(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target) && target.chainExhausted
}

// isQuotaExhaustedError is intentionally strict. A generic 429, auth error,
// network failure, or 5xx does not rotate providers; the response must explicitly
// identify quota, credits, billing balance, or payment exhaustion.
func isQuotaExhaustedError(err error) bool {
	return err != nil && agent.IsQuotaExhaustedMessage(err.Error())
}

type taskLLMSelection struct {
	task      *Task
	profileID int64
	revision  int64
	provider  llm.Provider
	// retry is the retry params resolved for the selected config (profile override →
	// global policy → built-in default). Same-provider safe-window retries follow it —
	// switching profiles switches the retry rhythm too.
	retry agent.RetryConfig
}

type taskLLMStreamHooks struct {
	current    func() (taskLLMSelection, error)
	exhaust    func(taskLLMSelection, error) (db.TaskLLMTransition, error)
	transition func(taskLLMSelection, db.TaskLLMTransition, error)
	// withoutThinking resolves an equivalent provider that **doesn't send the
	// thinking.type field**, for the 'model rejects thinking params' downgrade retry (see
	// thinking_fallback.go).
	//
	// Why it's needed: the thinking parameter is injected at the **provider config
	// layer** (llm.Config.ThinkingType), not in llm.CompletionRequest — so downgrading
	// can't happen by changing the request, only by swapping the provider.
	//
	// nil = no downgrade support (2013 then bubbles up as usual).
	withoutThinking func() (llm.Provider, error)
}

// current resolves the provider this role runs on, by precedence:
// pinned profile (B10) → agent binding → task LLM profile chain → global/env config.
// pin and binding share semantics: quota errors don't advance the task chain. Binding
// beats the task chain: a role with an explicitly assigned model keeps running on it;
// only when no binding exists or building it fails does it degrade to the task chain, and
// only to the global config when the chain is empty.
// The returned profile id is non-zero only on the task-chain path — streamTaskLLM uses
// that to decide whether a quota error should advance the task's failover state
// (binding/global paths never touch task-chain state — existing semantics).
func (r *taskLLMRuntime) current() (taskLLMSelection, error) {
	// pin caller (B10 compactor and other fixed-purpose users): a valid pinned profile
	// returns immediately, skipping the task-state DB read. A dead profile (deleted / no
	// key) falls back to the original chain below — no hard failure.
	if r.pin > 0 {
		if prov, cfg, ok := r.s.providerForProfile(r.pin); ok {
			return taskLLMSelection{provider: prov, retry: cfg.Retry}, nil
		}
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return taskLLMSelection{}, err
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil {
		return taskLLMSelection{}, err
	}
	if pt == nil {
		return taskLLMSelection{}, fmt.Errorf("task %s not found", r.taskID)
	}
	r.s.syncTaskLLMState(pt)
	t, _ := r.s.m.Task(r.taskID)
	sel := taskLLMSelection{task: t, revision: pt.LLMChainRevision}
	if prov, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		sel.provider, sel.retry = prov, cfg.Retry
		return sel, nil
	}
	if len(pt.LLMProfileIDs) > 0 {
		if pt.ActiveLLMProfileID == nil {
			return sel, &taskLLMError{taskID: r.taskID, chainExhausted: true, cause: errors.New("all selected profiles are quota exhausted")}
		}
		sel.profileID = *pt.ActiveLLMProfileID
		prov, cfg, ok := r.s.providerForProfile(sel.profileID)
		if !ok {
			return sel, fmt.Errorf("LLM profile #%d is missing or invalid", sel.profileID)
		}
		sel.provider, sel.retry = prov, cfg.Retry
		return sel, nil
	}
	prov, cfg, ok := r.s.globalProvider()
	if !ok {
		return sel, fmt.Errorf("task %s has no available fallback LLM provider", r.taskID)
	}
	sel.provider, sel.retry = prov, cfg.Retry
	return sel, nil
}

// activeCfg resolves the task's currently-active LLM config, mirroring current()'s
// source precedence (pin → agent binding → active chain profile → global). Read-only and
// best-effort: ok=false when nothing resolves, leaving the per-setting fallback to
// the caller. If failover switches profiles, the change takes effect on the next
// agent run (a fresh Session is built per run in captureRun).
func (r *taskLLMRuntime) activeCfg() (agent.Config, bool) {
	// pin caller (B10): same as current()'s pin branch — prefer the pinned config.
	if r.pin > 0 {
		if _, cfg, ok := r.s.providerForProfile(r.pin); ok {
			return cfg, true
		}
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return agent.Config{}, false
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil || pt == nil {
		return agent.Config{}, false
	}
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg, true
	}
	if len(pt.LLMProfileIDs) > 0 && pt.ActiveLLMProfileID != nil {
		if _, cfg, ok := r.s.providerForProfile(*pt.ActiveLLMProfileID); ok {
			return cfg, true
		}
	}
	if _, cfg, ok := r.s.globalProvider(); ok {
		return cfg, true
	}
	return agent.Config{}, false
}

// nonStreaming reports whether the task's currently-active LLM source is set to
// non-streaming. Unresolvable → streaming (false), the safe default.
func (r *taskLLMRuntime) nonStreaming() bool {
	cfg, ok := r.activeCfg()
	return ok && !cfg.Stream
}

// maxTokens returns the currently-active source's per-reply output cap.
// Unresolvable → 0, i.e. send no cap, matching the pre-setting behaviour.
func (r *taskLLMRuntime) maxTokens() int {
	cfg, _ := r.activeCfg() // zero value 0 when no config resolves
	return cfg.MaxTokens
}

func parseTaskID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid task id %q", id)
	}
	return n, nil
}

// streamHooks builds the failover/exhaustion callbacks shared by Stream and
// Complete: how to read the current profile selection, how to mark it quota
// exhausted, and how to emit a failover transition.
func (r *taskLLMRuntime) streamHooks() taskLLMStreamHooks {
	return taskLLMStreamHooks{
		current: r.current,
		exhaust: func(selection taskLLMSelection, cause error) (db.TaskLLMTransition, error) {
			taskNum, _ := parseTaskID(r.taskID)
			transition, err := r.s.m.pg.MarkTaskLLMProfileQuotaExhaustedAtRevision(taskNum, selection.profileID, selection.revision, cause.Error())
			if err != nil {
				return transition, err
			}
			if pt, getErr := r.s.m.pg.GetTask(taskNum); getErr == nil && pt != nil {
				r.s.syncTaskLLMState(pt)
			}
			return transition, nil
		},
		transition: func(selection taskLLMSelection, transition db.TaskLLMTransition, cause error) {
			r.s.emitTaskLLMTransition(selection.task, transition, cause)
		},
		withoutThinking: r.withoutThinking,
	}
}

// configForSelection resolves the LLM config for a selection (same priority order as
// current()).
//
// current() only hands out the provider; a downgrade retry needs **the config itself**
// to rebuild a thinking-free provider, so this resolves once more in the same order.
//
// agentKey empty = skip the agent-binding level (the caller already knows its result).
func (s *Server) configForSelection(agentKey string, sel taskLLMSelection) (agent.Config, bool) {
	// 1) agent binding
	if agentKey != "" {
		if prov, cfg, ok := s.agentBindingProvider(agentKey); ok && prov != nil {
			return cfg, true
		}
	}
	// 2) the task chain's current profile
	if sel.profileID > 0 {
		if _, cfg, ok := s.providerForProfile(sel.profileID); ok {
			return cfg, true
		}
	}
	// 3) global
	if _, cfg, ok := s.globalProvider(); ok {
		return cfg, true
	}
	return agent.Config{}, false
}

// withoutThinking resolves an equivalent provider that doesn't send thinking.type.
//
// It reuses current()'s resolution path (binding → task chain → global), only clearing
// ThinkingType from the resolved config before rebuilding the provider. The rebuilt
// provider **never enters the provider cache** — it exists for this one downgrade retry;
// caching it would strip the thinking parameter from every later call, silently altering
// the user's config.
//
// When no equivalent config resolves (no resolvable profile) it errors, and the caller
// bubbles the original error.
func (r *taskLLMRuntime) withoutThinking() (llm.Provider, error) {
	sel, err := r.current()
	if err != nil {
		return nil, err
	}
	// current() already resolved the config but only handed out the provider; cfg itself
	// is needed here to rebuild. So resolve once more in the same priority order.
	cfg, ok := r.s.configForSelection(r.agentKey, sel)
	if !ok {
		return nil, fmt.Errorf("cannot resolve an LLM config for the downgrade retry (profile %d)", sel.profileID)
	}
	if cfg.ThinkingType == "" {
		// thinking.type was never sent — downgrading is meaningless; let the caller bubble
		// the original error.
		return nil, fmt.Errorf("the current config sends no thinking parameter — nothing to downgrade")
	}
	cfg.SuppressThinking = true
	prov, err := cfg.NewProvider()
	if err != nil {
		return nil, err
	}
	return prov, nil
}

func (r *taskLLMRuntime) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	return streamTaskLLM(ctx, r.taskID, req, r.streamHooks())
}

// Complete is the non-streaming counterpart of Stream. A non-streaming call is
// atomic — it never delivers partial output — so every failure is safe to retry
// on the same provider or fail over to the next profile without risking
// duplicated model output or tool execution (the "committed" bookkeeping the
// streaming path needs is unnecessary here).
func (r *taskLLMRuntime) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	return completeTaskLLM(ctx, r.taskID, req, r.streamHooks())
}

func completeTaskLLM(ctx context.Context, taskID string, req llm.CompletionRequest, hooks taskLLMStreamHooks) (llm.Message, string, llm.Usage, error) {
	// the thinking downgrade happens at most once (same as streamTaskLLM, see
	// thinking_fallback.go). Downgrade means **swapping providers**, not editing the
	// request — the thinking parameter lives in provider config.
	downgradedProv, thinkingDowngraded := llm.Provider(nil), false
	for {
		selection, err := hooks.current()
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		var (
			msg     llm.Message
			sr      string
			usage   llm.Usage
			callErr error
		)
		// same-provider safe-window retry: a non-streaming call either wholly succeeds
		// or wholly fails — no mid-call output is delivered — so any transient failure
		// can be replayed verbatim.
		retries, backoffOf := sameProviderRetryPolicy(selection.retry)
		for attempt := 0; ; attempt++ {
			prov := selection.provider
			if downgradedProv != nil {
				prov = downgradedProv
			}
			msg, sr, usage, callErr = prov.Complete(ctx, req)
			// model rejects the thinking parameter → retry once with a thinking-free provider.
			if callErr != nil && !thinkingDowngraded && ctx.Err() == nil &&
				hooks.withoutThinking != nil && isThinkingRejected(callErr) {
				alt, altErr := hooks.withoutThinking()
				if altErr == nil {
					thinkingDowngraded = true
					downgradedProv = alt
					log.Printf("[task-llm] task %s model rejects thinking params, retrying with a thinking-free provider: %v", taskID, callErr)
					continue
				}
				log.Printf("[task-llm] task %s model rejects thinking params but downgrade is impossible (%v) — original error stands", taskID, altErr)
			}
			if callErr != nil && ctx.Err() == nil &&
				attempt < retries && isRetryableStreamError(callErr) {
				backoff := backoffOf(attempt)
				log.Printf("[task-llm] task %s non-streaming call failed, retrying on same provider in %v (%d/%d): %v",
					taskID, backoff, attempt+1, retries, callErr)
				if sleepCtx(ctx, backoff) {
					break // ctx cancelled during backoff → stop retrying
				}
				continue
			}
			break
		}
		if callErr == nil {
			return msg, sr, usage, nil
		}
		// profileID=0: the explicit chain was cleared; non-quota error: pass through.
		// Neither touches the task failover state.
		if selection.profileID == 0 || !isQuotaExhaustedError(callErr) {
			return llm.Message{}, "", llm.Usage{}, callErr
		}
		transition, markErr := hooks.exhaust(selection, callErr)
		if markErr != nil {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("mark profile quota exhausted after %v: %w", callErr, markErr)
		}
		if transition.Advanced && !transition.Stale && hooks.transition != nil {
			hooks.transition(selection, transition, callErr)
		}
		if !transition.Stale && transition.NextProfileID == nil {
			return llm.Message{}, "", llm.Usage{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: callErr}
		}
		// no output reached the caller, so replaying the same logical request on the next
		// profile is safe.
	}
}

func streamTaskLLM(ctx context.Context, taskID string, req llm.CompletionRequest, hooks taskLLMStreamHooks) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		// thinking downgrade at most once: on 'model rejects thinking params', swap
		// providers and retry. The variable sits outside the closure because the
		// downgraded provider must persist across the whole for loop (profile switches
		// keep using this same one).
		cur := req
		downgradedProv, thinkingDowngraded := llm.Provider(nil), false
		for {
			selection, err := hooks.current()
			if err != nil {
				yield(llm.StreamEvent{}, err)
				return
			}
			committed := false
			var pending []llm.StreamEvent
			var streamErr error
			retries, backoffOf := sameProviderRetryPolicy(selection.retry)
			// same-provider safe-window retry: transient failures before `committed` (no
			// output delivered to the caller yet) replay verbatim — no duplicated model
			// output or tool execution. After committed, on ctx cancel, or on
			// deterministic/quota errors, break out to the original pass-through/failover
			// logic below.
			for attempt := 0; ; attempt++ {
				committed = false
				pending = nil
				streamErr = nil
				prov := selection.provider
				if downgradedProv != nil {
					prov = downgradedProv
				}
				for event, err := range prov.Stream(ctx, cur) {
					if err != nil {
						streamErr = err
						break
					}
					if !committed && !streamEventCommitsOutput(event) {
						pending = append(pending, event)
						continue
					}
					if !committed {
						for _, buffered := range pending {
							if !yield(buffered, nil) {
								return
							}
						}
						pending = nil
						committed = true
					}
					if !yield(event, nil) {
						return
					}
				}
				// model rejects thinking params (adaptive-thinking models refuse
				// thinking.type=disabled) → retry once with a thinking-free provider.
				//
				// Why a catch-all here instead of making every caller careful: this 400
				// has bitten POJUN three times (judgement / compaction / side-summary) —
				// each time a new call site hardcoded thinking. Fixed once at the shared
				// entry, it works everywhere.
				//
				// Downgrade must **swap providers**, not edit the request: the thinking
				// parameter lives in provider config (llm.Config.ThinkingType), not in
				// llm.CompletionRequest — v1 edited the request, the condition was always
				// false, never fired (observed: 2013 appeared 23 times, downgrade 0).
				//
				// Downgrade only once: if the swapped provider reports the same error, it
				// wasn't the thinking param — further retries just waste.
				if streamErr != nil && !committed && !thinkingDowngraded &&
					ctx.Err() == nil && hooks.withoutThinking != nil && isThinkingRejected(streamErr) {
					alt, altErr := hooks.withoutThinking()
					if altErr == nil {
						thinkingDowngraded = true
						downgradedProv = alt
						log.Printf("[task-llm] task %s model rejects thinking params, retrying with a thinking-free provider: %v", taskID, streamErr)
						continue
					}
					log.Printf("[task-llm] task %s model rejects thinking params but downgrade is impossible (%v) — original error stands", taskID, altErr)
				}
				if streamErr != nil && !committed && ctx.Err() == nil &&
					attempt < retries && isRetryableStreamError(streamErr) {
					backoff := backoffOf(attempt)
					log.Printf("[task-llm] task %s pre-commit stream failure, retrying on same provider in %v (%d/%d): %v",
						taskID, backoff, attempt+1, retries, streamErr)
					if sleepCtx(ctx, backoff) {
						break // ctx cancelled during backoff → stop retrying
					}
					continue
				}
				break
			}
			if streamErr == nil {
				for _, buffered := range pending {
					if !yield(buffered, nil) {
						return
					}
				}
				return
			}
			// profileID=0 means the explicit chain was cleared while this stable task
			// bundle was still in use. Agent/global fallback errors follow the legacy
			// behavior and never mutate task failover state.
			if selection.profileID == 0 || !isQuotaExhaustedError(streamErr) {
				for _, buffered := range pending {
					if !yield(buffered, nil) {
						return
					}
				}
				yield(llm.StreamEvent{}, streamErr)
				return
			}
			transition, markErr := hooks.exhaust(selection, streamErr)
			if markErr != nil {
				cause := fmt.Errorf("mark profile quota exhausted after %v: %w", streamErr, markErr)
				if committed {
					// Output may already have driven tool execution. Report the persistence
					// failure, but classify it as router-handled so the worker does not
					// replay the entire intent and duplicate those side effects.
					yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, cause: cause})
				} else {
					yield(llm.StreamEvent{}, cause)
				}
				return
			}
			if transition.Advanced && !transition.Stale && hooks.transition != nil {
				hooks.transition(selection, transition, streamErr)
			}
			if committed || (!transition.Stale && transition.NextProfileID == nil) {
				yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: streamErr})
				return
			}
			// No event reached the caller, so replaying the same logical request on
			// the next profile cannot duplicate model output or tool execution.
		}
	}
}

func streamEventCommitsOutput(event llm.StreamEvent) bool {
	switch event.Type {
	case llm.SETextDelta, llm.SEThinkingDelta, llm.SEToolInputJSON:
		return event.Text != ""
	case llm.SEToolUseStart, llm.SEMessageDelta, llm.SEMessageStop:
		return true
	default:
		return false
	}
}

// default retry count within the pre-commit safe window, on the same provider. The
// SDK's doStream only retries the connect phase (before the 200 arrives); once the stream
// starts, mid-stream drops / overloaded / in-stream 429s bubble straight up as
// model_error — zero retries. While not a single token has been delivered to the caller
// (!committed), replaying the identical request duplicates neither model output nor tool
// side effects, so this adds a same-provider backoff retry layer that keeps such jitters
// from forcing an intent-level rerun. Overridable by LLM-config retry overrides / the
// global retry policy.
const sameProviderStreamRetries = 2

// sameProviderRetryBackoff is the default backoff before attempt #N (0.5s, 1s, ...,
// capped at 4s) — same exponential style as the SDK but a smaller cap so it doesn't stall
// a worker's settle/cancel responsiveness. Exposed as a variable so tests can zero it.
var sameProviderRetryBackoff = func(attempt int) time.Duration {
	return min(500*time.Millisecond*(1<<attempt), 4*time.Second)
}

// sameProviderRetryPolicy resolves which same-provider retry params this call uses:
// a configured count wins (negative = disable this retry layer); a configured interval
// replaces the exponential backoff with a fixed one; with neither set, behavior is
// byte-identical to before configurability.
func sameProviderRetryPolicy(r agent.RetryConfig) (retries int, backoff func(int) time.Duration) {
	retries, backoff = sameProviderStreamRetries, sameProviderRetryBackoff
	if r.StreamAttempts != 0 {
		retries = max(r.StreamAttempts, 0)
	}
	if r.StreamInterval > 0 {
		d := r.StreamInterval
		backoff = func(int) time.Duration { return d }
	}
	return retries, backoff
}

// isRetryableStreamError decides whether a pre-commit stream failure is worth replaying
// on the same provider. Transient transport drops / provider overload / rate limits heal
// on their own — safe to retry; these three are not:
//   - quota exhausted: the profile failover handles it — don't burn retries here
//   - context too long: replaying the same request is useless — the harness's reactive
//     compaction is the backstop
//   - deterministic 4xx rejections (400/401/403/404/422): every provider fails the same
func isRetryableStreamError(err error) bool {
	if err == nil {
		return false
	}
	if isQuotaExhaustedError(err) {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "too long") || strings.Contains(s, "context length") ||
		strings.Contains(s, "context_length") || strings.Contains(s, "maximum context") ||
		strings.Contains(s, "status 413") {
		return false
	}
	for _, code := range []string{"status 400", "status 401", "status 403", "status 404", "status 422"} {
		if strings.Contains(s, code) {
			return false
		}
	}
	// everything else (transport reset/EOF/timeout, 408/429/5xx, in-stream error events
	// like anthropic's overloaded_error) counts as transient — retry allowed.
	return true
}

// CompactionWindow mirrors current()'s precedence so the context window always
// matches the provider the role will actually stream on.
func (r *taskLLMRuntime) CompactionWindow() int {
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg.CompactionWindow()
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	chain, err := r.s.m.pg.TaskLLMProfiles(taskNum)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	if len(chain) == 0 {
		if _, cfg, ok := r.s.globalProvider(); ok {
			return cfg.CompactionWindow()
		}
		return (agent.Config{}).CompactionWindow()
	}
	minimum := 0
	for _, entry := range chain {
		if cfg, ok := r.s.loadProfileConfig(entry.ProfileID); ok {
			window := cfg.CompactionWindow()
			if minimum == 0 || window < minimum {
				minimum = window
			}
		}
	}
	if minimum == 0 {
		return (agent.Config{}).CompactionWindow()
	}
	return minimum
}

// agentBindingProvider resolves the profile a role is explicitly bound to
// (agents.llm_profile_id) — the highest-precedence level for task agents. ok=false
// when the role has no binding or the bound profile no longer builds, so callers
// fall through to the task chain. A bound profile stays exclusive unless
// llm_pool_bind_fallback is on, which is what poolForBinding encodes.
func (s *Server) agentBindingProvider(agentKey string) (llm.Provider, agent.Config, bool) {
	id := s.effectiveProfileForAgent(agentKey, nil)
	if id == nil {
		return nil, agent.Config{}, false
	}
	prov, cfg, ok := s.providerForProfile(*id)
	if !ok {
		return nil, agent.Config{}, false
	}
	return s.poolForBinding(*id, prov, cfg), cfg, true
}

// globalProvider returns the process-wide provider (persisted active profile or
// environment config) — the last resort once a role has neither a binding nor a
// task chain.
func (s *Server) globalProvider() (llm.Provider, agent.Config, bool) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if !s.llmOn || s.llmProv == nil {
		return nil, agent.Config{}, false
	}
	return s.llmProv, s.llmCfg, true
}

// taskRuntimeAvailable reports whether every listed role can resolve a provider
// under the runtime precedence in current(): the role's own binding first, then
// the task chain, then global. An exhausted chain is a hard stop for unbound
// roles rather than a silent fall through to global — same as current().
func (s *Server) taskRuntimeAvailable(t *Task, agentKeys ...string) bool {
	if t == nil || len(agentKeys) == 0 {
		return false
	}
	state := t.llmStateSnapshot()
	unboundReady := false
	if len(state.ProfileIDs) > 0 {
		if state.ActiveID != nil {
			_, _, unboundReady = s.providerForProfile(*state.ActiveID)
		}
	} else {
		_, _, unboundReady = s.globalProvider()
	}
	for _, key := range agentKeys {
		if _, _, ok := s.agentBindingProvider(key); ok {
			continue
		}
		if !unboundReady {
			return false
		}
	}
	return true
}

func (s *Server) invalidateTaskAgents() {
	s.taskAgentMu.Lock()
	s.taskAgents = map[string]*taskAgentBundle{}
	s.taskAgentMu.Unlock()
}

func (s *Server) agentsForTask(t *Task) *taskAgentBundle {
	s.taskAgentMu.Lock()
	defer s.taskAgentMu.Unlock()
	if bundle := s.taskAgents[t.ID]; bundle != nil {
		return bundle
	}
	goalRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "goals"}
	plannerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "planner"}
	workerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "worker"}
	mainRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "mainagent"}
	tx := transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
	window := workerRuntime.CompactionWindow()
	// authorization-boundary guard switch (v0.4.63): read once per agent-bundle
	// assembly.
	var scopeGuard, scopeInherit, notifyDedup bool
	if s.m.PG() != nil {
		scopeGuard = s.m.PG().GetBool("scope_write_guard", true)
		scopeInherit = s.m.PG().GetBool("scope_inherit_writes", false)
		notifyDedup = s.m.PG().GetBool("notify_cross_task_dedup", true)
	} else {
		scopeGuard, notifyDedup = true, true
	}
	wk := agent.NewWorker(workerRuntime, "task-router", s.m.dir, tx, window, s.agentMaxTurns("worker"))
	wk.SetScopeFlags(scopeGuard, scopeInherit, notifyDedup)
	wk.SetFindingRecorder(s.evidenceStore())
	wk.SetArtifactRecorder(s) // v0.5.0 evidence attachments: save_evidence records to disk
	wk.SetCompactionWindowResolver(workerRuntime.CompactionWindow)
	wk.SetNonStreaming(workerRuntime.nonStreaming) // follows the task's active profile's streaming switch (read each round)
	wk.SetMaxTokens(workerRuntime.maxTokens)       // same — the output cap follows the active profile too
	wk.SetNoaEnabled(s.m.NoaCompactionEnabled)     // experimental: noa context compaction (platform switch, read per run)
	wk.SetRunTimeout(time.Duration(s.agentRunSeconds("worker")) * time.Second)
	wk.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	wk.SetWebSearch(s.webSearchFor("worker"))
	wk.SetConstraintInject(s.constraintInjectWorker) // operation-constraint injection into worker (configurable, default on)
	// task-level login credentials (v0.4.8): read once at assembly and injected into the
	// worker system prompt. Auth config is currently only entered at task creation; if an
	// edit API is added later, it must invalidate this task's agent bundle after saving so
	// the next round re-assembles.
	if s.m.PG() != nil {
		if id64, err := strconv.ParseInt(t.ID, 10, 64); err == nil {
			if pgTask, err2 := s.m.PG().GetTask(id64); err2 == nil && pgTask != nil && pgTask.AuthConfig != nil && pgTask.AuthConfig.Enabled {
				wk.SetTaskAuthBlock(pgTask.AuthConfig.PromptBlock())
			}
		}
	}
	pl := agent.NewPlanner(plannerRuntime, "task-router", s.m.dir, tx, plannerRuntime.CompactionWindow(), s.agentMaxTurns("planner"))
	pl.SetScopeFlags(scopeGuard, scopeInherit, notifyDedup)
	pl.SetIntentQueueLimit(s.intentQueueBudget) // dispatch throttle (v0.4.68): new-this-round cap
	pl.SetFindingRecorder(s.evidenceStore())
	pl.SetCompactionWindowResolver(plannerRuntime.CompactionWindow)
	pl.SetNonStreaming(plannerRuntime.nonStreaming)
	pl.SetMaxTokens(plannerRuntime.maxTokens)
	pl.SetNoaEnabled(s.m.NoaCompactionEnabled) // experimental: noa context compaction (platform switch, read per run)
	pl.SetKillWork(s.engine.KillWork)
	pl.SetSteerWork(s.engine.SteerWork)
	// Guard attributions → graph_overview's guard_attributions block (counts + B6 recent
	// samples; seeing blocked/error counts plus the blocked commands lets the planner
	// switch tactics — v0.3.88 checkup N5). t.Guard is always created at task creation in
	// manager.go.
	pl.SetAttributions(t.Guard.AttributionStats)
	pl.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	pl.SetWebSearch(s.webSearchFor("planner"))
	pl.SetConstraintInject(s.constraintInjectPlanner) // operation-constraint injection into planner (configurable, default on)
	// cold-digest §7: cold-node background compaction. What the engine actually drives
	// via the authoritative resolver is this per-task planner (agentsForTask), so the
	// Compactor must attach here. Compaction generates the body via a one-shot Complete.
	// B10: the compactor shares the planner's runtime by default (same task chain —
	// historical behavior); when compactor_profile_id is set it gets its own runtime
	// pinned to that profile — mechanical compaction is one-shot, a natural fit for cheap
	// fast models instead of burning the planner's long-session model quota. A dead pin
	// falls back to the original chain inside the runtime — no hard failure. Setting
	// updates apply to new tasks' bundles (invalidateTaskAgents in putSettings hands it
	// to running tasks' next round too).
	compactorRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "planner", pin: s.m.CompactorProfileID()}
	if compactorRuntime.pin > 0 {
		log.Printf("[compactor] task %s: compactor pinned to profile #%d", t.ID, compactorRuntime.pin)
	}
	compactor := agent.NewCompactor(compactorRuntime, "task-router")
	// the compaction output budget and wall-clock cap come from settings (0 = package
	// defaults). Both must be generous: a thinking model's thinking length inflates
	// linearly with the max_tokens budget — too small a budget means endless thinking
	// and zero body text (measured: 1500/2048/4096/8192 all produced empty bodies).
	compactor.SetOutputTokens(s.m.CompactionTokens())
	if secs := s.m.CompactionTimeout(); secs > 0 {
		compactor.SetMaxDuration(time.Duration(secs) * time.Second)
	}
	compactor.SetMaxBlockMembers(s.m.CompactionMaxMembers())
	pl.SetCompactor(compactor)
	main := agent.NewMainAgent(mainRuntime, "task-router", s.m.dir, tx, mainRuntime.CompactionWindow(), s.agentMaxTurns("mainagent"))
	main.SetScopeFlags(scopeGuard, scopeInherit, notifyDedup)
	main.SetFindingRecorder(s.evidenceStore())
	main.SetCompactionWindowResolver(mainRuntime.CompactionWindow)
	main.SetNonStreaming(mainRuntime.nonStreaming)
	main.SetMaxTokens(mainRuntime.maxTokens)
	main.SetNoaEnabled(s.m.NoaCompactionEnabled) // experimental: noa context compaction (platform switch, read per run)
	main.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	main.SetWebSearch(s.webSearchFor("mainagent"))
	main.SetSteerWork(s.engine.SteerWork)          // steer_work: human course-correction on running work
	main.SetAttributions(t.Guard.AttributionStats) // Guard attribution samples (B6) → overview (human-in-the-loop sees rejection counts and artifacts)
	bundle := &taskAgentBundle{
		runtime: goalRuntime, plannerRuntime: plannerRuntime, workerRuntime: workerRuntime,
		mainRuntime: mainRuntime, pl: pl, wk: wk, main: main,
	}
	s.taskAgents[t.ID] = bundle
	return bundle
}

func (s *Server) syncTaskLLMState(pt *db.Task) {
	if pt == nil {
		return
	}
	id := fmt.Sprintf("%d", pt.ID)
	s.m.mu.Lock()
	if task := s.m.tasks[id]; task != nil {
		task.setLLMState(pt.LLMProfileID, pt.ActiveLLMProfileID, pt.LLMProfileIDs, pt.LLMChainRevision, pt.LLMFailoverState, pt.LLMFailoverReason)
	}
	s.m.mu.Unlock()
}

func (s *Server) emitTaskLLMTransition(t *Task, transition db.TaskLLMTransition, cause error) {
	if t == nil {
		return
	}
	previous := s.llmAuditProfile(transition.PreviousProfileID)
	var next *llmAuditProfile
	if transition.NextProfileID != nil {
		next = s.llmAuditProfile(*transition.NextProfileID)
	}
	mode := "automatic"
	kind := "llm_switch"
	summary := fmt.Sprintf("%s: insufficient quota", llmAuditProfileLabel(previous))
	if transition.NextProfileID != nil {
		summary += fmt.Sprintf("; later calls switched to %s", llmAuditProfileLabel(next))
	} else {
		mode = "exhausted"
		kind = "llm_failover"
		summary += "; profile chain exhausted"
	}
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: mode, Reason: cause.Error(), Previous: previous, Next: next,
	}})
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: kind, IsError: transition.ChainExhausted, Summary: summary, Detail: cause.Error(), Metadata: metadata})
	log.Printf("[llm-failover] task %s: %s", t.ID, summary)
}

func (s *Server) llmAuditProfile(id int64) *llmAuditProfile {
	if id <= 0 || s.m == nil || s.m.pg == nil {
		return nil
	}
	p, err := s.m.pg.ProfileByID(id)
	if err != nil || p == nil {
		return &llmAuditProfile{ID: id, Name: fmt.Sprintf("profile #%d", id)}
	}
	return &llmAuditProfile{ID: p.ID, Name: p.Name, Format: p.Format, Model: p.Model}
}

func llmAuditProfileLabel(profile *llmAuditProfile) string {
	if profile == nil {
		return "default profile"
	}
	name := profile.Name
	if name == "" {
		name = fmt.Sprintf("profile #%d", profile.ID)
	}
	detail := []string{}
	if profile.Format != "" {
		detail = append(detail, profile.Format)
	}
	if profile.Model != "" {
		detail = append(detail, profile.Model)
	}
	if len(detail) == 0 {
		return name
	}
	return fmt.Sprintf("%s(%s)", name, strings.Join(detail, " / "))
}

func sameOptionalID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (s *Server) emitManualTaskLLMSwitch(t *Task, previousID, nextID *int64) db.Activity {
	previous := (*llmAuditProfile)(nil)
	next := (*llmAuditProfile)(nil)
	if previousID != nil {
		previous = s.llmAuditProfile(*previousID)
	}
	if nextID != nil {
		next = s.llmAuditProfile(*nextID)
	}
	summary := fmt.Sprintf("user manually switched task LLM from %s to %s", llmAuditProfileLabel(previous), llmAuditProfileLabel(next))
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: "manual", Reason: "user manually switched task LLM", Previous: previous, Next: next,
	}})
	return s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "llm_switch", Summary: summary, Detail: summary, Metadata: metadata})
}
