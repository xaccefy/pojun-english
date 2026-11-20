// Package intercept implements the user-configurable tool-call interception layer.
// Rules are loaded from the database, cached in memory, and evaluated in priority
// order (highest first) on every PreToolUse event. Three actions are supported:
//
//   - allow: immediately permits the call, skipping lower-priority rules.
//   - deny:  blocks the call and returns a message to the model.
//   - ask:   blocks the call, creates an intercept_pending record, writes an
//     activity to the active conversation, then waits for the user to approve or
//     deny via the /api/intercept/pending/{id}/decide endpoint.
//
// The timeout behaviour is configurable at runtime via SetTimeoutConfig.
package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chu0119/pojun/db"
)

// ctxKey is the unexported context key type to avoid collisions.
type ctxKey int

// ConvIDKey stores the active conversation ID in a context.Context so the
// interceptor can associate "ask" pending records with the right conversation.
const ConvIDKey ctxKey = 0

// WithConvID returns a child context carrying convID.
func WithConvID(ctx context.Context, convID int64) context.Context {
	return context.WithValue(ctx, ConvIDKey, convID)
}

// ConvIDFromContext extracts the conversation ID (0 if absent).
func ConvIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(ConvIDKey).(int64)
	return v
}

// taskCtxKey is a separate unexported key type for task context values.
type taskCtxKey int

const (
	taskInfoCtxKey taskCtxKey = 1
	taskEmitCtxKey taskCtxKey = 2
	// autopilotCtxKey is the autopilot switch reader (checked per call, so turning the
	// switch off mid-flight restores normal task semantics on the next planning/run).
	autopilotCtxKey taskCtxKey = 3
)

// WithAutopilot injects the autopilot switch reader (nil / false = normal task).
// Only decides whether to append the autopilot tail to the system prompt; it changes no
// approval or intercept semantics.
func WithAutopilot(ctx context.Context, enabled func() bool) context.Context {
	return context.WithValue(ctx, autopilotCtxKey, enabled)
}

// AutopilotFromContext returns the autopilot switch reader; nil when not injected.
func AutopilotFromContext(ctx context.Context) func() bool {
	f, _ := ctx.Value(autopilotCtxKey).(func() bool)
	return f
}

type taskCtxInfo struct{ taskID, agentName string }

// WithTaskContext injects task metadata and an emit function into ctx so that
// HandleAsk can tag pending records and write intercept_request activities to
// the task's exploration stream (making them appear inline in session transcripts).
func WithTaskContext(ctx context.Context, taskID, agentName string, emit func(db.Activity)) context.Context {
	ctx = context.WithValue(ctx, taskInfoCtxKey, taskCtxInfo{taskID, agentName})
	if emit != nil {
		ctx = context.WithValue(ctx, taskEmitCtxKey, emit)
	}
	return ctx
}

func taskInfoFromCtx(ctx context.Context) (taskID, agentName string) {
	if v, ok := ctx.Value(taskInfoCtxKey).(taskCtxInfo); ok {
		return v.taskID, v.agentName
	}
	return "", ""
}

func taskEmitFromCtx(ctx context.Context) func(db.Activity) {
	f, _ := ctx.Value(taskEmitCtxKey).(func(db.Activity))
	return f
}

// compiledRule is an InterceptRule with the regex pre-compiled (nil for string rules).
type compiledRule struct {
	db.InterceptRule
	re *regexp.Regexp
}

// pendingManager tracks in-flight "ask" requests via per-request channels.
type pendingManager struct {
	mu sync.Mutex
	ch map[int64]chan bool
}

func newPendingManager() *pendingManager { return &pendingManager{ch: map[int64]chan bool{}} }

func (p *pendingManager) add(id int64) chan bool {
	ch := make(chan bool, 1)
	p.mu.Lock()
	p.ch[id] = ch
	p.mu.Unlock()
	return ch
}

func (p *pendingManager) resolve(id int64, allowed bool) {
	p.mu.Lock()
	ch, ok := p.ch[id]
	delete(p.ch, id)
	p.mu.Unlock()
	if ok {
		ch <- allowed
	}
}

func (p *pendingManager) remove(id int64) {
	p.mu.Lock()
	delete(p.ch, id)
	p.mu.Unlock()
}

// Reviewer runs the LLM fallback judge for one tool call and returns its verdict
// as a Decision (Action ∈ allow|ask|deny; empty Action means the reply could not
// be parsed). It is injected by the server layer so the intercept package stays
// free of any llm dependency. profileID == 0 means "use the active/default profile".
type Reviewer func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error)

// Interceptor loads intercept rules from the database and evaluates them on
// tool calls. It is safe for concurrent use.
type Interceptor struct {
	db              *db.DB
	mu              sync.RWMutex
	cached          []compiledRule  // sorted by priority DESC; nil means not loaded yet
	enabledTools    map[string]bool // nil means not loaded yet
	enabledPrefixes []string        // '*' suffix entries → prefix match (e.g. mcp__*)
	pending         *pendingManager
	reviewer        Reviewer // nil = LLM fallback judge not wired
}

// SetReviewer installs the LLM fallback judge callback. Passing nil disables it.
func (i *Interceptor) SetReviewer(r Reviewer) {
	i.mu.Lock()
	i.reviewer = r
	i.mu.Unlock()
}

// defaultEnabledTools is the hard-coded set of tools that enter the intercept
// rule system when no intercept_enabled_tools setting has been saved.
// goal_met ends the whole task in one sentence without going through prove_goal's
// evidence chain (v0.3.88 audit S3) — once in the set it can be matched by rules (the
// built-in judge rule 'goal_met wrap-up review' ships in the V5 seed batch).
// Every tool with host/target side effects belongs here — a tool missing from
// this set silently bypasses BOTH rule matching and the fallback judge
// (guard.applyIntercept returns early on IsToolEnabled=false). Entries ending
// in '*' match by prefix, covering dynamically named families like mcp__<srv>__<tool>.
var defaultEnabledTools = []string{
	"Bash", "WebFetch", "web_search",
	"shell_open", "shell_send",
	"listener_start", "listener_stop",
	"goal_met",
	"Write", "Edit", "MultiEdit",
	"NotebookEdit",
	// Background jobs: job_start is equivalent to Bash (execs arbitrary commands)
	// — it must face the same destructive/exfil rules.
	"job_start", "job_stop",
	// Script/evidence file writes and script execution.
	"run_script", "save_script", "save_evidence", "poc_scaffold",
	// Tools that act on the target or the network: exfil-shaped deny/ask rules
	// must reach them, not only Bash.
	"http_request", "session_login", "http_probe", "auth_request",
	"js_audit", "scan_with_nuclei",
	// MCP tools are named dynamically (mcp__<server>__<tool>) — prefix wildcard.
	"mcp__*",
}

// DefaultEnabledTools returns the shipped intercept tool set (copy — callers may
// append their own tool names when materializing a persisted list).
func DefaultEnabledTools() []string {
	out := make([]string, len(defaultEnabledTools))
	copy(out, defaultEnabledTools)
	return out
}

// New creates an Interceptor backed by d. The rule cache is lazy-loaded on
// first use.
func New(d *db.DB) *Interceptor {
	return &Interceptor{db: d, pending: newPendingManager()}
}

// Invalidate clears the in-memory rule cache and the enabled-tools cache.
// The next call to Match or IsToolEnabled will reload from the database.
// Call this after any CRUD operation on rules or tool config.
func (i *Interceptor) Invalidate() {
	i.mu.Lock()
	i.cached = nil
	i.enabledTools = nil
	i.enabledPrefixes = nil
	i.mu.Unlock()
}

// SetRulesInMemory replaces the in-memory rule cache with the given rules.
//
// Purpose: let the 'rule → verdict → allow/deny/ask' chain be verified end-to-end
// without a database (Match's rule source is db.ListInterceptRules and unit tests have no
// PG). Production never uses it — rules still load from the DB.
//
// Passed rules are sorted by priority DESC, id ASC (matching DB load order) and their
// regexes precompiled; rules failing to compile are skipped (same as loadLocked).
func (i *Interceptor) SetRulesInMemory(rules []db.InterceptRule) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cr := compiledRule{InterceptRule: r}
		if r.MatchType == "regex" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue
			}
			cr.re = re
		}
		out = append(out, cr)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	i.mu.Lock()
	i.cached = out
	i.mu.Unlock()
}

func (i *Interceptor) loadLocked() error {
	// nil db (server not yet wired to a database): no rules to load, but **must not
	// panic** — interception sits on the synchronous tool-call path; a panic kills the
	// whole agent process. judgeConfig already guards nil db; this covers the rule side.
	if i == nil || i.db == nil {
		// if rules were injected via SetRulesInMemory, **don't overwrite** them — they
		// exist to verify the 'rule → verdict' chain without a database.
		if i.cached == nil {
			i.cached = []compiledRule{}
		}
		i.enabledTools, i.enabledPrefixes = splitEnabledTools(defaultEnabledTools)
		return nil
	}
	rules, err := i.db.ListInterceptRules()
	if err != nil {
		return err
	}
	var out []compiledRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cr := compiledRule{InterceptRule: r}
		if r.MatchType == "regex" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue // skip rules with bad regex rather than crashing
			}
			cr.re = re
		}
		out = append(out, cr)
	}
	i.cached = out

	// Load enabled-tools set from settings, falling back to hard-coded defaults.
	val, ok, _ := i.db.GetSetting("intercept_enabled_tools")
	if !ok {
		i.enabledTools, i.enabledPrefixes = splitEnabledTools(defaultEnabledTools)
	} else {
		var names []string
		if json.Unmarshal([]byte(val), &names) != nil {
			i.enabledTools = map[string]bool{}
			i.enabledPrefixes = nil
		} else {
			i.enabledTools, i.enabledPrefixes = splitEnabledTools(names)
		}
	}
	return nil
}

// splitEnabledTools separates exact names from '*' suffix wildcard entries
// (prefix match — covers dynamically named tool families like mcp__<srv>__<tool>
// which can't be enumerated statically).
func splitEnabledTools(names []string) (map[string]bool, []string) {
	m := make(map[string]bool, len(names))
	var prefixes []string
	for _, n := range names {
		if strings.HasSuffix(n, "*") {
			prefixes = append(prefixes, n[:len(n)-1])
			continue
		}
		m[n] = true
	}
	return m, prefixes
}

func (i *Interceptor) rules() ([]compiledRule, error) {
	i.mu.RLock()
	if i.cached != nil {
		out := i.cached
		i.mu.RUnlock()
		return out, nil
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.cached != nil {
		return i.cached, nil
	}
	if err := i.loadLocked(); err != nil {
		return nil, err
	}
	return i.cached, nil
}

// IsToolEnabled returns true if the named tool is in the intercept-enabled set
// (i.e. it should enter the rule-matching path). Uses the same double-check lock
// pattern as rules(). A '*' suffix entry in the set matches by prefix.
func (i *Interceptor) IsToolEnabled(name string) bool {
	i.mu.RLock()
	if i.enabledTools != nil {
		v := i.enabledTools[name]
		if !v {
			for _, p := range i.enabledPrefixes {
				if strings.HasPrefix(name, p) {
					v = true
					break
				}
			}
		}
		i.mu.RUnlock()
		return v
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.enabledTools == nil {
		_ = i.loadLocked()
	}
	if i.enabledTools[name] {
		return true
	}
	for _, p := range i.enabledPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// GetEnabledTools returns the ordered list of tool names that are currently
// configured to enter the intercept rule system. When the setting has never been
// saved the hard-coded default list is returned.
func (i *Interceptor) GetEnabledTools() ([]string, error) {
	val, ok, err := i.db.GetSetting("intercept_enabled_tools")
	if err != nil {
		return nil, err
	}
	if !ok {
		out := make([]string, len(defaultEnabledTools))
		copy(out, defaultEnabledTools)
		return out, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(val), &names); err != nil {
		return []string{}, nil
	}
	return names, nil
}

// SetEnabledTools persists the list of tool names that should enter the intercept
// rule system, then invalidates the cache so the next call picks up the new list.
func (i *Interceptor) SetEnabledTools(tools []string) error {
	b, err := json.Marshal(tools)
	if err != nil {
		return err
	}
	if err := i.db.SetSetting("intercept_enabled_tools", string(b)); err != nil {
		return err
	}
	i.Invalidate()
	return nil
}

// Decision is the outcome of a successful rule match.
type Decision struct {
	ModelInput       json.RawMessage
	ModelInputDigest string
	ModelFallback    bool
	RuleName         string
	ConfigDigest     string
	ProfileID        int64
	Action           string // "allow" | "deny" | "ask"
	Message          string
	RuleID           int64
	TimeoutEnabled   bool
	TimeoutSeconds   int
	TimeoutAction    string // "deny" | "allow"
}

// --- LLM fallback judge ---

// Judge settings keys (stored in the settings KV table). See docs §3.
const (
	settingJudgeEnabled          = "llm_judge_enabled"
	settingJudgeProfileID        = "llm_judge_profile_id"
	settingJudgePrompt           = "llm_judge_prompt"
	settingJudgeTimeoutSecs      = "llm_judge_timeout_seconds"
	settingJudgeFailAction       = "llm_judge_fail_action"
	settingJudgeAskTimeoutSecs   = "llm_judge_ask_timeout_seconds"
	settingJudgeAskTimeoutAction = "llm_judge_ask_timeout_action"

	// global backstop cap for ask approvals (when a rule declares no timeout). The last
	// wall beyond rule-level TimeoutEnabled: an absent approver must not hang a worker
	// forever (v0.3.88 audit S2).
	settingAskDefaultTimeoutSecs = "intercept_ask_default_timeout_seconds"
)

// defaultAskTimeoutSecs: 6 hours. Semantics differ from the judge side's 180s — here
// 'a rule demands human sign-off but nobody declared how long to wait', waiting for
// **the operator to come back to work**, so give a within-one-workday magnitude; expiry
// closes as deny (deny is always the safe side for ask-class rules) and the outcome is
// recorded in approval history (status=timeout) for audit.

// Judge default values.
//
// These defaults assume 'nobody at the keyboard':
//
//   - verdict timeout 90s (not 15s): thinking models (MiniMax-M3.1 / Claude extended
//     thinking) spend a dozen-plus seconds thinking; 15s misjudges 'the model is
//     thinking' as failure, dropping every verdict into the fallback policy — with
//     thinking on, the judge might as well be off.
//   - verdict failure → route to human (not allow): allow would mean 'model died → gate
//     swings open', and models die of config problems (thinking incompatibility, quota
//     exhaustion, upstream 5xx) — auto-permitting there silently disables all control.
//   - human-approval timeout → permit (not deny): ask **blocks the worker
//     synchronously** waiting for a human. With nobody at the keyboard, deny deadlocks
//     the task and stalls the whole chain; permitting lets this one call continue, and the
//     record stays visible for later confirmation on the 'intercept approvals' page.
//     Real damage prevention belongs at 'rule match → model verdict', not at 'a human
//     didn't click confirm in time'.
//   - human-approval timeout 180s: 3 minutes, enough for an operator to glance back.
const (
	// defaultJudgeTimeoutSecs is the model verdict's wall-clock cap.
	//
	// 180 rather than shorter: thinking-model verdict latency scales with command length
	// (measured 4–26s for short commands; noticeably longer for long ones — hundreds to
	// thousands of chars of shell), and empty bodies trigger escalating-budget retries
	// (32768 → 65536) that must fit inside the same window. Too short a window misjudges
	// 'the model can actually judge' as a timeout failure.
	defaultJudgeTimeoutSecs      = 180
	defaultJudgeFailAction       = "ask"
	defaultJudgeAskTimeoutSecs   = 180
	defaultJudgeAskTimeoutAction = "allow"

	// ask global backstop: 6h (see the settingAskDefaultTimeoutSecs comment).
	defaultAskTimeoutSecs = 6 * 60 * 60
)

// JudgeConfig is the resolved LLM-fallback-judge configuration. Prompt is always
// non-empty (falls back to DefaultJudgePrompt).
type JudgeConfig struct {
	Enabled           bool   `json:"enabled"`
	ProfileID         int64  `json:"profile_id"` // 0 = follow active/default
	Prompt            string `json:"prompt"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	FailAction        string `json:"fail_action"` // allow|ask|deny
	AskTimeoutSeconds int    `json:"ask_timeout_seconds"`
	AskTimeoutAction  string `json:"ask_timeout_action"` // allow|deny
}

// judgeConfig reads the judge configuration from settings, applying defaults for
// missing/invalid keys. Read fresh on each fallback judgement — the LLM call that
// follows dwarfs a few KV reads, and freshness avoids a cache-invalidation path.
func (i *Interceptor) judgeConfig() JudgeConfig {
	// nil db (server not yet wired): everything uses defaults. Don't panic here — the
	// verdict sits on the synchronous tool-call path; a panic kills the agent process.
	if i == nil || i.db == nil {
		return JudgeConfig{
			Enabled:           false,
			ProfileID:         0,
			Prompt:            DefaultJudgePrompt,
			TimeoutSeconds:    defaultJudgeTimeoutSecs,
			FailAction:        defaultJudgeFailAction,
			AskTimeoutSeconds: defaultJudgeAskTimeoutSecs,
			AskTimeoutAction:  defaultJudgeAskTimeoutAction,
		}
	}
	c := JudgeConfig{
		Enabled:           i.db.GetBool(settingJudgeEnabled, false),
		ProfileID:         int64(i.getSettingInt(settingJudgeProfileID, 0)),
		TimeoutSeconds:    i.getSettingInt(settingJudgeTimeoutSecs, defaultJudgeTimeoutSecs),
		FailAction:        i.getSettingChoice(settingJudgeFailAction, defaultJudgeFailAction, "allow", "ask", "deny"),
		AskTimeoutSeconds: i.getSettingInt(settingJudgeAskTimeoutSecs, defaultJudgeAskTimeoutSecs),
		AskTimeoutAction:  i.getSettingChoice(settingJudgeAskTimeoutAction, defaultJudgeAskTimeoutAction, "allow", "deny"),
	}
	// Prompt: stored value if non-empty, else the built-in template.
	if v, ok, _ := i.db.GetSetting(settingJudgePrompt); ok && strings.TrimSpace(v) != "" {
		c.Prompt = v
	} else {
		c.Prompt = DefaultJudgePrompt
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = defaultJudgeTimeoutSecs
	}
	if c.AskTimeoutSeconds <= 0 {
		c.AskTimeoutSeconds = defaultJudgeAskTimeoutSecs
	}
	return c
}

// DefaultJudgeTimeoutSeconds returns the verdict's default wall-clock cap (seconds).
//
// Exported for server-layer test assertions: thinking-model verdict latency scales with
// command length (long commands noticeably slower) and empty bodies trigger escalating-
// budget retries — too short a timeout misjudges 'the model can actually judge' as
// failure.
func DefaultJudgeTimeoutSeconds() int { return defaultJudgeTimeoutSecs }

func (i *Interceptor) getSettingInt(key string, def int) int {
	v, ok, err := i.db.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func (i *Interceptor) getSettingChoice(key, def string, allowed ...string) string {
	v, ok, err := i.db.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	v = strings.TrimSpace(v)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}

// GetJudgeConfig returns the resolved judge configuration for the API/UI. Prompt
// is the effective prompt (built-in template when unset), so the UI can prefill.
func (i *Interceptor) GetJudgeConfig() JudgeConfig { return i.judgeConfig() }

// SetJudgeConfig persists the judge configuration. An empty Prompt clears the
// override (the built-in template is used again).
func (i *Interceptor) SetJudgeConfig(c JudgeConfig) error {
	if err := i.db.SetBool(settingJudgeEnabled, c.Enabled); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeProfileID, strconv.FormatInt(c.ProfileID, 10)); err != nil {
		return err
	}
	// Store the prompt only when it differs from the built-in template, so version
	// updates to DefaultJudgePrompt flow through for users who never customized it.
	promptToStore := ""
	if strings.TrimSpace(c.Prompt) != "" && strings.TrimSpace(c.Prompt) != strings.TrimSpace(DefaultJudgePrompt) {
		promptToStore = c.Prompt
	}
	if err := i.db.SetSetting(settingJudgePrompt, promptToStore); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeTimeoutSecs, strconv.Itoa(c.TimeoutSeconds)); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeFailAction, c.FailAction); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeAskTimeoutSecs, strconv.Itoa(c.AskTimeoutSeconds)); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeAskTimeoutAction, c.AskTimeoutAction); err != nil {
		return err
	}
	return nil
}

// Judge runs the LLM fallback judge for a tool call that matched no rule. It
// returns (Decision, true) when the judge produced a terminal verdict, or
// (Decision{}, false) when the fallback is disabled or not wired (caller then
// keeps the current behavior: allow). On model error or an unparseable reply it
// falls back to the configured FailAction. Ask verdicts carry the human-approval
// timeout so the existing HandleAsk consumes them unchanged.
func (i *Interceptor) Judge(ctx context.Context, tool string, arguments json.RawMessage) (Decision, bool) {
	return i.judge(ctx, tool, arguments, false, RuleTimeout{})
}

// RuleTimeout is a rule's explicit timeout declaration.
//
// A rule may declare its own 'what happens after I time out / fail' — an explicit
// statement by the rule author that outranks the global judge config. Zero value
// (Enabled=false) means 'the rule says nothing — follow the global setting'.
//
// Why this exists: rules and verdicts are two layers. The global config answers 'how
// should the model-fallback verdict time out', while a 'forbid disk destruction' rule
// wants 'deny outright if the model didn't answer in time' — the former is fallback
// policy, the latter safety policy. Merging them into one config can't express both, so
// before P0 these three rule fields were dead: the UI showed one thing while another took
// effect.
type RuleTimeout struct {
	// When Enabled is true this declaration applies, replacing the global timeout +
	// fail_action.
	Enabled bool
	// Seconds is the verdict's wall-clock cap (seconds).
	Seconds int
	// Action is the post-failure/timeout action: "deny" | "allow".
	Action string
}

// JudgeRule is Judge for a rule whose action is "judge": the rule itself asks
// for a model verdict, so the global llm_judge_enabled switch is ignored (a rule
// that silently did nothing would be worse than either fixed action). The
// configured fail action / timeout still apply.
func (i *Interceptor) JudgeRule(ctx context.Context, tool string, arguments json.RawMessage) (Decision, bool) {
	return i.judge(ctx, tool, arguments, true, RuleTimeout{})
}

// JudgeRuleWithTimeout is JudgeRule with the triggering rule's own timeout
// declaration applied. The rule's timeout_enabled/seconds/action override the
// global judge configuration when enabled; otherwise the global values apply.
//
// Semantics (regression baseline in intercept/rule_timeout_test.go):
//   - Enabled=false → global llm_judge_timeout_seconds + global llm_judge_fail_action
//   - Enabled=true  → the rule's own Seconds + Action
//
// Action only applies on 'model verdict failed or timed out' (no verdict available);
// on success the model's action (allow/ask/deny) wins.
func (i *Interceptor) JudgeRuleWithTimeout(ctx context.Context, tool string, arguments json.RawMessage, rt RuleTimeout) (Decision, bool) {
	return i.judge(ctx, tool, arguments, true, rt)
}

func (i *Interceptor) judge(ctx context.Context, tool string, arguments json.RawMessage, forced bool, rt RuleTimeout) (Decision, bool) {
	cfg := i.judgeConfig()
	// rule-level timeout overrides global: the rule author explicitly declared 'what
	// happens on my timeout' — that's this rule's policy, unaffected by global fallback.
	if rt.Enabled {
		if rt.Seconds > 0 {
			cfg.TimeoutSeconds = rt.Seconds
		}
		switch rt.Action {
		case "allow", "deny", "ask":
			cfg.FailAction = rt.Action
		}
	}
	i.mu.RLock()
	rv := i.reviewer
	i.mu.RUnlock()
	if !forced && (!cfg.Enabled || rv == nil) {
		return Decision{}, false
	}
	if rv == nil {
		// the rule explicitly demands a verdict but the server has no reviewer wired
		// (test env / early init): apply the configured failure policy rather than letting
		// the rule become a no-op.
		return Decision{Action: cfg.FailAction, ModelFallback: true, Message: "[model] verdict not wired — applying failure policy"}, true
	}

	cctx := ctx
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	input, contextErr := BuildReviewInput(cctx, tool, arguments)
	cfg.Prompt = EffectiveJudgePrompt(cfg.Prompt)
	var out Decision
	var err error
	var modelInput []byte
	if contextErr != nil {
		// Invalid current arguments cannot be reviewed faithfully, regardless of
		// the configured model-failure strategy. A human must resolve the input.
		out = Decision{Action: "ask", ModelFallback: true, Message: "review context incomplete — human confirmation needed: " + contextErr.Error()}
	} else {
		modelInput, _ = json.Marshal(input)
		out, err = rv(cctx, cfg.ProfileID, cfg.Prompt, input)
	}
	if err != nil {
		out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: cfg.FailAction, Message: "model approval failed — applying failure policy: " + err.Error()}
	}
	switch out.Action {
	case "allow", "ask", "deny":
		// valid verdict
	default:
		out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: cfg.FailAction, Message: "model output unparseable — applying failure policy"}
	}
	// A model verdict never carries a rule; keep RuleID 0 (→ NULL) for history.
	out.RuleID = 0
	if len(modelInput) > 0 {
		out.ModelInput = modelInput
		out.ModelInputDigest = digestInput(modelInput)
	}
	if out.ProfileID != 0 {
		cfg.ProfileID = out.ProfileID
	}
	out.ProfileID = cfg.ProfileID
	configJSON, _ := json.Marshal(cfg)
	out.ConfigDigest = digestInput(configJSON)
	if out.Message == "" {
		out.Message = "[model] " + judgeActionLabel(out.Action)
	} else if !strings.HasPrefix(out.Message, "[model]") {
		out.Message = "[model] " + out.Message
	}
	if out.Action == "ask" {
		out.TimeoutEnabled = true
		out.TimeoutSeconds = cfg.AskTimeoutSeconds
		out.TimeoutAction = cfg.AskTimeoutAction
	}
	return out, true
}

func judgeActionLabel(action string) string {
	switch action {
	case "allow":
		return "permit"
	case "deny":
		return "block"
	case "ask":
		return "route to human approval"
	default:
		return action
	}
}

// Match evaluates the rule list (priority DESC) against a tool call.
// Returns (Decision, true) for the first matching enabled rule, or
// (Decision{}, false) if no rule matches.
func (i *Interceptor) Match(toolName string, input []byte) (Decision, bool) {
	rules, err := i.rules()
	if err != nil || len(rules) == 0 {
		return Decision{}, false
	}
	for _, r := range rules {
		if ruleMatches(r, toolName, input) {
			msg := r.Message
			if msg == "" {
				msg = defaultMessage(r.Action, r.Name)
			}
			configJSON, _ := json.Marshal(r.InterceptRule)
			return Decision{
				RuleName: r.Name, ConfigDigest: digestInput(configJSON),
				Action:         r.Action,
				Message:        msg,
				RuleID:         r.ID,
				TimeoutEnabled: r.TimeoutEnabled,
				TimeoutSeconds: r.TimeoutSeconds,
				TimeoutAction:  r.TimeoutAction,
			}, true
		}
	}
	return Decision{}, false
}

// toolScopeAllows reports whether a rule carrying the given scope should be
// evaluated for toolName. 空 scope 表示不限工具——加列前的全部规则都是这个
// 状态，因此行为不变。
func toolScopeAllows(scope []string, toolName string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, s := range scope {
		if s == toolName {
			return true
		}
	}
	return false
}

func ruleMatches(r compiledRule, toolName string, input []byte) bool {
	// 规则级适用工具：先按工具过滤，再选匹配对象。被排除的规则既不参与匹配，
	// 也不参与 allow 短路——否则一条只针对 shell 的 allow 会顺带豁免掉别的工具。
	if !toolScopeAllows(r.ToolScope, toolName) {
		return false
	}
	var subject string
	switch r.MatchTarget {
	case "tool_name":
		subject = toolName
	case "tool_input":
		subject = string(input)
	default:
		return false
	}
	if r.MatchType == "regex" {
		return r.re != nil && r.re.MatchString(subject)
	}
	return strings.Contains(subject, r.Pattern)
}

func defaultMessage(action, name string) string {
	switch action {
	case "deny":
		return "intercept rule [" + name + "] forbids this tool"
	case "ask":
		return "intercept rule [" + name + "] requires user approval — please wait"
	default:
		return ""
	}
}

// Log records an allow/deny rule or model decision into intercept_pending as an ALREADY-decided
// row (status = "allowed" | "denied"), for observability. Unlike HandleAsk it does NOT
// block and needs no user action — it makes explicit review decisions visible on the history
// page (GET /api/intercept/history) and the task's intercept list. Best-effort: a DB
// error is swallowed so logging never changes the tool call's outcome. The pending list
// (status='pending') is unaffected, so it still shows only asks awaiting a decision.
func (i *Interceptor) Log(ctx context.Context, convID int64, dec Decision, toolName string, input []byte, status string) {
	// nil db (server not yet wired): nowhere to record, but **must not panic** — Log sits
	// on the synchronous tool-call path; a panic kills the agent process.
	if i == nil || i.db == nil {
		return
	}
	taskID, agentName := taskInfoFromCtx(ctx)
	audit := auditFor(ctx, dec, input, status)
	id, err := i.db.CreateDecidedIntercept(dec.RuleID, convID, taskID, agentName, toolName, input, status, dec.Message, audit)
	if err == nil {
		i.bindResult(ctx, id, audit)
	}
}

// HandleAsk creates a pending approval record and blocks until the user decides
// (via /api/intercept/pending/{id}/decide) or the per-rule timeout elapses.
// Returns true if the user approved.
//
// convID == 0 means no active conversation (background pentest task). The
// pending record is still created (conversation_id = NULL) so the approvals
// page shows it and the sidebar badge lights up. The worker thread blocks just
// like in a chat session — the user must visit the approvals page to unblock it.
func (i *Interceptor) HandleAsk(ctx context.Context, convID int64, dec Decision, toolName string, input []byte) bool {
	// nil db (server not yet wired): no approval record can be created, so nobody can
	// approve. Treat as 'deny' — never default to permit just because no one can approve.
	if i == nil || i.db == nil {
		return false
	}
	ruleID := dec.RuleID
	taskID, agentName := taskInfoFromCtx(ctx)
	taskEmit := taskEmitFromCtx(ctx)

	audit := auditFor(ctx, dec, input, "pending")
	pendingID, err := i.db.CreateInterceptPending(ruleID, convID, taskID, agentName, toolName, input, dec.Message, audit)
	if err != nil {
		return false
	}

	i.bindResult(ctx, pendingID, audit)
	ch := i.pending.add(pendingID)
	defer i.pending.remove(pendingID)
	// Polling clients can decide after INSERT commits but before the channel is
	// registered. Re-read after registration so that decision cannot be lost;
	// later decisions will be delivered through ch.
	if saved, err := i.db.GetInterceptDetail(pendingID); err == nil && saved != nil && saved.Status != "pending" {
		return saved.Status == "allowed" || (saved.Audit != nil && saved.Audit.EffectiveAction == "allow")
	}

	detail, _ := json.Marshal(map[string]any{
		"pending_id": pendingID,
		"tool":       toolName,
		"input":      json.RawMessage(input),
	})
	activity := db.Activity{
		Kind:    "intercept_request",
		Summary: fmt.Sprintf("tool %s requests approval (#%d)", toolName, pendingID),
		Detail:  string(detail),
	}

	if convID != 0 {
		// Chat session: write inline card to the conversation stream.
		_, _ = i.db.AppendConvActivity(convID, activity)
	} else if taskEmit != nil {
		// Task worker: emit to the exploration activity stream so it appears
		// inline in the session transcript (the emit fn stamps NodeID + Worker).
		taskEmit(activity)
	}

	if !dec.TimeoutEnabled {
		// no declared timeout ≠ wait forever: with the approver away the worker hangs
		// until task timeout and the whole task budget burns (v0.3.88 audit S2). Apply a
		// global backstop — expiry closes as deny (ask guards capability-boundary changes;
		// deny is always the safe side) and logs so ops see the 'timeout' outcome in
		// approval history. Override via system setting
		// intercept_ask_default_timeout_seconds (seconds).
		ceiling := i.getSettingInt(settingAskDefaultTimeoutSecs, defaultAskTimeoutSecs)
		if ceiling <= 0 {
			ceiling = defaultAskTimeoutSecs
		}
		timer := time.NewTimer(time.Duration(ceiling) * time.Second)
		defer timer.Stop()
		select {
		case allowed := <-ch:
			return allowed
		case <-timer.C:
			log.Printf("[intercept] ask approval #%d exceeded the global backstop (%ds) unattended — closing as deny", pendingID, ceiling)
			allowed := false
			action := "deny"
			resolved, err := i.db.ResolveIntercept(pendingID, "timeout", action, "approval exceeded the backstop unattended — treated as deny")
			if err != nil {
				return false
			}
			if !resolved {
				detail, err := i.db.GetInterceptDetail(pendingID)
				return err == nil && detail != nil && (detail.Status == "allowed" || (detail.Audit != nil && detail.Audit.EffectiveAction == "allow"))
			}
			return allowed
		case <-ctx.Done():
			_, _ = i.db.ResolveIntercept(pendingID, "denied", "deny", "work cancelled")
			_ = i.db.CompleteIntercept(pendingID, audit.RunID, audit.ToolUseID, "not_executed", "work cancelled before execution", false)
			return false
		}
	}

	secs := dec.TimeoutSeconds
	if secs <= 0 {
		secs = 60
	}
	timer := time.NewTimer(time.Duration(secs) * time.Second)
	defer timer.Stop()
	select {
	case allowed := <-ch:
		return allowed
	case <-timer.C:
		allowed := dec.TimeoutAction == "allow"
		action := "deny"
		if allowed {
			action = "allow"
		}
		resolved, err := i.db.ResolveIntercept(pendingID, "timeout", action, "approval timed out — applying the timeout policy")
		if err != nil {
			return false
		}
		if !resolved {
			detail, err := i.db.GetInterceptDetail(pendingID)
			return err == nil && detail != nil && (detail.Status == "allowed" || (detail.Audit != nil && detail.Audit.EffectiveAction == "allow"))
		}
		return allowed
	case <-ctx.Done():
		_, _ = i.db.ResolveIntercept(pendingID, "denied", "deny", "work cancelled")
		_ = i.db.CompleteIntercept(pendingID, audit.RunID, audit.ToolUseID, "not_executed", "work cancelled before execution", false)
		return false
	}
}

var ErrAlreadyDecided = errors.New("approval already handled or missing — refresh the record")

// Decide resolves a pending request. Called by the HTTP decide endpoint.
func (i *Interceptor) Decide(pendingID int64, allowed bool) error {
	status := "denied"
	if allowed {
		status = "allowed"
	}
	action, reason := "deny", "manually denied"
	if allowed {
		action, reason = "allow", "manually permitted"
	}
	resolved, err := i.db.ResolveIntercept(pendingID, status, action, reason)
	if err != nil {
		return err
	}
	if !resolved {
		return ErrAlreadyDecided
	}
	i.pending.resolve(pendingID, allowed)
	return nil
}
