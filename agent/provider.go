// Package agent wires real LLM-driven planner and work agents (on top of the
// agent-core SDK) to the dual SQLite graph. See docs/pojun-architecture-design.md
// §4.3 (planner) and §4.4 (work agent).
//
// Provider configuration is read from the environment so the system runs with
// any Anthropic- or OpenAI-format endpoint. If no key is configured, FromEnv
// returns ok=false and the exploration engine stays idle (an LLM is required).
package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/transcript"
	"github.com/chu0119/pojun/llmrec"
)

// Config describes the LLM backend resolved from the environment.
type Config struct {
	Format  llm.Format
	BaseURL string
	APIKey  string
	Model   string
	// Proxy routes all LLM requests through the given proxy URL (http/https/socks5,
	// optionally with user:pass@ credentials). Empty means direct — it does NOT
	// fall back to the standard *_PROXY environment variables.
	Proxy string
	// RatePerSecond / RatePerMinute cap the shared request rate across ALL agents
	// using the provider (0 = that window unlimited).
	RatePerSecond float64
	RatePerMinute float64
	// ContextWindowK is the model's context window in K tokens (user-configured),
	// used to size compaction thresholds. 0 = default; see CompactionWindow.
	ContextWindowK int
	// ThinkingType independently controls the thinking 'switch' field (thinking.type):
	//   "" = don't send (default; compatible with models lacking the field); "disabled" = explicitly off;
	//   "enabled" = on. Fully decoupled from ReasoningEffort — some endpoints have no thinking field
	//   and activate thinking purely via the effort param, so the two can be set independently.
	ThinkingType string
	// SuppressThinking forces thinking.type [not] to be sent (overrides ThinkingType).
	//
	// Why it exists: the thinking param is injected at the **provider config layer** (see NewProvider),
	// not in llm.CompletionRequest — so 'strip thinking and retry on 2013' can't be done
	// by editing the request; the only way is rebuilding a provider without thinking.
	//
	// What 2013 means: the model has **mandatory adaptive thinking** (MiniMax-M3.1 etc.) —
	// explicitly disabling thinking gets rejected outright upstream:
	//   400 "requires adaptive thinking; thinking.type=\"disabled\" ... is not allowed (2013)"
	// With the field removed the model follows its own default (thinking on) and the request succeeds.
	//
	// This switch is only for **one-shot degraded retries** — it doesn't change the profile's persisted
	// config (that's the user's choice); it only changes how this one call is sent.
	SuppressThinking bool
	// ReasoningEffort independently controls the thinking 'effort' field:
	//   "" = don't send (default); "low"/"medium"/"high"/"xhigh"/"max" = the corresponding effort.
	//   Mapped to top-level reasoning_effort for OpenAI; to output_config.effort for Anthropic.
	ReasoningEffort string
	// Stream controls whether this profile uses the streaming (SSE) API. true (default) = streaming; false = true
	// non-streaming (sends stream:false, fetches the whole JSON at once, via Provider.Complete). Non-streaming
	// dodges some gateways' broken SSE implementations (empty frames, dropped thinking fields), at the cost of
	// losing live progress/live token counts. Mapped to agentcore.Options.NonStreaming = !Stream.
	Stream bool
	// MaxTokens is the output cap (tokens) per reply. 0 = don't send the field — the server's default decides
	// (historic behavior). Unlike ContextWindowK, which is the model's total capacity used only locally to
	// compute compaction thresholds and never sent; this value goes out with every request. Mapped to agentcore.Options.MaxTokens.
	MaxTokens int
	// MaxTokensField picks which request field carries MaxTokens — format=openai only:
	//   "" = max_tokens (default); "max_completion_tokens" = the newer field.
	// OpenAI reasoning models (o-series/GPT-5) only accept the latter — receiving max_tokens errors
	// unsupported_parameter; most compat gateways only accept the former, so no auto-inference — the user picks per endpoint.
	MaxTokensField string
	// SessionHeaderKey, when non-empty, makes every LLM request carry a custom HTTP header whose name is
	// this value and whose value is [the current session's session id] (chat conv-<id>, worker exp<x>-worker-i<intent>
	// etc., see WorkerSessionID). For gateways that do prompt caching/sticky routing by session-id header.
	// Empty = don't send. The value is hung on the request context by transcript.WithSessionID and read
	// by the RoundTripper — so one shared provider can emit different header values per session.
	SessionHeaderKey string
	// UserAgent, when non-empty, replaces the User-Agent header on every LLM request. Default empty =
	// keep the SDK/Go "Go-http-client/1.1" (historical behavior). Some gateways/WAFs reject the default
	// Go UA outright; setting a browser UA gets through. Injected uniformly by quotaAwareTransport, so it
	// covers every request from connect retries and empty-response retries.
	UserAgent string
	// Retry holds this config's parsed retry params (profile override → global policy → built-in default,
	// parsed server-side). The three layers' meanings are in RetryConfig; zero value = fully inherit built-in defaults.
	Retry RetryConfig
}

// RetryConfig is the per-LLM-config retry params. Each layer's 'attempts' shares one semantic:
// 0 = use the built-in default count; negative = disable that layer's retry; >0 = use that value. Each layer's 'interval':
// 0 = keep that layer's original exponential backoff; >0 = switch to this fixed interval.
type RetryConfig struct {
	// ConnectAttempts/ConnectInterval: SDK connect retries (conn reset/timeout/429/5xx, before the stream starts),
	// mapped directly to llm.Config.MaxRetries / RetryInterval. Default 3 attempts, 0.5s exponential start (8s cap).
	ConnectAttempts int
	ConnectInterval time.Duration
	// EmptyAttempts/EmptyInterval: SDK empty-response retries (completed but no content block — openai
	// format only), mapped to llm.Config.EmptyResponseRetries / EmptyResponseInterval.
	// Default 2 attempts, same exponential ladder.
	EmptyAttempts int
	EmptyInterval time.Duration
	// StreamAttempts/StreamInterval: same-provider safe-window retries — an extra layer this project
	// adds above the SDK, replaying stream-cut/overload/in-stream-429 only when 'no output has been
	// delivered to the caller yet'. The SDK can't see it; consumed by server/task_llm.go. Default 2 attempts, 0.5s exponential start (4s cap).
	StreamAttempts int
	StreamInterval time.Duration
}

// compaction window resolution bounds (in K tokens). Below the floor the
// threshold math (window − summary reserve − buffer) would go non-positive and
// compaction would fire every turn; above the cap it would never fire.
const (
	// defaultWindowK = 1000 (1M): the platform's usual model is minimax-m3.1-flash-free,
	// whose native context is 1M (self-reports 1000000). It was previously computed at 200K (Claude default),
	// so compaction fired far below the real limit — and compaction itself is a heavy extra LLM call,
	// burning budget and slowing the flow for nothing. At 1M the threshold rises from ~174K to ~930K.
	//
	// The cap maxWindowK is already 1000 (users explicitly asked to use the full million context),
	// and the threshold math is safe at 1M: effectiveWindow = 1M − 20K = 980K,
	// buffer 50K, auto-compaction threshold 930K.
	defaultWindowK = 1000
	minWindowK     = 32   // floor so effectiveWindow stays comfortably positive
	maxWindowK     = 1000 // cap at 1M tokens (user request)
)

// CompactionWindow returns the model context window in TOKENS for compaction
// thresholds, resolved from the user-configured size (ContextWindowK). 0/unset →
// a 200K default; otherwise clamped to [32K, 1M] so compaction stays effective.
func (c Config) CompactionWindow() int {
	k := c.ContextWindowK
	if k <= 0 {
		k = defaultWindowK
	}
	if k < minWindowK {
		k = minWindowK
	}
	if k > maxWindowK {
		k = maxWindowK
	}
	return k * 1000
}

// compactionConfig builds the agent-core compaction config for a context window
// in tokens. agentcore.NewSession wires the summarizer (same provider) when this
// is set on Options.Compaction.
func compactionConfig(windowTokens int) *compaction.Config {
	if windowTokens <= 0 {
		windowTokens = defaultWindowK * 1000
	}
	return &compaction.Config{ContextWindow: windowTokens}
}

// FromEnv resolves the LLM provider config:
//
//	POJUN_LLM_PROVIDER = anthropic|openai (default: inferred from keys)
//	POJUN_LLM_MODEL    = model id        (default: per provider)
//	POJUN_LLM_BASE_URL = endpoint        (optional)
//	POJUN_LLM_PROXY    = proxy URL        (optional; http/https/socks5)
//	ANTHROPIC_API_KEY / OPENAI_API_KEY         = credentials
func FromEnv() (Config, bool) {
	prov := os.Getenv("POJUN_LLM_PROVIDER")
	anthKey := os.Getenv("ANTHROPIC_API_KEY")
	oaiKey := os.Getenv("OPENAI_API_KEY")

	if prov == "" {
		switch {
		case anthKey != "":
			prov = "anthropic"
		case oaiKey != "":
			prov = "openai"
		default:
			return Config{}, false
		}
	}

	c := Config{
		BaseURL: os.Getenv("POJUN_LLM_BASE_URL"),
		Model:   os.Getenv("POJUN_LLM_MODEL"),
		Proxy:   strings.TrimSpace(os.Getenv("POJUN_LLM_PROXY")),
		// Default streaming; POJUN_LLM_STREAM=false/0/off explicitly switches to non-streaming.
		Stream: !isFalsy(os.Getenv("POJUN_LLM_STREAM")),
	}
	switch prov {
	case "openai":
		c.Format = llm.FormatOpenAI
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	default:
		c.Format = llm.FormatAnthropic
		c.APIKey = anthKey
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	if c.APIKey == "" {
		return Config{}, false
	}
	return c, true
}

// ConfigFrom builds a Config from UI-provided strings (provider defaults to
// anthropic; model defaults per provider). Inputs are trimmed and the base URL
// is normalized to the API base the provider expects (the provider appends the
// endpoint path itself), so a full endpoint URL is tolerated.
func ConfigFrom(provider, model, baseURL, apiKey, proxy string) Config {
	c := Config{
		Model:   strings.TrimSpace(model),
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		APIKey:  strings.TrimSpace(apiKey),
		Proxy:   strings.TrimSpace(proxy),
		Stream:  true, // default streaming; callers override per profile
	}
	switch strings.TrimSpace(provider) {
	case "openai":
		c.Format = llm.FormatOpenAI
		// provider appends "/chat/completions"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/chat/completions"), "/")
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		// provider appends "/responses"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/responses"), "/")
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	default:
		c.Format = llm.FormatAnthropic
		// provider appends "/v1/messages".
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/v1/messages"), "/")
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	return c
}

// isFalsy reports whether an env-var string explicitly requests "off". Empty or
// unrecognized → false (so an unset var keeps the streaming default).
func isFalsy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// Provider returns the short provider name ("anthropic"/"openai").
func (c Config) Provider() string {
	switch c.Format {
	case llm.FormatOpenAI:
		return "openai"
	case llm.FormatOpenAIResponses:
		return "openai-responses"
	}
	return "anthropic"
}

// NewProvider builds an llm.Provider from the config. When a rate is set, the
// limiter lives on the single provider instance — so planner + all workers +
// main agent (which share this provider) are bounded by one shared rate limit.
func (c Config) NewProvider() (llm.Provider, error) {
	client, err := quotaAwareHTTPClient(c.Proxy, c.SessionHeaderKey, c.UserAgent)
	if err != nil {
		return nil, err
	}
	lc := llm.Config{
		Format:     c.Format,
		BaseURL:    c.BaseURL,
		APIKey:     c.APIKey,
		Model:      c.Model,
		HTTPClient: client,
	}
	// The thinking switch and effort fields each pass through independently (empty = field not sent). Decoupled:
	// send only thinking.type, only effort, both, or neither.
	//
	// With SuppressThinking, thinking.type is not sent (degraded retry — see that field's comment).
	if !c.SuppressThinking {
		lc.ThinkingType = c.ThinkingType
	}
	lc.ReasoningEffort = c.ReasoningEffort
	// Which field name the output cap uses (empty = max_tokens). The cap's 'value' isn't decided here — each
	// round it flows via agentcore.Options.MaxTokens; the provider only decides which key carries it.
	lc.MaxTokensField = c.MaxTokensField
	// Retry params share the SDK's semantics (attempts 0=default/negative=off, interval 0=exponential/>0=fixed) — passed through verbatim.
	lc.MaxRetries = c.Retry.ConnectAttempts
	lc.RetryInterval = c.Retry.ConnectInterval
	lc.EmptyResponseRetries = c.Retry.EmptyAttempts
	lc.EmptyResponseInterval = c.Retry.EmptyInterval
	if c.RatePerSecond > 0 || c.RatePerMinute > 0 {
		lc.RateLimit = &llm.RateLimit{PerSecond: c.RatePerSecond, PerMinute: c.RatePerMinute}
	}
	prov, err := llm.NewProvider(lc)
	if err != nil {
		return nil, err
	}
	// Misrefusal self-heal: wrapping only changes the 'authorization blurb on the retried request' — not the intent or tool permissions.
	return GuardRefusal(prov), nil
}

// IsQuotaExhaustedMessage deliberately recognizes only explicit balance,
// billing, credit, or quota-exhaustion signals. Generic 429/rate-limit text,
// authentication failures, network errors, and server failures are excluded.
var nonFailoverHTTPStatus = regexp.MustCompile(`(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(?:401|403|5\d\d)\b`)
var transientQuotaLimit = regexp.MustCompile(`(?i)(?:\b(?:rpm|tpm|rpd|qps)\b|quota[_\s-]*metric|rate[_\s-]*limit|too many requests|(?:requests?|tokens?)\s+(?:per|/)\s*(?:second|minute)|(?:per|/)\s*(?:second|minute)\s+(?:requests?|tokens?)|generate[_\s-]*requests[_\s-]*per[_\s-]*(?:minute|second)|tokens?[_\s-]*per[_\s-]*(?:minute|second))`)

func IsQuotaExhaustedMessage(message string) bool {
	message = strings.ToLower(message)
	// Authentication/authorization and provider-side 5xx failures never rotate,
	// even when a gateway happens to echo a quota-looking phrase in the body.
	if nonFailoverHTTPStatus.MatchString(message) {
		return false
	}
	// Provider APIs frequently describe an ordinary rate limit as "quota
	// exceeded", especially Google-style responses containing a quota metric.
	// These limits recover with time and must stay on the current provider.
	if transientQuotaLimit.MatchString(message) {
		return false
	}
	markers := []string{
		"insufficient_quota", "quota_exceeded", "quota exceeded", "quota exhausted",
		"exceeded your current quota", "billing_hard_limit_reached",
		"billing hard limit", "billing_not_active", "credit balance", "insufficient credit",
		"insufficient balance", "balance is too low", "payment required", "status 402",
		"insufficient quota", "overdue payment",
		// Chinese gateways return these verbatim; the list is machine matching, not copy.
		"余额不足", "额度不足", "额度已用尽", "欠费",
	}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	// gRPC RESOURCE_EXHAUSTED is overloaded for both account quota and ordinary
	// request-rate limiting. Preserve it as an explicit exhaustion signal only
	// when the same error does not identify a transient rate limit.
	return strings.Contains(message, "resource_exhausted") &&
		!strings.Contains(message, "rate limit") &&
		!strings.Contains(message, "too many requests")
}

// quotaAwareTransport preserves Norma's normal retry behavior except for a 429
// whose body explicitly says the account quota/balance is exhausted. Norma's
// retry loop treats every 429 as transient; normalizing only that response to
// 402 lets a task router fail over immediately while retaining the original
// response body for provider-specific classification and audit logs.
type quotaAwareTransport struct {
	base http.RoundTripper
	// sessionHeaderKey, when non-empty, is the HTTP header name each request
	// carries; its value is the session id read from the request context. Empty
	// disables it. See Config.SessionHeaderKey.
	sessionHeaderKey string
	// userAgent, when non-empty, replaces the request's User-Agent header. Empty
	// keeps the SDK/Go default. See Config.UserAgent.
	userAgent string
}

func (t quotaAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// User-Agent override: net/http has already filled in Go-http-client/1.1 by
	// the time RoundTrip runs, so a plain Set is enough to replace it. Applying it
	// here (not at request construction) also covers the SDK's connect/empty
	// retries, which build their own requests.
	if t.userAgent != "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	// Custom session-id header: name is user-configured, value is THIS run's
	// session id (norma stashes it on the context via transcript.WithSessionID).
	// Stable across a session's turns and distinct across sessions — exactly what
	// a session-keyed prompt cache wants. Skipped when no session id is present.
	if t.sessionHeaderKey != "" {
		if sid := transcript.SessionIDFrom(req.Context()); sid != "" {
			req.Header.Set(t.sessionHeaderKey, sid)
		}
	}
	// When LLM recording is on, the Recorder puts a Capture on the context so the
	// raw wire bodies can be persisted. This is the only layer that still sees
	// them: norma builds the request body internally and decodes the SSE response
	// before either reaches the recorder.
	capt := llmrec.CaptureFrom(req.Context())
	capt.SetRequest(requestBodySnapshot(req))

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	// Tee rather than read: a 200 is an SSE stream that must keep streaming. The
	// 429 branch below reads through this wrapper, so its body lands in the
	// capture before being replaced.
	resp.Body = capt.TeeResponse(resp.StatusCode, resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		return resp, nil
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if readErr != nil {
		return resp, nil
	}
	if IsQuotaExhaustedMessage(string(body)) {
		resp.StatusCode = http.StatusPaymentRequired
		resp.Status = "402 Payment Required"
	}
	return resp, nil
}

// requestBodySnapshot copies an outgoing request body without consuming it.
// norma builds every model request from a *bytes.Reader, so net/http populates
// GetBody and the copy has no effect on what gets sent.
func requestBodySnapshot(req *http.Request) string {
	if req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	return string(b)
}

func quotaAwareHTTPClient(proxy, sessionHeaderKey, userAgent string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		transport.Proxy = nil // empty = direct connect; no fallback to HTTP_PROXY/HTTPS_PROXY env vars
	} else {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("llm: invalid proxy %q: %w", proxy, err)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5":
		case "":
			return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", proxy)
		default:
			return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: quotaAwareTransport{base: transport, sessionHeaderKey: strings.TrimSpace(sessionHeaderKey), userAgent: sanitizeUserAgent(userAgent)}}, nil
}

// sanitizeUserAgent makes any user-supplied UA safe to send as a single HTTP
// header value: trim the ends and turn control characters (CR/LF above all)
// into spaces. The save path already rejects CR/LF, but a profile edited
// directly in the DB must not be able to break every model request.
func sanitizeUserAgent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if r == '\t' || r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// logTestConnection prints the raw HTTP status code(s) and response body of a
// connection test to the server log, so 'clicking test' leaves a diagnosable trail of
// exactly what the gateway returned — 401 bodies, quota text, empty frames — not
// just the collapsed ok/err the UI shows. Bodies are clipped to keep a chatty
// SSE stream from flooding the log.
func logTestConnection(c Config, capt *llmrec.Capture) {
	attempts := capt.Attempts()
	if len(attempts) == 0 {
		log.Printf("[llm-test] %s / %s @ %s — no HTTP request was ever sent (config parse or connect failed immediately)",
			c.Provider(), c.Model, c.BaseURL)
		return
	}
	for i, a := range attempts {
		log.Printf("[llm-test] %s / %s @ %s — attempt %d/%d HTTP %d\nresponse body: %s",
			c.Provider(), c.Model, c.BaseURL, i+1, len(attempts), a.Status, clipBody(a.Body))
	}
}

// clipBody trims a wire body for logging. 4K is plenty to show an error JSON or
// the head of an SSE stream while bounding a runaway response.
func clipBody(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty)"
	}
	const max = 4096
	if len(s) > max {
		return s[:max] + fmt.Sprintf("…(truncated, %d bytes total)", len(s))
	}
	return s
}

// TestConnection makes a minimal real completion to verify the provider/model/
// endpoint/key actually work. Returns the round-trip latency and the model's
// reply text.
func TestConnection(ctx context.Context, c Config) (time.Duration, string, error) {
	prov, err := c.NewProvider()
	if err != nil {
		return 0, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Capture raw wire packets: what a connection test most needs to see is what the gateway actually
	// answered (status code + body) — after norma decodes the response into StreamEvents that's gone.
	// quotaAwareTransport finds this Capture in the context and fills each HTTP attempt's status code and body.
	ctx, capt := llmrec.NewCapture(ctx)
	defer logTestConnection(c, capt)
	// A connection test is a single-shot path — it doesn't go through agentcore's session loop, so nobody
	// hangs a session id on the context. For endpoints configured with SessionHeaderKey (e.g. opencode zen
	// mandates an x-opencode-session header — 400 MissingSessionID without it), that creates a 'chat works,
	// click-test 400s' discrepancy. Here we hang a one-shot random session id so the test uses the same
	// header logic as real conversations; endpoints without SessionHeaderKey don't read it — no side effects.
	ctx = transcript.WithSessionID(ctx, "conntest-"+transcript.NewSessionID())
	start := time.Now()
	// MaxTokens must be generous: reasoning models (e.g. deepseek-v4-pro) produce a long thinking
	// segment before the answer (measured: ~2900 tokens burned on a single 'ping'). Given only 32, the model
	// stays stuck in 'thinking phase' and hits the output cap (finish=length) — truncated; the test still
	// counts as passing (err=nil) but shows as a 'interrupted/length/resume' mess. Give it enough budget to
	// finish OK cleanly (finish=stop). EscalateMaxTokens stays false: don't raise the cap on truncation — avoids resume loops burning budget.
	reply, err := agentcore.Run(ctx, agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{"You are a connection test. Just output the two characters OK — no thinking, no explanation, nothing else."},
		PermissionMode: acperm.ModeBypass,
		MaxTurns:       1,
		MaxTokens:      8192,
		NonStreaming:   !c.Stream, // test the connection with the profile's real send/recv mode
	}, "ping")
	lat := time.Since(start)
	if err != nil {
		return lat, "", err
	}
	// err==nil isn't enough: cases exist where the request went through but the model emitted nothing
	// (thinking burned the whole budget, body swallowed by a safety policy, the compat layer dropped content).
	// In a conversation that config means 'never replies' — yet the test reports success — exactly the gap
	// this check removes. No visible body = failure.
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return lat, "", fmt.Errorf("model returned no content (request succeeded but no text came back)")
	}
	return lat, reply, nil
}
