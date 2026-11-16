package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// weComMarkdownLimit is the WeCom bot's hard cap on markdown content (bytes, not chars).
// The tightest of all six channels — the main reason TruncateBytes exists.
const weComMarkdownLimit = 4096

// weComChannel implements the WeCom group bot.
//
// Platform traits:
//   - Auth is only the URL's key — no signing, so the webhook URL is the entire credential.
//   - markdown content cap is 4096 **bytes**; oversize rejects the whole message (not
//     truncation). At 3 bytes/CJK char that's barely a thousand chars — client-side
//     truncation is mandatory.
//   - 20 msgs/min rate limit — likewise held client-side.
type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

// WeCom's only credential is the webhook (the URL's key) — no signing exists, so the whole
// URL is the credential and nothing else needs masking.
func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

// WeCom has just the webhook field — destination and credential in one, so there's no leftover credential after an address change.
func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("missing webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	// A digest batch can run long (50 items × one line + intro); 4096 bytes is easy to exceed.
	// Truncate here rather than rely on the platform error: rejection loses the whole batch,
	// while truncation still delivers the leading items.
	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse WeCom response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 45009 is 'API call over limit' — the platform's rate window rolls, so retry-after-backoff
		// works; classified retriable on purpose. Reaching here means client rate_per_min is too
		// aggressive — retry is the backstop, the real fix is lowering this channel's rate.
		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("WeCom rate-limited %d: %s", res.ErrCode, res.ErrMsg)
		}
		// 93000 is invalid webhook key — permanent; retries won't heal.
		return 0, Permanent(fmt.Errorf("WeCom error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}
