package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// dingTalkChannel implements the DingTalk custom bot.
//
// Platform traits (driving the design choices here):
//   - 20 msgs/min per bot; overshoot is silently dropped (HTTP may still return 200) —
//     rate limiting must be client-side, see DefaultRatePerMin.
//   - Security setting is one-of-three: signature / custom keywords / IP whitelist.
//     Signature is the only content-independent option, so only signing is supported
//     (a bare webhook with none enabled also works).
//   - Success and failure both return HTTP 200 — the body's errcode tells them apart;
//     not checking errcode records delivery failures as successes.
type dingTalkChannel struct{}

func (dingTalkChannel) Kind() string { return KindDingTalk }

func (dingTalkChannel) DefaultRatePerMin() int { return 20 }

// DingTalk webhook URLs carry an access_token — a credential themselves, so fully masked.
func (dingTalkChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// The destination is the DingTalk webhook URL itself; changing it requires re-affirming the signing secret for the new one.
func (dingTalkChannel) DestinationKeys() []string { return []string{"webhook"} }

func (dingTalkChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("missing webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	return nil
}

// Send delivers one message. A single item with a deep link uses ActionCard (with button); otherwise markdown.
func (c dingTalkChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	hook := cfgString(cfg, "webhook")
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := dingTalkSignedURL(hook, cfgString(cfg, "secret"), time.Now())
	if err != nil {
		return 0, Permanent(err)
	}

	title := markdownTitle(m)
	// DingTalk markdown has no documented byte cap — still capped to keep an abnormal evidence field from bloating it.
	text, kept := markdownBody(m, 20000)

	var payload any
	if !m.Batch && len(m.Items) == 1 && m.Items[0].DetailURL != "" {
		payload = map[string]any{
			"msgtype": "actionCard",
			"actionCard": map[string]any{
				"title":          title,
				"text":           text,
				"btnOrientation": "0",
				"singleTitle":    "View details",
				"singleURL":      m.Items[0].DetailURL,
			},
		}
	} else {
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": text},
		}
	}

	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	// DingTalk hides business errors inside 200 responses.
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse DingTalk response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 301000 is signature failure, 310000 keyword mismatch — both config errors that
		// retries can't heal.
		return 0, Permanent(fmt.Errorf("DingTalk error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

// dingTalkSignedURL appends timestamp and sign to the webhook per DingTalk's signing rules.
//
// Rules: string-to-sign = timestamp + "\n" + secret; HMAC-SHA256 keyed **also by secret**;
// result is base64 then URL-encoded. timestamp is milliseconds. Empty secret returns the URL
// verbatim — for bots with signing off.
func dingTalkSignedURL(hook, secret string, now time.Time) (string, error) {
	if secret == "" {
		return hook, nil
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u, err := url.Parse(hook)
	if err != nil {
		// Don't pass err through: url.Parse's error text carries the full URL (incl. access_token).
		return "", fmt.Errorf("failed to parse webhook URL (%s)", redactRequestTarget(hook))
	}
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateHTTPURL checks the URL is usable, the scheme supported, and flags literal-IP
// internal targets.
//
// Two subtleties:
//
//  1. **Error text must be redacted.** url.Parse returns *url.Error whose Error() carries
//     the **full original URL** — and these channels embed credentials in their URLs
//     (DingTalk access_token, WeCom key, Telegram bot token, Feishu hook id). This once did
//     `return err` directly, so 'invalid URL format' leaked the credential into test-endpoint
//     400 responses, per-delivery last_error, server logs and the delivery-history API.
//
//  2. **Literal IPs get the internal check here**; domains wait for dial time
//     (blockInternalDial is the real enforcement point and covers DNS rebinding). Doing it
//     here too surfaces the problem at config save, not at first delivery failure.
//
// Scheme restriction is defensive: file:///gopher:// etc. would make http.Client behave
// unexpectedly (already blocked by the scheme check, but no reason to widen the surface).
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("URL cannot be parsed (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http/https supported, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("missing hostname")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("refusing to deliver to local/link-local address %s (set %s=1 if you really need local delivery)", ip, AllowLocalTargetsEnv)
	}
	return nil
}
