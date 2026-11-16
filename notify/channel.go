package notify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Channel adapts a notification channel. Implementations must be **stateless**: one instance
// is shared concurrently by many channel configs; credentials always arrive via cfg.
type Channel interface {
	// Kind returns the channel kind identifier; must match the registry key.
	Kind() string
	// Validate runs when config is saved, checking required fields and formats. The returned
	// error is shown verbatim to the configurer, so it must say 'which field is missing' rather
	// than a generic 'invalid config'.
	Validate(cfg map[string]any) error
	// Send delivers one message, returning the **actually delivered item count** and error.
	//
	// Why a count: every platform has a message-length cap; a digest message that can't hold the
	// batch gets truncated. If the caller marked the whole batch delivered, the truncated items
	// would vanish — invisible in the message, shown as success in delivery history, with nothing
	// left to reveal the vulns never went out. With kept returned, the caller marks only the
	// first kept items; the rest wait for the next batch.
	//
	// A returned error means delivery failed; *PermanentError means don't retry.
	// On failure kept is meaningless — callers should ignore it.
	Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
	// DefaultRatePerMin returns the channel's officially suggested per-minute delivery cap, used
	// as the default rate limit for new channel instances. 0 means no known limit.
	DefaultRatePerMin() int
	// SecretKeys returns the config keys that are credentials. API echo masks their values; on
	// update a masked value keeps the stored original. Only the implementation knows which fields
	// are credentials (WeCom's whole webhook URL is one, while DingTalk's is just the secret) —
	// so this knowledge must come from the channel, not guessed upstream.
	SecretKeys() []string
	// DestinationKeys returns the config keys that decide 'where messages go'.
	//
	// Like SecretKeys this is security-relevant: destination and credentials are two separate
	// field sets; if 'change only the address, keep the stored credentials' were allowed, anyone
	// who can edit channel config could exfiltrate the real credentials to a server they control,
	// voiding the masking entirely. See PrepareConfigUpdate.
	DestinationKeys() []string
}

// registry is the channel registry. Deliberately an explicit literal rather than init()
// self-registration: 'which channels exist' is visible in one place, and adding a channel
// surfaces omissions at compile time instead of runtime side effects.
var registry = map[string]Channel{
	KindDingTalk: dingTalkChannel{},
	KindFeishu:   feishuChannel{},
	KindWeCom:    weComChannel{},
	KindWebhook:  webhookChannel{},
	KindTelegram: telegramChannel{},
	KindEmail:    emailChannel{},
}

// Get returns a channel implementation by kind.
func Get(kind string) (Channel, bool) {
	c, ok := registry[kind]
	return c, ok
}

// ValidKind reports whether kind is a supported channel type.
func ValidKind(kind string) bool {
	_, ok := registry[kind]
	return ok
}

// Kinds returns all supported kinds in lexicographic order (stable UI dropdown).
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermanentError marks a delivery failure not worth retrying: bad credentials, target
// rejection, illegal request body, etc. Retries only help transient faults (network blips,
// rate limits, peer 5xx); backing off on permanent failures never succeeds and buries the
// real error under retry noise.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent flags err as a permanent failure. Returns nil for nil err,
// enabling `return Permanent(someCheck())`.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent reports whether the err chain carries the permanent-failure flag.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// ---- config-reading helpers ----
//
// Channel config comes from a database JSONB column: after encoding/json it is
// map[string]any — numbers are float64, arrays []any. The helpers below unify that
// conversion and tolerate type drift from blank UI fields (e.g. a port saved as a string).

// cfgString reads a string config value, always trimmed — form copy-paste brings whitespace easily.
func cfgString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// cfgInt reads an int config value, accepting float64 (JSON default) and string sources.
func cfgInt(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// cfgBool reads a bool config value, accepting strings "true"/"1".
func cfgBool(cfg map[string]any, key string) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

// cfgStrings reads a string-array config value, trimming each and dropping empties.
func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key].([]any)
	if !ok {
		// Also accepts a single string — convenient when a form submits just one value.
		if s := cfgString(cfg, key); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cfgMap reads a string-map config value (e.g. custom HTTP headers); keys and values trimmed, empty keys dropped.
func cfgMap(cfg map[string]any, key string) map[string]string {
	raw, ok := cfg[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out
}
