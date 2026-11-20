package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Pre-registered credential login breaker (issue #24).
//
// ## Why it exists
//
// Once a task's pre-registered test credential has expired or been rotated by the target's admin,
// workers on different intents each call session_login and retry — the target's consecutive-failure
// lockout policy then locks out the customer's test, or even production, account. That is an
// authorization/compliance incident: with the account locked the task can't proceed and the customer
// relationship suffers. Prompt-side shielding can't stop the storm (each worker only sees its own
// 401), so the trip has to be deterministic, in the Go execution layer.
//
// ## Semantics
//
//   - 【Pre-registered credentials】 only (registered on an asset and referenced via
//     asset_id+auth_index): a credential passed explicitly as username/password is a one-off typed by
//     the model, has no "same credential hammered repeatedly" shape, and is excluded.
//   - Only 401/403 count as a failure (explicit auth rejection); 2xx clears the count; other status
//     codes (5xx, other 4xx, 3xx) are neutral — neither a failure nor a reset — so a flaky target or a
//     malformed model argument can't inflate the count.
//   - loginBreakerThreshold consecutive 401/403 → trip for loginBreakerLockTTL: meanwhile session_login
//     on that credential is 【refused locally with no network request at all】. On TTL expiry one
//     half-open attempt passes: success resets, another 401/403 trips again — covering the case where
//     the target's locked account was later unlocked by an admin, so the credential recovers unchanged.
//   - A credential content change (operator rotates the password/token on the asset) resets
//     automatically: state is keyed by the credential hash, and a different hash means a new credential.
//   - Transport errors (connect failure/proxy fault) don't count — that's an egress problem, not a
//     credential problem.
//
// ## Why no persistence
//
// Breaker state is in memory: a process restart clears it and counting starts over. The window for a
// pre-registered credential failure storm is the task's run, and restart windows are small; persisting
// would only add the complexity of not harming new tasks after a restart.
const (
	loginBreakerThreshold = 2
	loginBreakerLockTTL   = 30 * time.Minute
)

// loginBreakerState is one pre-registered credential's breaker state.
type loginBreakerState struct {
	SecretHash  string    // hash of the current credential content: changed = operator rotated it, auto-reset
	Failures    int       // consecutive auth failures (cleared on success)
	LockedUntil time.Time // non-zero = tripped; one request passes when it expires (half-open)
	LastStatus  int       // HTTP status of the most recent failure
	UpdatedAt   time.Time
}

var (
	loginBreakerMu     sync.Mutex
	loginBreakerStates = map[string]*loginBreakerState{}
	loginBreakerNow    = time.Now // injected by tests
)

// loginBreakerKey returns a pre-registered credential's breaker key and its content hash. The key is
// per task (different tasks' attempts on the same asset don't affect each other) and the hash covers the
// credential content — a password change is a new identity.
func loginBreakerKey(taskID, assetID, authIndex int64, username, secret string) (key, secretHash string) {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%d|%s|%s", taskID, assetID, authIndex, username, secret)))
	return fmt.Sprintf("%d/%d/%d", taskID, assetID, authIndex), hex.EncodeToString(h[:12])
}

// loginBreakerCheck is called before sending a login request. Returns (locked, message): with
// locked=true the caller must refuse locally and send no network request.
func loginBreakerCheck(key, secretHash string) (bool, string) {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	st, ok := loginBreakerStates[key]
	if !ok {
		return false, ""
	}
	if st.SecretHash != secretHash {
		// The operator updated the credential: the old trip state is void, treat it as new.
		delete(loginBreakerStates, key)
		return false, ""
	}
	now := loginBreakerNow()
	if !st.LockedUntil.IsZero() {
		if now.Before(st.LockedUntil) {
			remain := st.LockedUntil.Sub(now).Round(time.Second)
			return true, fmt.Sprintf(
				"this pre-registered credential has failed auth %d times in a row (last HTTP %d) and is tripped for about %s: refused locally with no login request sent, so the target's lockout policy can't lock the customer account. Test unauthenticated surface instead, or have the operator update/reset the credential on the asset (it recovers automatically once updated).",
				st.Failures, st.LastStatus, remain)
		}
		// TTL expired: one half-open request passes. The tally is kept — another failure re-trips at once.
		st.LockedUntil = time.Time{}
	}
	return false, ""
}

// loginBreakerRecordFailure records one auth failure. A non-empty return means the threshold was hit and
// the breaker tripped; the caller should attach it to the tool result to inform the model.
func loginBreakerRecordFailure(key, secretHash string, status int) string {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	now := loginBreakerNow()
	st, ok := loginBreakerStates[key]
	if !ok || st.SecretHash != secretHash {
		st = &loginBreakerState{SecretHash: secretHash}
		loginBreakerStates[key] = st
	}
	// Failure again after a half-open pass: keep the tally (already >= threshold) and re-trip at once.
	st.Failures++
	st.LastStatus = status
	st.UpdatedAt = now
	if st.Failures >= loginBreakerThreshold {
		st.LockedUntil = now.Add(loginBreakerLockTTL)
		return fmt.Sprintf(
			"⚠️ this pre-registered credential has failed auth %d times in a row (HTTP %d) and is tripped for %s: later session_login calls on it are refused locally with no request sent, so the target's lockout policy can't lock the customer account. Switch to another credential on the asset (auth_index), test unauthenticated surface, or have the operator update/reset the credential.",
			st.Failures, status, loginBreakerLockTTL)
	}
	return fmt.Sprintf("this pre-registered credential has failed auth %d times in a row (HTTP %d); %d more failure(s) will trip it and stop login requests to the target. Prefer another auth_index or unauthenticated surface.",
		st.Failures, status, loginBreakerThreshold-st.Failures)
}

// loginBreakerRecordSuccess records a successful login: clears the count and the trip.
func loginBreakerRecordSuccess(key, secretHash string) {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	st, ok := loginBreakerStates[key]
	if !ok || st.SecretHash != secretHash {
		return
	}
	delete(loginBreakerStates, key)
}

// resetLoginBreakers clears all breaker state (tests only).
func resetLoginBreakers() {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	loginBreakerStates = map[string]*loginBreakerState{}
}

// classifyLoginOutcome classifies a login response as success / failure / neutral.
// 401/403 are explicit auth rejections; 2xx is success; everything else (5xx, other 4xx, 3xx) is neutral.
func classifyLoginOutcome(status int) string {
	switch {
	case status == 401 || status == 403:
		return "failure"
	case status >= 200 && status < 300:
		return "success"
	}
	return "neutral"
}
