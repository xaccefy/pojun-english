package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// the floor matches the setup page's frontend check — validating only in the
	// frontend is no validation at all (the API can be hit directly). The ceiling is
	// bcrypt's hard limit: past 72 bytes GenerateFromPassword returns
	// ErrPasswordTooLong — rejecting early beats an opaque 'encryption failed'.
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable is the uniform reply for failed password-related reads.
// These handlers must never treat 'unreadable' as 'not set': authInit once allowed
// requests through on a DB error, letting an unauthenticated request overwrite the
// existing admin password.
const errDataSourceUnavailable = "data source temporarily unavailable — retry later"

// validatePassword returns "" on pass, else a user-displayable reason.
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("password must be at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("password must not exceed %d bytes", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key migrated %s -> %s (out of the browsable workspace)", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] new JWT key written to %s", path)
	return buf, nil
}

// currentJWTKey atomically reads the current signing key (changes immediately after a
// password-change rotation).
func (s *Server) currentJWTKey() []byte {
	if v, ok := s.jwtKey.Load().([]byte); ok {
		return v
	}
	return nil
}

// rotateJWTKey generates a new key, atomically swaps and persists it: **all issued
// tokens die instantly**. Rotation on password change is mandatory — otherwise a leaked
// old token keeps working until its natural 7-day expiry and 'change the password to
// kick the attacker' is an empty promise.
func (s *Server) rotateJWTKey() error {
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(filepath.Join(s.keyDir, jwtKeyFilename), buf, 0o600); err != nil {
		return fmt.Errorf("write jwt key: %w", err)
	}
	s.jwtKey.Store(buf)
	log.Printf("[auth] JWT key rotated (password change) — all old sessions dead")
	return nil
}

// clientIP extracts the client IP: first hop of X-Forwarded-For behind a reverse proxy
// (the deploy guide requires the proxy to overwrite that header), RemoteAddr when
// direct. XFF is spoofable, so the limiter keeps a global cap as backstop — spoofed
// infinite IPs can't break the global threshold.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginLimiter is the process-level anti-bruteforce gate for login/init:
//   - per IP: 5 failures in a 10-minute window → locked 15 minutes;
//   - global: 30 failures in a 1-minute window → global lock 5 minutes (covers XFF
//     spoofing and distributed low-rate).
//
// In-memory is fine: a restart only resets the attacker's wait time, not correctness.
// Returns (allowed, remaining lock time).
type loginLimiter struct {
	mu          sync.Mutex
	fails       map[string][]time.Time // ip → failure timestamps (sliding window)
	lockedUntil map[string]time.Time   // ip → lock expiry
	globalFails []time.Time
	globalUntil time.Time
}

var loginLimit = &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}

const (
	loginMaxFailsPerIP   = 5
	loginFailWindow      = 10 * time.Minute
	loginLockoutPerIP    = 15 * time.Minute
	loginGlobalMaxFails  = 30
	loginGlobalWindow    = time.Minute
	loginGlobalLockout   = 5 * time.Minute
	loginFailureMinDelay = 300 * time.Millisecond // artificial floor on failure responses, flattening timing
)

func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if until, ok := l.lockedUntil[ip]; ok && now.Before(until) {
		return false, until.Sub(now)
	}
	if now.Before(l.globalUntil) {
		return false, l.globalUntil.Sub(now)
	}
	// lazily prune expired windows so the map doesn't grow forever with scan traffic.
	for k, until := range l.lockedUntil {
		if now.After(until) && len(l.fails[k]) == 0 {
			delete(l.lockedUntil, k)
		}
	}
	return true, 0
}

func (l *loginLimiter) recordFail(ip string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// per-IP sliding window.
	f := append(l.fails[ip], now)
	cut := now.Add(-loginFailWindow)
	i := 0
	for i < len(f) && f[i].Before(cut) {
		i++
	}
	f = f[i:]
	l.fails[ip] = f
	if len(f) >= loginMaxFailsPerIP {
		l.lockedUntil[ip] = now.Add(loginLockoutPerIP)
		l.fails[ip] = nil
	}
	// global sliding window.
	l.globalFails = append(l.globalFails, now)
	gcut := now.Add(-loginGlobalWindow)
	j := 0
	for j < len(l.globalFails) && l.globalFails[j].Before(gcut) {
		j++
	}
	l.globalFails = l.globalFails[j:]
	if len(l.globalFails) >= loginGlobalMaxFails {
		l.globalUntil = now.Add(loginGlobalLockout)
		l.globalFails = nil
	}
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
	delete(l.lockedUntil, ip)
}

// loginGuard wraps login/init with the anti-bruteforce semantics: over-limit gets a
// straight 429; failures are recorded and the response artificially slowed. Returning
// false means the response was written — the caller returns directly.
func loginGuard(w http.ResponseWriter, r *http.Request, action string) bool {
	ip := clientIP(r)
	if ok, wait := loginLimit.allow(ip); !ok {
		log.Printf("[auth] %s rate limit hit ip=%s remaining=%s", action, ip, wait.Truncate(time.Second))
		writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return false
	}
	if action == "login-fail" {
		loginLimit.recordFail(ip)
		log.Printf("[auth] login failed ip=%s", ip)
		time.Sleep(loginFailureMinDelay)
	}
	return true
}

// signJWT issues a 7-day HS256 token for user POJUN.
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "POJUN",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	return err == nil && t.Valid
}

// sseQueryTokenPaths is the only whitelist of endpoints accepting ?token= query auth:
// browser EventSource can't send an Authorization header, and these direct SSE stream
// endpoints historically authed via query token. Every other path no longer takes
// tokens from query (N1 convergence) — tokens end up in access logs / X-Forwarded
// headers / Referer, and cookie-capable paths (frontend is configured) shouldn't keep
// that risk. Same-origin EventSource sends cookies by default; query is just the
// fallback. side-questions' events endpoint carries a request id — covered by the
// prefix+suffix check in queryTokenAllowed.
var sseQueryTokenPaths = map[string]bool{
	"/api/exploration/activity/stream": true,
	"/api/logs/stream":                 true,
	"/api/update/stream":               true,
}

// queryTokenAllowed reports whether ?token= may be trusted for this request:
// only the four URL-direct SSE stream endpoints (see sseQueryTokenPaths).
func queryTokenAllowed(r *http.Request) bool {
	if sseQueryTokenPaths[r.URL.Path] {
		return true
	}
	// side-questions events are per-request-id: /api/side-questions/<id>/events
	return strings.HasPrefix(r.URL.Path, "/api/side-questions/") && strings.HasSuffix(r.URL.Path, "/events")
}

// extractToken reads the JWT from Authorization: Bearer header, or the
// pojun_token cookie. ?token= query is only honored on the SSE stream endpoints
// (queryTokenAllowed) — elsewhere the token would leak into access logs and
// Referer headers without giving up anything the cookie doesn't already do.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("pojun_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if queryTokenAllowed(r) {
		return r.URL.Query().Get("token")
	}
	return ""
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "unauthorized")
			return
		}
		if !verifyJWT(tok, s.currentJWTKey()) {
			writeErr(w, 401, "invalid or expired token")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// a read failure must return 503, not initialized:false — on initialized:false the
// frontend pushes the user to /setup to set a password (login/page.tsx), and wrapping a
// DB failure as 200 pushes the user toward overwriting the existing password.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	if !loginGuard(w, r, "init") {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "password already set")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "password must not be empty")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "password encryption failed")
		return
	}
	// INSERT ... ON CONFLICT DO NOTHING, not upsert: the GetSetting above is only a
	// fast-fail path — the real 'first-time-only' guarantee is the PK constraint. bcrypt
	// takes tens of ms; another request may well set the password first, and the read
	// check itself can silently fail too.
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "save failed: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "password already set")
		return
	}
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.currentJWTKey()) {
		writeErr(w, 401, "unauthorized")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "malformed request")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "new password must not be empty")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "password not initialized — set one first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "current password is wrong")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "password encryption failed")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "save failed: "+err.Error())
		return
	}
	// rotate the signing key: the old password may already be leaked (a password change
	// is often *because* of suspected leakage) — without rotation, sessions holding old
	// tokens live to natural expiry.
	if err := s.rotateJWTKey(); err != nil {
		// password changed but rotation failed: don't roll back (a changed password is
		// safer than unchanged), but warn explicitly.
		log.Printf("[auth] JWT key rotation failed after password change: %v (old tokens still valid — restart the service to force rotation)", err)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if !loginGuard(w, r, "login") {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "malformed request")
		return
	}
	if req.Username != "POJUN" && req.Username != "ARTEX" { // v0.4.19 rename: accept the legacy username
		writeErr(w, 401, "wrong username or password")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "password not initialized — set one first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		loginGuard(w, r, "login-fail")
		writeErr(w, 401, "wrong username or password")
		return
	}
	loginLimit.recordSuccess(clientIP(r))
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
