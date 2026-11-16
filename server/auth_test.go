package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GetSetting's 'key missing' vs 'read error' differ only by the returned error — value
// is "" in both cases. If a password handler treats an error as 'no password set yet',
// it opens the init path during a database hiccup: authInit would let an
// unauthenticated request overwrite the existing admin password, and authStatus would
// send the frontend to /setup to do exactly that.
//
// These two tests close the handler's connection pool to simulate read failure and
// assert both handlers fail closed.
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// close the pool so later GetSetting calls return an error, not sql.ErrNoRows.
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (a read failure treated as uninitialized would send users to /setup to overwrite the password); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("must not answer initialized on read failure, got %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (letting a read failure through lets an unauthenticated request overwrite the password); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("must not issue a token on read failure: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"empty", "", true},
		{"seven chars", "1234567", true},
		{"eight chars", "12345678", false},
		{"eight CJK chars count as characters not bytes", "password", false},
		{"three CJK chars = 9 bytes but only 3 characters", "pwd", true},
		{"72 bytes", strings.Repeat("a", 72), false},
		{"73 bytes exceeds the bcrypt cap", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}

// testKey builds a Server with a signing key installed (atomic.Value fields can't be
// initialized in a literal — tests all go through here).
func testKey(k []byte) *Server {
	s := &Server{}
	s.jwtKey.Store(k)
	return s
}

// login anti-bruteforce: 5 failures per IP in a 10-minute window → 15-minute lock;
// success resets; other IPs unaffected; global threshold backstops XFF spoofing.
func TestLoginLimiterPerIPLockout(t *testing.T) {
	l := &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	for i := 0; i < loginMaxFailsPerIP; i++ {
		l.recordFail("1.2.3.4")
	}
	ok, wait := l.allow("1.2.3.4")
	if ok {
		t.Fatal("consecutive failures should lock")
	}
	if wait <= 0 || wait > loginLockoutPerIP {
		t.Fatalf("remaining lock time=%v, should be within (0,%v]", wait, loginLockoutPerIP)
	}
	if ok, _ := l.allow("5.6.7.8"); !ok {
		t.Fatal("other IPs must not be locked out too")
	}
	l.recordSuccess("1.2.3.4")
	if ok, _ := l.allow("1.2.3.4"); !ok {
		t.Fatal("a successful login should reset and unlock")
	}
}

// after success, failure counts restart at zero — without the reset, a normal user's
// occasional typo would slowly accumulate into a lock.
func TestLoginLimiterSuccessResetsWindow(t *testing.T) {
	l := &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	for i := 0; i < loginMaxFailsPerIP-1; i++ {
		l.recordFail("9.9.9.9")
	}
	l.recordSuccess("9.9.9.9")
	for i := 0; i < loginMaxFailsPerIP-1; i++ {
		l.recordFail("9.9.9.9")
	}
	if ok, _ := l.allow("9.9.9.9"); !ok {
		t.Fatal("under the threshold after reset must not lock")
	}
	l.recordFail("9.9.9.9")
	if ok, _ := l.allow("9.9.9.9"); ok {
		t.Fatal("consecutive failures to threshold after reset should lock again")
	}
}

// global backstop: 1 failure per IP, enough IPs to hit the global threshold → global
// lock (including brand-new IPs).
func TestLoginLimiterGlobalBackstop(t *testing.T) {
	l := &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}
	for i := 0; i < loginGlobalMaxFails; i++ {
		l.recordFail(fmt.Sprintf("10.0.0.%d", i))
	}
	if ok, _ := l.allow("10.9.9.9"); ok {
		t.Fatal("at the global failure threshold even a brand-new IP should be caught by the global lock")
	}
}

// /api/health is the only unauthenticated liveness endpoint: the response body must
// never contain the service name or version — that's the cheapest body fingerprint for
// public scanning engines. Version lookup goes through authenticated /api/version.
func TestHealthResponseHasNoIdentity(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.health(w, httptest.NewRequest("GET", "/api/health", nil))
	body := w.Body.String()
	for _, banned := range []string{"pojun", "POJUN", "version", "0.3"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(banned)) {
			t.Fatalf("health response contains fingerprint info %q: %s", banned, body)
		}
	}
	if !strings.Contains(body, "\"ok\":true") {
		t.Fatalf("health should keep the ok liveness field: %s", body)
	}
}

// security-headers middleware: nosniff / DENY / no-referrer required; /api/* must
// carry no-store.
func TestSecurityHeadersApplied(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := securityHeaders(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/tasks", nil))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options: DENY")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("/api/* missing Cache-Control: no-store")
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("arbitrary cross-origin reads must not be allowed anymore (ACAO removed)")
	}
}
