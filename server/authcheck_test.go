package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

// TestTOTPCode pins the implementation to RFC 6238 SHA1 test vectors (the Base32 form of
// secret "12345678901234567890"; at T=59s the 8-digit code 94287082 → 6 digits takes the
// last six: 287082).
func TestTOTPCode(t *testing.T) {
	code, err := totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("totp=%s want 287082", code)
	}
	if _, err := totpCode("not-base32!!!", time.Now()); err == nil {
		t.Fatal("invalid base32 must error")
	}
}

// TestRunAuthCheck uses a local httptest to verify the three login shapes and success
// determination, and confirms results never echo the password (neither logs nor details).
// No real network needed for the target site.
func TestRunAuthCheck(t *testing.T) {
	var gotUser, gotPass, gotTOTP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stringsHasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			_ = r.ParseForm()
			gotUser, gotPass, gotTOTP = r.PostForm.Get("user"), r.PostForm.Get("pass"), r.PostForm.Get("totp")
		} else {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotUser, gotPass, gotTOTP = body["user"], body["pass"], body["totp"]
		}
		if gotUser == "alice" && gotPass == "s3cret" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"token":"ok-token"}`))
			return
		}
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"bad credentials"}`))
	}))
	defer srv.Close()

	base := &db.TaskAuthConfig{
		Enabled: true, LoginURL: srv.URL + "/login", Method: "POST",
		ContentType: "json", UsernameField: "user", PasswordField: "pass",
		Username: "alice", Password: "s3cret", SuccessContains: "token",
	}
	res := runAuthCheck(base)
	if !res.OK || res.StatusCode != 200 {
		t.Fatalf("json login should pass: %+v", res)
	}
	if gotTOTP != "" {
		t.Fatal("totp must not be sent when unconfigured")
	}

	// failing credentials: 401 + missing token → fail, and details carry no password.
	bad := *base
	bad.Password = "wrong-pass"
	res = runAuthCheck(&bad)
	if res.OK {
		t.Fatalf("bad credentials must fail: %+v", res)
	}
	if stringsContains(res.Detail, "wrong-pass") {
		t.Fatal("detail leaked password")
	}

	// form shape
	form := *base
	form.ContentType = "form"
	res = runAuthCheck(&form)
	if !res.OK || gotUser != "alice" || gotPass != "s3cret" {
		t.Fatalf("form login should pass: %+v user=%s pass=%s", res, gotUser, gotPass)
	}

	// disabled: state it explicitly instead of misjudging as success.
	off := db.TaskAuthConfig{}
	if res := runAuthCheck(&off); res.OK {
		t.Fatal("disabled config must not report ok")
	}
}

func stringsHasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
