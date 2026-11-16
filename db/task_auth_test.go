package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNormalizeTaskAuth pins down validation and defaults: only enabled configs are validated; the URL must be
// http/https; method/request body format/field names have safe defaults; the user password is required.
func TestNormalizeTaskAuth(t *testing.T) {
	ok := &TaskAuthConfig{Enabled: true, LoginURL: "https://t.example.com/login", Username: "u", Password: "p"}
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ok.Method != "POST" || ok.ContentType != "json" || ok.UsernameField != "username" || ok.PasswordField != "password" {
		t.Fatalf("defaults missing: %+v", ok)
	}
	if !ok.HasPassword {
		t.Fatal("HasPassword must be derived")
	}

	bad := []*TaskAuthConfig{
		{Enabled: true, LoginURL: "ftp://t/login", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", Method: "PUT", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", ContentType: "xml", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", Username: "u"},
		{Enabled: true, LoginURL: "https://t/login", Password: "p"},
	}
	for _, b := range bad {
		if err := b.Normalize(); err == nil {
			t.Fatalf("expected error for %+v", b)
		}
	}
	// A disabled config is not validated (a draft can be saved).
	if err := (&TaskAuthConfig{Enabled: false, LoginURL: "not-a-url"}).Normalize(); err != nil {
		t.Fatal("disabled config must not be validated")
	}
}

// TestTaskAuthSecretsNotSerialized is the security boundary: no JSON serialization (API response)
// may contain password / totp_secret; only DBValue storage carries the secrets.
func TestTaskAuthSecretsNotSerialized(t *testing.T) {
	a := &TaskAuthConfig{
		Enabled: true, LoginURL: "https://t/login", Username: "alice", Password: "s3cret",
		TOTPSecret: "GEZDGNBV", HasPassword: true, HasTOTP: true,
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "GEZDGNBV") {
		t.Fatalf("API JSON leaked secrets: %s", raw)
	}

	dbRaw, err := a.DBValue()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dbRaw), "s3cret") || !strings.Contains(string(dbRaw), "GEZDGNBV") {
		t.Fatalf("DBValue must persist secrets: %s", dbRaw)
	}
	back := ParseTaskAuth(dbRaw)
	if back == nil || back.Password != "s3cret" || back.TOTPSecret != "GEZDGNBV" || !back.HasPassword || !back.HasTOTP {
		t.Fatalf("roundtrip failed: %+v", back)
	}
	if ParseTaskAuth([]byte("null")) != nil || ParseTaskAuth(nil) != nil {
		t.Fatal("empty config must parse to nil")
	}
}

// TestTaskAuthPromptBlock: the worker needs the password in clear to log in, but the block must have clear discipline:
// the report must not write out the password/TOTP.
func TestTaskAuthPromptBlock(t *testing.T) {
	a := &TaskAuthConfig{Enabled: true, LoginURL: "https://t/login", Method: "POST", ContentType: "json",
		UsernameField: "user", PasswordField: "pass", Username: "alice", Password: "s3cret",
		SuccessStatus: 200, SuccessContains: "token"}
	a.HasPassword = true
	block := a.PromptBlock()
	for _, want := range []string{"https://t/login", "alice", "s3cret", "token", "do not write the password or TOTP secret into the report"} {
		if !strings.Contains(block, want) {
			t.Fatalf("prompt block missing %q:\n%s", want, block)
		}
	}
	if (&TaskAuthConfig{}).PromptBlock() != "" {
		t.Fatal("disabled config must render empty block")
	}
}
