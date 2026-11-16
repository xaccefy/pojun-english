package db

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// TaskAuthConfig is a task's "target login credentials" config (v0.4.8, modeled on Shannon's
// authentication approach): a worker takes it, logs in first, then tests within the session; after
// creation a login self-check can be triggered so unusable credentials are known before scanning instead of letting a worker probe blindly.
//
// Security boundary: Password / TOTPSecret are tagged json:"-" -- no API response ever returns the
// secrets; DB storage goes through DBValue (which carries the secrets explicitly). HasPassword/HasTOTP are read-only derived flags so
// the frontend knows "a password is configured" without exposing the content.
type TaskAuthConfig struct {
	Enabled         bool              `json:"enabled"`
	LoginURL        string            `json:"login_url"`
	Method          string            `json:"method"`       // POST|GET
	ContentType     string            `json:"content_type"` // json|form
	UsernameField   string            `json:"username_field,omitempty"`
	PasswordField   string            `json:"password_field,omitempty"`
	Username        string            `json:"username,omitempty"`
	Password        string            `json:"-"`
	HasPassword     bool              `json:"has_password,omitempty"`
	TOTPSecret      string            `json:"-"`
	HasTOTP         bool              `json:"has_totp,omitempty"`
	ExtraFields     map[string]string `json:"extra_fields,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	SuccessStatus   int               `json:"success_status,omitempty"`   // 0=do not check the status code
	SuccessContains string            `json:"success_contains,omitempty"` // success when the response body contains this
}

// authWire is the DB storage shape: TaskAuthConfig's json:"-" faces the API, so the DB must explicitly
// carry the password / totp_secret secret fields.
type authWire struct {
	TaskAuthConfig
	Password   string `json:"password,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

// DBValue serializes JSON that includes the secret fields (written to tasks.auth_config).
func (a *TaskAuthConfig) DBValue() ([]byte, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(authWire{TaskAuthConfig: *a, Password: a.Password, TOTPSecret: a.TOTPSecret})
}

// ParseTaskAuth parses auth_config from the DB; empty/nil returns nil. On success it derives
// HasPassword/HasTOTP for frontend display.
func ParseTaskAuth(raw []byte) *TaskAuthConfig {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return nil
	}
	var w authWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil
	}
	a := w.TaskAuthConfig
	a.Password = w.Password
	a.TOTPSecret = w.TOTPSecret
	a.HasPassword = a.Password != ""
	a.HasTOTP = a.TOTPSecret != ""
	return &a
}

// Normalize validates and fills in defaults. Only enabled configs are validated: a disabled config keeps its
// value as-is (so the user can save a draft first and enable it later).
func (a *TaskAuthConfig) Normalize() error {
	if a == nil || !a.Enabled {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(a.LoginURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("the login URL must be a complete http/https URL")
	}
	a.LoginURL = strings.TrimSpace(a.LoginURL)
	a.Method = strings.ToUpper(strings.TrimSpace(a.Method))
	if a.Method == "" {
		a.Method = "POST"
	}
	if a.Method != "POST" && a.Method != "GET" {
		return fmt.Errorf("the login method only supports POST / GET")
	}
	a.ContentType = strings.ToLower(strings.TrimSpace(a.ContentType))
	if a.ContentType == "" {
		a.ContentType = "json"
	}
	if a.ContentType != "json" && a.ContentType != "form" {
		return fmt.Errorf("the login request body only supports json / form")
	}
	if strings.TrimSpace(a.UsernameField) == "" {
		a.UsernameField = "username"
	}
	if strings.TrimSpace(a.PasswordField) == "" {
		a.PasswordField = "password"
	}
	if strings.TrimSpace(a.Username) == "" || a.Password == "" {
		return fmt.Errorf("both username and password are required when enabling a login config")
	}
	if a.SuccessStatus != 0 && (a.SuccessStatus < 100 || a.SuccessStatus > 599) {
		return fmt.Errorf("the success status code must be between 100-599 (0 means do not check)")
	}
	a.HasPassword = a.Password != ""
	a.HasTOTP = strings.TrimSpace(a.TOTPSecret) != ""
	return nil
}

// PromptBlock renders the text block injected into the worker system prompt. It describes things neutrally and never prints
// the password in clear -- credentials are given as "field list + value" and the worker logs in with them directly.
func (a *TaskAuthConfig) PromptBlock() string {
	if a == nil || !a.Enabled {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n━━ Target login credentials (task-level config) ━━\n")
	b.WriteString("The target site has login credentials configured. Log in with them before testing and keep the authenticated state for the session; do not write the password or TOTP secret into the report.\n")
	b.WriteString("Login URL: " + a.LoginURL + "\n")
	b.WriteString("Request method: " + a.Method + ", request body format: " + a.ContentType + "\n")
	b.WriteString("Username field: " + a.UsernameField + " = " + a.Username + "\n")
	b.WriteString("Password field: " + a.PasswordField + " = " + a.Password + "\n")
	if a.HasTOTP {
		b.WriteString("TOTP secret (Base32): " + a.TOTPSecret + " (generate a 6-digit code for the current time and fill it into the code field)\n")
	}
	if len(a.ExtraFields) > 0 {
		keys := make([]string, 0, len(a.ExtraFields))
		for k := range a.ExtraFields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("Additional form fields: ")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(k + "=" + a.ExtraFields[k])
		}
		b.WriteString("\n")
	}
	if len(a.Headers) > 0 {
		b.WriteString("Additional request headers: ")
		first := true
		for k, v := range a.Headers {
			if !first {
				b.WriteString(", ")
			}
			first = false
			b.WriteString(k + ": " + v)
		}
		b.WriteString("\n")
	}
	if a.SuccessStatus > 0 {
		b.WriteString(fmt.Sprintf("Success criterion: response status code %d", a.SuccessStatus))
		if a.SuccessContains != "" {
			b.WriteString(fmt.Sprintf(", and the response body contains %q", a.SuccessContains))
		}
		b.WriteString("\n")
	} else if a.SuccessContains != "" {
		b.WriteString(fmt.Sprintf("Success criterion: the response body contains %q\n", a.SuccessContains))
	}
	b.WriteString("After a successful login, extract the session credential (Set-Cookie/token) from the response headers/body and carry it on later requests. If the login fails, record the failure reason faithfully instead of guessing other credentials.")
	return b.String()
}
