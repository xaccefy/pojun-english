package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// totpCode generates the current window's 6-digit code per RFC 6238 (HMAC-SHA1, 30s).
// Only standard login scenarios need support: Base32 secrets (spaces and case
// ignored).
func totpCode(secret string, at time.Time) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("TOTP secret is not valid Base32: %w", err)
	}
	counter := uint64(at.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// authCheckResult is the login self-check result (no credentials echoed).
type authCheckResult struct {
	OK         bool   `json:"ok"`
	StatusCode int    `json:"status_code,omitempty"`
	Matched    bool   `json:"matched"` // hit a success criterion
	Detail     string `json:"detail"`
	ElapsedMS  int64  `json:"elapsed_ms"`
	UsedTOTP   bool   `json:"used_totp,omitempty"`
	CheckedAt  string `json:"checked_at"`
}

// runAuthCheck sends one real login request with the task's configured credentials and
// judges success. Rules match the worker prompt: SuccessStatus (0 = no check) and
// SuccessContains must both hold; with neither configured, 2xx/3xx counts as success.
// Details never carry the password/TOTP/response body (status code and match note
// only).
func runAuthCheck(cfg *db.TaskAuthConfig) authCheckResult {
	res := authCheckResult{CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	start := time.Now()
	if cfg == nil || !cfg.Enabled {
		res.Detail = "no login credentials configured"
		return res
	}
	fields := map[string]string{
		cfg.UsernameField: cfg.Username,
		cfg.PasswordField: cfg.Password,
	}
	for k, v := range cfg.ExtraFields {
		fields[k] = v
	}
	if cfg.HasTOTP {
		code, err := totpCode(cfg.TOTPSecret, time.Now())
		if err != nil {
			res.Detail = err.Error()
			return res
		}
		res.UsedTOTP = true
		// when the OTP field name isn't configured separately, fill common names
		// totp/code/otp.
		names := []string{"totp", "otp", "code"}
		placed := false
		for _, n := range names {
			if _, exists := fields[n]; !exists {
				fields[n] = code
				placed = true
				break
			}
		}
		_ = placed
	}

	var req *http.Request
	var err error
	if cfg.Method == "GET" {
		q := url.Values{}
		for k, v := range fields {
			q.Set(k, v)
		}
		u := cfg.LoginURL
		if strings.Contains(u, "?") {
			u += "&" + q.Encode()
		} else {
			u += "?" + q.Encode()
		}
		req, err = http.NewRequest(http.MethodGet, u, nil)
	} else if cfg.ContentType == "form" {
		form := url.Values{}
		for k, v := range fields {
			form.Set(k, v)
		}
		req, err = http.NewRequest(http.MethodPost, cfg.LoginURL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		body, _ := json.Marshal(fields)
		req, err = http.NewRequest(http.MethodPost, cfg.LoginURL, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		res.Detail = "failed to build the login request: " + err.Error()
		return res
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	res.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Detail = "login request failed: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	res.StatusCode = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))

	statusOK := cfg.SuccessStatus == 0 || resp.StatusCode == cfg.SuccessStatus
	if cfg.SuccessStatus == 0 {
		statusOK = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	containsOK := cfg.SuccessContains == "" || strings.Contains(string(body), cfg.SuccessContains)
	res.Matched = statusOK && containsOK
	res.OK = res.Matched
	switch {
	case res.OK && cfg.SuccessStatus > 0:
		res.Detail = fmt.Sprintf("login succeeded (HTTP %d, hit the success status code)", resp.StatusCode)
	case res.OK && cfg.SuccessContains != "":
		res.Detail = fmt.Sprintf("login succeeded (HTTP %d, response contains the match string)", resp.StatusCode)
	case res.OK:
		res.Detail = fmt.Sprintf("login succeeded (HTTP %d)", resp.StatusCode)
	default:
		parts := []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
		if cfg.SuccessStatus > 0 && resp.StatusCode != cfg.SuccessStatus {
			parts = append(parts, fmt.Sprintf("status code differs from expected %d", cfg.SuccessStatus))
		}
		if cfg.SuccessContains != "" && !containsOK {
			parts = append(parts, "response lacks the match string "+strconv.Quote(cfg.SuccessContains))
		}
		res.Detail = "login failed: " + strings.Join(parts, ", ")
	}
	return res
}

// taskAuthCheck runs one real login self-check against the task's configured
// credentials.
// POST /api/tasks/{id}/auth-check
func (s *Server) taskAuthCheck(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || s.m.PG() == nil {
		writeErr(w, 400, "invalid task id")
		return
	}
	t, err := s.m.PG().GetTask(id)
	if err != nil || t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if t.AuthConfig == nil || !t.AuthConfig.Enabled {
		writeErr(w, 400, "this task has no login credentials configured")
		return
	}
	writeJSON(w, 200, runAuthCheck(t.AuthConfig))
}
