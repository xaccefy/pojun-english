package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// emailDialTimeout / emailSessionTimeout bound connect and the whole SMTP session
// respectively. net/smtp has no timeouts of its own — without these, a stuck peer pins the
// delivery goroutine forever, and since the dispatcher is a single serial goroutine, the
// whole notification system stalls.
const (
	emailDialTimeout    = 10 * time.Second
	emailSessionTimeout = 45 * time.Second
)

// emailChannel implements SMTP email delivery.
type emailChannel struct{}

func (emailChannel) Kind() string { return KindEmail }

// Email has no platform rate cap, but shouldn't spam either — a generous default.
func (emailChannel) DefaultRatePerMin() int { return 60 }

// Only the password is masked. SMTP host, account and recipients aren't secret — masking them just makes editing harder.
func (emailChannel) SecretKeys() []string { return []string{"password"} }

// host/port decide which server receives the password; tls decides transport encryption.
// Any change to the three requires re-affirming the password — which also forces 'turning
// off TLS' to carry credentials explicitly, not as a casual flip.
func (emailChannel) DestinationKeys() []string { return []string{"host", "port", "tls"} }

func (emailChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "host") == "" {
		return errors.New("missing SMTP server address")
	}
	port := cfgInt(cfg, "port")
	if port <= 0 || port > 65535 {
		return errors.New("invalid SMTP port (expected 1-65535)")
	}
	if cfgString(cfg, "from") == "" {
		return errors.New("missing sender address")
	}
	if len(cfgStrings(cfg, "to")) == 0 {
		return errors.New("at least one recipient address required")
	}
	return nil
}

func (c emailChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	host := cfgString(cfg, "host")
	port := cfgInt(cfg, "port")
	from := cfgString(cfg, "from")
	to := cfgStrings(cfg, "to")
	username := cfgString(cfg, "username")
	password := cfgString(cfg, "password")
	implicitTLS := cfgBool(cfg, "tls")

	msg, err := buildEmailMessage(from, to, m)
	if err != nil {
		return 0, Permanent(err)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := emailDial(ctx, addr, host, implicitTLS)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	// STARTTLS: upgrade when the peer supports it. No credentials over plaintext (see auth below).
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return 0, fmt.Errorf("STARTTLS failed: %w", err)
			}
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			// smtp.PlainAuth refuses to send credentials over unencrypted connections (unless the
			// target is localhost). That's **correct** security behavior — not to be bypassed — but the
			// reason needs translating, or users see 'unencrypted connection' with no idea what to do.
			if strings.Contains(err.Error(), "unencrypted connection") {
				return 0, Permanent(fmt.Errorf("refusing to send credentials: connection unencrypted. Enable TLS, or use port 465 (implicit TLS) (%w)", err))
			}
			return 0, Permanent(fmt.Errorf("SMTP auth failed: %w", err))
		}
	}
	if err := client.Mail(from); err != nil {
		return 0, smtpStageError(fmt.Sprintf("sender %s rejected", from), err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return 0, smtpStageError(fmt.Sprintf("recipient %s rejected", rcpt), err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return 0, fmt.Errorf("failed to write email body: %w", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("failed to submit email: %w", err)
	}
	// A failed Quit doesn't change that the server accepted the mail — its error is ignored.
	_ = client.Quit()
	// Email isn't length-truncated (full HTML body sent) — the whole batch counts delivered.
	return len(m.Items), nil
}

// emailDial opens an SMTP connection.
//
// implicitTLS=true means 'TLS on connect' like port 465; false means plaintext connect on
// 25/587 then STARTTLS. Don't mix: a plaintext greeting to 465 gets cut immediately.
//
// The session deadline is set **at dial time** (not patched later) because net/smtp's Client
// hides the underlying conn in an unexported field — once handed over, the pre-set deadline
// is the only bound. This also covers handshake-phase blocking.
// Control hangs blockInternalDial — the same guard the HTTP channels share. Without it SMTP
// is the hole in the SSRF defense: host=169.254.169.254 or 127.0.0.1 connects directly, and
// a failed smtp.NewClient handshake wraps the peer's reply line into the error, which
// last_error echoes through the delivery-history API — a semi-blind read primitive; the
// 'refused vs timeout' timing gap even enables port probing. Dial time is the real
// enforcement point and covers DNS rebinding.
func emailDial(ctx context.Context, addr, host string, implicitTLS bool) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: emailDialTimeout, Control: blockInternalDial}
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect SMTP server: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(emailSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP handshake failed: %w", err)
	}
	return client, nil
}

// smtpStageError classifies a stage failure as 'retriable' or 'permanent' by SMTP reply code.
//
// Why distinguish: 4xx and 5xx mean entirely different things —
//   - 4xx (450 greylisting, 451 local error, 452 insufficient storage) is a **temporary**
//     rejection; retry later is the norm. Greylisting hits almost every first delivery.
//   - 5xx (550 no such user, 553 invalid address) is permanent — retrying is pointless.
//
// Judging everything permanent would drop **every** push into failed on first attempt behind
// a greylisting server — exactly where automatic retries matter most.
// The reply code is the error text's first three digits; when no code parses, treat as
// retriable (one extra try beats condemning a transient fault to permanent).
func smtpStageError(what string, err error) error {
	code := smtpReplyCode(err.Error())
	if code >= 500 && code < 600 {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	return fmt.Errorf("%s: %w", what, err)
}

// smtpReplyCode extracts the leading 3-digit reply code from SMTP error text; 0 if absent.
// net/smtp doesn't export a code field — text parsing is the only way; format '450 4.7.1 ...'.
func smtpReplyCode(text string) int {
	if len(text) < 3 {
		return 0
	}
	n, err := strconv.Atoi(text[:3])
	if err != nil {
		return 0
	}
	return n
}

// buildEmailMessage assembles the full RFC 5322 message.
//
// Base64 body for two reasons: SMTP caps a line at 1000 bytes and HTML bodies (digests
// especially) easily produce longer lines; base64 also never starts a line with ".",
// skipping SMTP dot-stuffing entirely.
func buildEmailMessage(from string, to []string, m Message) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	// Non-ASCII subjects need RFC 2047 encoding or clients show mojibake.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", htmlTitle(m)))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	// Email has no hard length cap — no body truncation.
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody(m, 0)))
	// base64 wraps at 76 chars per RFC 2045.
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return b.String(), nil
}
