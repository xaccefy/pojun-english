package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets decides whether messages may be delivered to loopback / link-local
// addresses.
//
// Default deny. Those ranges are no place for IM bots or public mail servers, and what they
// can reach is sensitive: a co-hosted service's admin port, and the cloud metadata endpoint
// (169.254.169.254 — instance credentials). The delivery address is admin-configured, but an
// admin session borrowed via XSS/CSRF, or a second person sharing the JWT, could read
// responses back through config changes — doJSON writes the first 200 bytes of 4xx/5xx
// bodies into last_error, which the delivery-history API echoes: a semi-blind read primitive.
//
// Still, 'local SMTP relay' (postfix on 127.0.0.1:25) is a common self-hosting setup; a
// blanket ban breaks it. So an explicit escape hatch instead of a hardcoded exception:
// set POJUN_NOTIFY_ALLOW_LOCAL=1 to allow.
//
// Exported as AllowLocalTargetsEnv so tests can turn it on deliberately — this package's and
// server/'s cases lean heavily on httptest fake receivers on 127.0.0.1; without it the guard
// blocks them all.
const AllowLocalTargetsEnv = "POJUN_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP reports whether a target IP falls in a 'deny by default' range.
//
// Denies loopback, link-local (incl. cloud metadata 169.254.169.254), unspecified and
// multicast. **Does not deny** RFC1918 private ranges — in-house Mattermost / SMTP relays
// are common legitimate uses; blocking them would break real deployments. Deliberate
// trade-off: guard the truly sensitive targets without disabling normal setups.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) must unwrap to IPv4 first — or it bypasses the check.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial is the http.Transport dialer's Control hook — it checks the target
// **at connect time**.
//
// Why dial time instead of only at config save: this is the final enforcement point. It
// covers two ways around config validation — DNS rebinding (public IP at validation,
// internal IP at connect) and redirects (cross-host redirects are already refused, but a
// same-host redirect could still point the path elsewhere).
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("cannot resolve target address %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("refusing to deliver to local/link-local address %s (set %s=1 if you really need local delivery)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport adds just a dial guard on top of the default Transport.
// Clone keeps every default tuning (pooling, HTTP/2, timeouts) — a check shouldn't change
// other behavior.
//
// Proxy must be cleared explicitly: http.DefaultTransport reads HTTP_PROXY / HTTPS_PROXY
// env vars; the service process may carry them at startup and the cloned transport would too
// — making 'IM push goes direct' a lie and tunneling notifications through the target
// network's proxy. agent/provider.go's quotaAwareHTTPClient already does this.
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{Proxy: nil}
	}
	clone := t.Clone()
	clone.Proxy = nil
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient is shared by every channel delivery.
//
// Deliberately **not** reusing the project's global egress proxy (server-side GlobalProxy):
// that proxy exists for pentest target traffic — often a flaky tunnel — and notification
// availability shouldn't be hostage to the target network. IM push goes direct. Timeout 15s:
// a slower peer is effectively broken anyway.
//
// Cross-host redirects refused: delivery addresses here are 'one fixed endpoint' — a legit
// one never redirects elsewhere, and the channels' credentials (DingTalk access_token, WeCom
// key, Telegram bot token) **sit in the URL**: following a cross-host redirect hands them to
// the redirect target. Same-host redirects (e.g. trailing-slash fixes) stay allowed.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("cross-host redirect refused (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit caps the response body read. A misbehaving peer may return huge content;
// we only need the status code and a short error snippet for the delivery history.
const respBodyLimit = 8 << 10

// doJSON sends one request and returns the (length-capped) response body.
//
// payload=nil sends an empty body (GET, or platforms wanting none).
// headers are appended verbatim — for the generic webhook's custom headers.
//
// Error classification is this function's core job: network failures plus 5xx/408/429 are
// 'retriable'; other 4xx are 'permanent' — retrying a 403 just logs the same error 3 times.
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// A marshal failure is a local bug (bad config field type) — retries will not fix it.
			return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// Bad URL — usually a user typo, permanent. Again err is not passed through:
		// url.Parse's error text carries the full URL.
		return nil, Permanent(fmt.Errorf("invalid request URL: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection refused, DNS failure, timeout — mostly transient; handed to backoff retry.
		//
		// The error text must be redacted before going out: http.Client.Do returns *url.Error whose
		// Error() reads `Op "full URL": underlying error` — and these channels' credentials **live
		// in the URL** (DingTalk access_token, WeCom key, Feishu hook id, Telegram /bot<token>/).
		// Unredacted, the credential flows along the error into four places:
		// notification_deliveries.last_error (plaintext at rest), the delivery-history response
		// (**bypassing channel-config masking**), server logs, and the test-send endpoint's 502
		// text back to the frontend.
		return nil, fmt.Errorf("request failed: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429 (rate limit) and 408 (timeout) deserve retries; other 4xx are config/permission issues — pointless.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("peer rate-limited or timed out (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("peer service error (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("peer rejected request (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet compresses a response body to a one-line excerpt for error messages. Responses
// may carry newlines and big whitespace — verbatim in last_error would wreck the delivery
// history page.
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget compresses a delivery URL to 'scheme://host/…' for error messages.
//
// The package's only address-redaction form, deliberately **brutal**: everything beyond
// scheme and host is dropped, because there's no 'generic and safe' way to tell which URL
// segment is the credential:
//
//	DingTalk  credential in query              /robot/send?access_token=xxx
//	WeCom     credential in query              /cgi-bin/webhook/send?key=xxx
//	Feishu    credential in **last path segment** /open-apis/bot/v2/hook/<hook_id>
//	Telegram  credential in **mid path**       /bot<token>/sendMessage
//
// 'Keep only the useful parts' means per-channel patching — and missing even one is a
// credential leak. Keeping host suffices for troubleshooting (unresolvable DNS, refused
// connect, bad cert all surface); which bot it is comes from the masked tail hint in the
// channel config.
//
// Parse failure returns a fixed placeholder — never echo the raw string.
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparseable URL)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError strips the URL from a transport error, keeping the root cause.
//
// *url.Error is {Op, URL, Err} and Error() prints the URL with it. Taking the Err field
// explicitly skips its Error() — more reliable than string replacement afterward, which
// must handle every URL-encoded/escaped variant and misses easily.
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: unknown error", uerr.Op, host)
	}
	// Non-*url.Error values (e.g. redirect-policy errors) may carry the URL too — redact uniformly.
	return redactURLsInText(err.Error())
}

// redactURLsInText replaces http(s) URLs found in a text with their redacted form.
//
// Fallback for errors without structured fields (redirect-policy errors, third-party custom
// errors). Only http/https prefixes are recognized, split on whitespace and quotes — URLs
// contain neither.
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
