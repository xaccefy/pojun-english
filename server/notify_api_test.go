package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/notify"
)

// This file covers the push feature end to end: vuln insert → event → fan-out → real HTTP.
//
// A safety note: these cases **do not call the global Notifier.step()** — they call
// stepRealtime/stepDigest only for channels they created. step() walks every enabled
// channel in the DB; run against a dev DB with real DingTalk/WeCom bots, a global step
// would really push the test vulns into those groups. Per-channel calls bound the blast
// radius strictly to the test's own fake receivers.
//
// Cleanup: at case end, delete this case's events (cascading to deliveries) and channels,
// leaving no backlog for real channels.
//
// Assertion discipline: stepRealtime/stepDigest return nothing and log internally, so we
// assert on **observable external behavior** (what the fake receiver got, what state the
// delivery row landed in) rather than return values — closer to the real call path than
// stubbing return values.

// notifyFixture is the shared harness for this file's cases.
type notifyFixture struct {
	s       *Server
	pg      *db.DB
	request func(method, path, body string) *httptest.ResponseRecorder
	n       *Notifier
	// self-built task/exploration: cases record vulns here, isolated from other cases' data.
	taskID int64
	expID  int64
	// events produced after cleanupMark get deleted during cleanup.
	cleanupMark int64
}

func newNotifyFixture(t *testing.T) *notifyFixture {
	t.Helper()
	// all fake receivers in this file run on 127.0.0.1, and delivery refuses loopback by
	// default (SSRF guard vs same-host services and cloud metadata). Tests enable this
	// switch explicitly; the guard's default-deny behavior is covered by notify's ssrf_test.go.
	t.Setenv(notify.AllowLocalTargetsEnv, "1")
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg

	// build our own task: the shared trafficEvidenceServer's task has no exploration id,
	// and recording a vuln requires one.
	task, err := s.m.CreateTask("notify push test", "push behavior verification", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID) })

	var mark int64
	if err := pg.QueryRow(`SELECT COALESCE(max(id),0) FROM notification_events`).Scan(&mark); err != nil {
		t.Fatal(err)
	}
	// make the fixture self-contained: mark events that existed before it was built as
	// already fanned out, in one shot.
	//
	// Why it's required: FanOutPendingEvents is **global** — it expands every pending event
	// in the DB onto every matching channel. The shared trafficEvidenceServer itself
	// records a vuln (the initial finding it returns), and other cases may leave residue.
	// Without isolation, those stray events get fanned out to this case's channel, making
	// 'expect N deliveries' assertions intermittently wrong — and the failure mode depends
	// on case order, which is harder to debug than a clean fail.
	if _, err := pg.Exec(`UPDATE notification_events SET fanned_out = true WHERE id <= $1 AND NOT fanned_out`, mark); err != nil {
		t.Fatal(err)
	}

	f := &notifyFixture{s: s, pg: pg, request: request, n: newNotifier(s), taskID: taskID, expID: task.ExpID, cleanupMark: mark}
	t.Cleanup(func() {
		if _, err := pg.Exec(`DELETE FROM notification_events WHERE id > $1`, f.cleanupMark); err != nil {
			t.Logf("failed to clean up notification events: %v", err)
		}
	})
	// the master switch must be on (other cases may have turned it off).
	if err := pg.SetBool(settingNotifyEnabled, true); err != nil {
		t.Fatal(err)
	}
	return f
}

// record writes a vuln through the real evidence path and returns the finding id.
// That path registers the push event **in the same transaction** — this feature's hook point.
func (f *notifyFixture) record(t *testing.T, vulnclass, severity string) int64 {
	t.Helper()
	out, err := f.s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID:        f.taskID,
		ExplorationID: f.expID,
		Worker:        "test",
		VulnClass:     vulnclass,
		Name:          vulnclass,
		Severity:      severity,
		Summary:       vulnclass + " summary",
		Evidence:      "poc",
	}, nil)
	if err != nil {
		t.Fatalf("failed to record vuln: %v", err)
	}
	return out.FindingID
}

// channel reads back the channel config (for per-channel stepX calls).
func (f *notifyFixture) channel(t *testing.T, id int64) *db.NotificationChannel {
	t.Helper()
	ch, err := f.pg.NotificationChannelByID(context.Background(), id)
	if err != nil {
		t.Fatalf("failed to read channel: %v", err)
	}
	return ch
}

// deliver fans out events and runs one delivery round for the given channel only.
func (f *notifyFixture) deliver(t *testing.T, chID int64, baseURL string) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatalf("fan-out failed: %v", err)
	}
	f.n.stepRealtime(ctx, f.channel(t, chID), 50, baseURL)
}

// createChannel builds a channel via the HTTP API, also covering the API's own validation path.
func (f *notifyFixture) createChannel(t *testing.T, payload map[string]any) int64 {
	t.Helper()
	raw, _ := json.Marshal(payload)
	r := f.request("POST", "/api/notify/channels", string(raw))
	if r.Code != 200 {
		t.Fatalf("channel create failed %d: %s", r.Code, r.Body)
	}
	var res struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &res); err != nil || res.ID == 0 {
		t.Fatalf("channel create returned abnormally: %s (%v)", r.Body, err)
	}
	t.Cleanup(func() { f.pg.Exec(`DELETE FROM notification_channels WHERE id=$1`, res.ID) })
	return res.ID
}

// fakeWebhook is a fake receiver that records the request bodies it gets.
type fakeWebhook struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []map[string]any
}

func newFakeWebhook(t *testing.T) *fakeWebhook {
	t.Helper()
	f := &fakeWebhook{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeWebhook) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeWebhook) body(t *testing.T, i int) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.bodies) {
		t.Fatalf("fake receiver only got %d requests, can't take #%d", len(f.bodies), i)
	}
	return f.bodies[i]
}

func (f *fakeWebhook) last(t *testing.T) map[string]any {
	t.Helper()
	if f.count() == 0 {
		t.Fatal("fake receiver got no requests")
	}
	return f.body(t, f.count()-1)
}

// markdownText extracts the body from a request, tolerating each vendor's field name:
// DingTalk markdown uses `text`, ActionCard uses `text`, WeCom markdown uses `content`.
func markdownText(t *testing.T, body map[string]any) string {
	t.Helper()
	for _, key := range []string{"markdown", "actionCard"} {
		section, ok := body[key].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"text", "content"} {
			if s, ok := section[field].(string); ok && s != "" {
				return s
			}
		}
	}
	t.Fatalf("no recognizable body in the request: %v", body)
	return ""
}

// agePendingBatch ages this channel's pending deliveries, to test digest-batch expiry.
func (f *notifyFixture) agePendingBatch(t *testing.T, chID int64) {
	t.Helper()
	if _, err := f.pg.Exec(`UPDATE notification_deliveries SET created_at = now() - interval '2 hours'
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyEndToEndRealtimeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "realtime push",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	f.record(t, "SQL injection", "high")
	f.deliver(t, chID, "")

	if hook.count() != 1 {
		t.Fatalf("expected 1 message sent, got %d", hook.count())
	}
	text := markdownText(t, hook.last(t))
	for _, want := range []string{"SQL injection", "High", "summary"} {
		if !strings.Contains(text, want) {
			t.Fatalf("message body missing %q:\n%s", want, text)
		}
	}
	// the delivery should transition to sent.
	var pending int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state <> $2`,
		chID, db.NotifyStateSent).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("%d deliveries still not marked sent after delivery", pending)
	}
}

func TestNotifyChannelAPIMasksSecretsAndPreservesOnUpdate(t *testing.T) {
	f := newNotifyFixture(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "masking case",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "https://oapi.dingtalk.com/robot/send?access_token=abc123456", "secret": "SECabcdef123456"},
	})

	r := f.request("GET", "/api/notify/channels", "")
	if r.Code != 200 {
		t.Fatalf("channel list failed %d: %s", r.Code, r.Body)
	}
	if strings.Contains(r.Body.String(), "abc123456") || strings.Contains(r.Body.String(), "SECabcdef123456") {
		t.Fatalf("API echo leaks credentials: %s", r.Body)
	}
	var listed struct {
		Channels []struct {
			ID         int64          `json:"id"`
			Config     map[string]any `json:"config"`
			SecretKeys []string       `json:"secret_keys"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	var mine *struct {
		ID         int64          `json:"id"`
		Config     map[string]any `json:"config"`
		SecretKeys []string       `json:"secret_keys"`
	}
	for i := range listed.Channels {
		if listed.Channels[i].ID == chID {
			mine = &listed.Channels[i]
		}
	}
	if mine == nil {
		t.Fatal("newly created channel missing from the list")
	}
	if !notify.IsMasked(fmt.Sprint(mine.Config["webhook"])) || !notify.IsMasked(fmt.Sprint(mine.Config["secret"])) {
		t.Fatalf("credential fields should be mask values: %v", mine.Config)
	}
	if len(mine.SecretKeys) == 0 {
		t.Fatal("API should tell the frontend which fields are credentials")
	}

	// PATCH rename-only + echoed mask credentials: the real credentials must survive.
	body, _ := json.Marshal(map[string]any{
		"name":   "renamed",
		"config": map[string]any{"webhook": fmt.Sprint(mine.Config["webhook"]), "secret": fmt.Sprint(mine.Config["secret"])},
	})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("update failed %d: %s", r.Code, r.Body)
	}
	cfg := f.channelConfig(t, chID)
	if cfg["webhook"] != "https://oapi.dingtalk.com/robot/send?access_token=abc123456" {
		t.Fatalf("mask echo overwrote the real credential: %v", cfg["webhook"])
	}
	if cfg["secret"] != "SECabcdef123456" {
		t.Fatalf("mask echo overwrote secret: %v", cfg["secret"])
	}
	if f.channel(t, chID).Name != "renamed" {
		t.Fatal("name was not updated")
	}

	// explicitly clearing secret must take effect (distinct from 'mask echo = unchanged').
	body, _ = json.Marshal(map[string]any{"config": map[string]any{"secret": ""}})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("clearing secret failed %d: %s", r.Code, r.Body)
	}
	if _, still := f.channelConfig(t, chID)["secret"]; still {
		t.Fatal("empty string should clear secret")
	}
}

func (f *notifyFixture) channelConfig(t *testing.T, id int64) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(f.channel(t, id).Config, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestNotifyChannelAPICreateValidation(t *testing.T) {
	f := newNotifyFixture(t)
	cases := []struct {
		name    string
		payload map[string]any
		wantSub string
	}{
		{"bad kind", map[string]any{"name": "x", "kind": "nope", "config": map[string]any{}}, "invalid channel kind"},
		{"missing name", map[string]any{"kind": notify.KindDingTalk, "config": map[string]any{"webhook": "https://e.com/h"}}, "channel name is required"},
		{"missing webhook", map[string]any{"name": "x", "kind": notify.KindDingTalk, "config": map[string]any{}}, "webhook"},
		{"bad webhook scheme", map[string]any{"name": "x", "kind": notify.KindDingTalk, "config": map[string]any{"webhook": "file:///etc/passwd"}}, "invalid webhook URL"},
		{"bad mode", map[string]any{"name": "x", "kind": notify.KindDingTalk, "mode": "sometimes", "config": map[string]any{"webhook": "https://e.com/h"}}, "invalid push mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.payload)
			r := f.request("POST", "/api/notify/channels", string(raw))
			if r.Code != 400 {
				t.Fatalf("expected 400, got %d: %s", r.Code, r.Body)
			}
			if !strings.Contains(r.Body.String(), tc.wantSub) {
				t.Fatalf("error should mention %q, got %s", tc.wantSub, r.Body)
			}
		})
	}
	if r := f.request("DELETE", "/api/notify/channels/99999999", ""); r.Code != 404 {
		t.Fatalf("deleting a nonexistent channel should 404, got %d", r.Code)
	}
}

func TestNotifyFilterBlocksBelowThreshold(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "critical only",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
		"filter": map[string]any{"min_severity": "critical"},
	})
	f.record(t, "low-severity issue", "low")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("below-threshold vuln must not produce deliveries, got %d", n)
	}
	f.n.stepRealtime(context.Background(), f.channel(t, chID), 50, "")
	if hook.count() != 0 {
		t.Fatal("filtered vuln must not send a message")
	}
}

func TestNotifyDigestBatchesMultipleFindingsIntoOneMessage(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "digest push",
		"kind":   notify.KindDingTalk,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"webhook": hook.URL},
	})
	for i := 0; i < 3; i++ {
		f.record(t, fmt.Sprintf("digest vuln %d", i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)

	// not due: don't send.
	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 0 {
		t.Fatal("digest batch sent before it was due")
	}

	// after aging the batch: three items merge into one message.
	f.agePendingBatch(t, chID)
	f.n.stepDigest(ctx, ch, 50, "")
	if got := hook.count(); got != 1 {
		t.Fatalf("three items should merge into one message, actually sent %d", got)
	}
	text := markdownText(t, hook.last(t))
	if !strings.Contains(text, "last") || !strings.Contains(text, "3 new vulns") {
		t.Fatalf("digest message missing count/time-window wording:\n%s", text)
	}
	for i := 1; i <= 3; i++ {
		if !strings.Contains(text, fmt.Sprintf("digest vuln %d", i)) {
			t.Fatalf("digest message missing item %d:\n%s", i, text)
		}
	}
	// the same batch should share a batch_id.
	var distinct, total int
	if err := f.pg.QueryRow(`SELECT count(DISTINCT batch_id), count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&distinct, &total); err != nil {
		t.Fatal(err)
	}
	if total != 3 || distinct != 1 {
		t.Fatalf("three deliveries should share one batch_id, got distinct=%d total=%d", distinct, total)
	}
}

func TestNotifyDisabledChannelDoesNotSend(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":    "disabled channel",
		"kind":    notify.KindDingTalk,
		"enabled": false,
		"config":  map[string]any{"webhook": hook.URL},
	})
	f.record(t, "vuln during disabled period", "critical")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("disabled channel must not produce deliveries, got %d", n)
	}
}

func TestNotifyStatusChangeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "status-change subscription",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
		"filter": map[string]any{"on_status_change": true},
	})
	finding := f.record(t, "status-change case", "high")
	r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"fixed"}`)
	if r.Code != 200 {
		t.Fatalf("status change failed %d: %s", r.Code, r.Body)
	}
	f.deliver(t, chID, "")

	// two deliveries expected: the fixed one is the status change; the finding_created one
	// may go out in the same round. The status change is actually created later, but we
	// don't rely on order — search everything.
	found := false
	for i := 0; i < hook.count(); i++ {
		text := markdownText(t, hook.body(t, i))
		if strings.Contains(text, "Status change") && strings.Contains(text, "Fixed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no 'Status change → Fixed' message received (%d total)", hook.count())
	}
}

func TestNotifyStatusChangeSuppressedByDefault(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "no status-change subscription",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	finding := f.record(t, "unsubscribed change", "high")
	if r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"false_positive"}`); r.Code != 200 {
		t.Fatalf("status change failed %d: %s", r.Code, r.Body)
	}
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id
WHERE d.channel_id=$1 AND e.kind=$2`, chID, notify.EventFindingStatusChanged).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a channel not subscribed to status changes must not get them, got %d", n)
	}
}

func TestNotifyTestMessageEndpoint(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "test send",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", chID), ""); r.Code != 200 {
		t.Fatalf("test send failed %d: %s", r.Code, r.Body)
	}
	if hook.count() != 1 {
		t.Fatalf("fake receiver should get 1 test message, got %d", hook.count())
	}
	// the test message must be unmistakably a test — not mistakable for a real vuln.
	if text := markdownText(t, hook.last(t)); !strings.Contains(text, "Test") {
		t.Fatalf("test message should say it is a test: %s", text)
	}
	// with a broken config the channel's raw error should be relayed to the user verbatim.
	badID := f.createChannel(t, map[string]any{
		"name":   "bad address",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "http://127.0.0.1:1/hook"},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", badID), ""); r.Code != 502 {
		t.Fatalf("failed delivery should return 502, got %d: %s", r.Code, r.Body)
	}
}

func TestNotifyDeliveriesHistoryAndRetry(t *testing.T) {
	f := newNotifyFixture(t)
	// point at a doomed address to produce failed deliveries.
	chID := f.createChannel(t, map[string]any{
		"name":   "retry on failure",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "http://127.0.0.1:1/hook"},
	})
	f.record(t, "doomed push", "high")
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)
	// deliver repeatedly until the retry budget is exhausted.
	for i := 0; i < db.MaxNotifyAttempts; i++ {
		f.n.stepRealtime(ctx, ch, 50, "")
		if _, err := f.pg.Exec(`UPDATE notification_deliveries SET next_attempt_at = now() - interval '1 minute' WHERE channel_id=$1`, chID); err != nil {
			t.Fatal(err)
		}
	}
	var state string
	if err := f.pg.QueryRow(`SELECT state FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStateFailed {
		t.Fatalf("state should be failed after retries are exhausted, got %s", state)
	}

	r := f.request("GET", fmt.Sprintf("/api/notify/deliveries?channel_id=%d&state=failed", chID), "")
	if r.Code != 200 {
		t.Fatalf("history query failed %d: %s", r.Code, r.Body)
	}
	var hist struct {
		Deliveries []struct {
			ID        int64  `json:"id"`
			State     string `json:"state"`
			LastError string `json:"last_error"`
			Attempts  int    `json:"attempts"`
			Title     string `json:"title"`
		} `json:"deliveries"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Total != 1 || len(hist.Deliveries) != 1 {
		t.Fatalf("expected 1 failed delivery, got total=%d len=%d", hist.Total, len(hist.Deliveries))
	}
	if hist.Deliveries[0].LastError == "" {
		t.Fatal("history must carry the failure reason or users can't diagnose")
	}
	if hist.Deliveries[0].Attempts < db.MaxNotifyAttempts {
		t.Fatalf("attempt count should be recorded, got %d", hist.Deliveries[0].Attempts)
	}
	if hist.Deliveries[0].Title != "doomed push" {
		t.Fatalf("history should carry the vuln title, got %q", hist.Deliveries[0].Title)
	}

	// manual resend: should return to pending with counters cleared.
	if r := f.request("POST", fmt.Sprintf("/api/notify/deliveries/%d/retry", hist.Deliveries[0].ID), ""); r.Code != 200 {
		t.Fatalf("resend failed %d: %s", r.Code, r.Body)
	}
	var attempts int
	if err := f.pg.QueryRow(`SELECT state, attempts FROM notification_deliveries WHERE id=$1`, hist.Deliveries[0].ID).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStatePending || attempts != 0 {
		t.Fatalf("after resend should be pending with attempts=0, got %s/%d", state, attempts)
	}
}

func TestNotifyMetaAndSettingsRoundTrip(t *testing.T) {
	f := newNotifyFixture(t)
	r := f.request("GET", "/api/notify/meta", "")
	if r.Code != 200 {
		t.Fatalf("meta failed: %s", r.Body)
	}
	var meta struct {
		Kinds []struct {
			Kind       string   `json:"kind"`
			SecretKeys []string `json:"secret_keys"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Kinds) != len(notify.Kinds()) {
		t.Fatalf("meta should list all %d channel kinds, got %d", len(notify.Kinds()), len(meta.Kinds))
	}
	for _, k := range meta.Kinds {
		if len(k.SecretKeys) == 0 {
			t.Errorf("channel %s doesn't report credential fields", k.Kind)
		}
	}

	// round-trip the three global settings. A trailing slash must be normalized away —
	// else deep links end up "//function/...".
	if r := f.request("PUT", "/api/settings", `{"notify_public_base_url":"https://pojun.example.com/","notify_digest_interval_min":15,"notify_enabled":true}`); r.Code != 200 {
		t.Fatalf("settings write failed %d: %s", r.Code, r.Body)
	}
	t.Cleanup(func() {
		f.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, settingNotifyPublicBaseURL, settingNotifyDigestMinutes)
	})
	payload := f.s.settingsPayload()
	if payload["notify_public_base_url"] != "https://pojun.example.com" {
		t.Fatalf("base URL not normalized: %v", payload["notify_public_base_url"])
	}
	if payload["notify_digest_interval_min"] != 15 {
		t.Fatalf("digest interval didn't take effect: %v", payload["notify_digest_interval_min"])
	}

	// invalid values must be rejected.
	for _, body := range []string{
		`{"notify_public_base_url":"ftp://x"}`,
		`{"notify_digest_interval_min":0}`,
		`{"notify_digest_interval_min":99999}`,
	} {
		if r := f.request("PUT", "/api/settings", body); r.Code != 400 {
			t.Errorf("%s should return 400, got %d", body, r.Code)
		}
	}
}

// TestNotifyDeepLinkUsesPublicBaseURL covers deep-link assembly: with public_base_url
// configured, a single-item message must use the buttoned ActionCard linking to the vuln
// detail page.
func TestNotifyDeepLinkUsesPublicBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "deep link",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	finding := f.record(t, "vuln with deep link", "high")
	f.deliver(t, chID, "https://pojun.example.com")

	body := hook.last(t)
	card, _ := body["actionCard"].(map[string]any)
	if card == nil {
		t.Fatalf("with a deep link the msgtype should be ActionCard, got %v", body["msgtype"])
	}
	want := fmt.Sprintf("https://pojun.example.com/function/findings/detail?id=%d", finding)
	if card["singleURL"] != want {
		t.Fatalf("wrong deep link\nwant %s\ngot  %v", want, card["singleURL"])
	}
}

// TestNotifyNoDeepLinkWithoutBaseURL is the counter case: with no external address
// configured, no broken link (localhost, relative path) should be produced — fall back to
// plain markdown.
func TestNotifyNoDeepLinkWithoutBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "no deep link",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	f.record(t, "vuln without deep link", "high")
	f.deliver(t, chID, "")

	body := hook.last(t)
	if body["msgtype"] != "markdown" {
		t.Fatalf("with no external address the msgtype should be markdown, got %v", body["msgtype"])
	}
	if text := markdownText(t, body); strings.Contains(text, "View details") {
		t.Fatalf("a detail link must not appear with no external address configured:\n%s", text)
	}
}

// TestNotifyDigestSegmentsAndDefersRemainder is the end-to-end evidence for the
// 'silent loss' fix.
//
// Digest messages are bounded by the channel length cap (WeCom 4096 bytes). When a batch
// doesn't fit it must split at **whole-item** boundaries: the items that made it get marked
// delivered, the rest return to the queue for the next message. The old implementation
// marked the whole batch sent — the truncated items were neither in the message nor in the
// failure list, while history still showed success: the vulns simply vanished.
//
// Four assertions: (1) only the items that actually fit get marked, (2) the rest stay
// pending, (3) deferred items **don't consume retry attempts**, (4) another round sends
// the remainder (no deadlock).
func TestNotifyDigestSegmentsAndDefersRemainder(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	// use WeCom: the 4096-byte markdown cap is the tightest of the six channels.
	chID := f.createChannel(t, map[string]any{
		"name":   "segmented digest",
		"kind":   notify.KindWeCom,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"webhook": hook.URL},
	})
	const total = 60
	// give titles length so 60 items far exceed 4096 bytes and must segment.
	longName := strings.Repeat("overlong vulnerability name", 6) // CJK fixture: 3 bytes/char overflows the byte cap fast
	for i := 0; i < total; i++ {
		f.record(t, longName+strconv.Itoa(i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	f.agePendingBatch(t, chID)
	ch := f.channel(t, chID)

	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 1 {
		t.Fatalf("exactly one message should go out, got %d", hook.count())
	}

	var sent, pending int
	if err := f.pg.QueryRow(`SELECT
    count(*) FILTER (WHERE state=$2),
    count(*) FILTER (WHERE state=$3)
  FROM notification_deliveries WHERE channel_id=$1`, chID, db.NotifyStateSent, db.NotifyStatePending).
		Scan(&sent, &pending); err != nil {
		t.Fatal(err)
	}
	if sent == 0 {
		t.Fatal("some items should be marked delivered")
	}
	if pending == 0 {
		t.Fatalf("a batch of %d can't fit in 4096 bytes — there must be pending leftovers; sent=%d", total, sent)
	}
	if sent+pending != total {
		t.Fatalf("item counts don't add up: sent=%d pending=%d total=%d (neither delivered nor pending = lost)", sent, pending, total)
	}
	// the body must state honestly how many items are not included here.
	if text := markdownText(t, hook.last(t)); !strings.Contains(text, "remaining") {
		t.Fatalf("message should state that more items are not included:\n%.400s", text)
	}

	// deferred items must not consume retry budget: claim already optimistically +1'd
	// attempts, so deferral must decrement it back.
	var maxAttempts int
	if err := f.pg.QueryRow(`SELECT COALESCE(max(attempts),0) FROM notification_deliveries
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending).Scan(&maxAttempts); err != nil {
		t.Fatal(err)
	}
	if maxAttempts > 0 {
		t.Fatalf("deferred items must not consume retries (else they'd fail after a few), got attempts=%d", maxAttempts)
	}

	// repeat until convergence. Asserts **everything eventually delivered** and that it
	// really took multiple rounds — stronger than 'done by round two': proves segmentation
	// neither deadlocks nor drops the remainder.
	rounds := 0
	for {
		var undelivered int
		if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries
WHERE channel_id=$1 AND state <> $2 AND state <> $3`, chID, db.NotifyStateSent, db.NotifyStateFailed).
			Scan(&undelivered); err != nil {
			t.Fatal(err)
		}
		if undelivered == 0 {
			break
		}
		rounds++
		if rounds > total+5 {
			t.Fatalf("segmented delivery doesn't converge: after %d rounds %d still undelivered", rounds, undelivered)
		}
		before := hook.count()
		f.n.stepDigest(ctx, ch, 50, "")
		if hook.count() == before {
			t.Fatalf("round %d made no progress — the remaining %d would be stuck forever", rounds, undelivered)
		}
	}
	if rounds < 2 {
		t.Fatalf("one 4096-byte message can't hold %d long-titled vulns — it should take multiple rounds, but only %d ran", total, rounds)
	}
	// every round after the first should be **pure continuation** — no item rejected by the channel.
	var failed int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state=$2`,
		chID, db.NotifyStateFailed).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Fatalf("the fake receiver always succeeds — there should be no failures, got %d", failed)
	}
}

// TestNotifyBackoffTableMatchesAttemptBudget is a drift guard.
//
// The retry budget (db.MaxNotifyAttempts) and the backoff schedule (notifyBackoff) live in
// different packages: the former is the state machine's policy, the latter the engine's
// pacing. Change only one — e.g. raise the budget to 5 and forget a backoff step — and
// nothing errors; retries 4 and 5 just reuse the last interval, surfacing as 'retries got
// mysteriously slower', hard to trace back here.
// Assert the two lengths match so the drift shows up in CI.
func TestNotifyBackoffTableMatchesAttemptBudget(t *testing.T) {
	if len(notifyBackoff) != db.MaxNotifyAttempts {
		t.Fatalf("backoff steps (%d) don't match max attempts (%d) — changing one requires changing the other",
			len(notifyBackoff), db.MaxNotifyAttempts)
	}
	// backoff intervals must be non-decreasing, else retries speed up and worsen rate limiting.
	for i := 1; i < len(notifyBackoff); i++ {
		if notifyBackoff[i] < notifyBackoff[i-1] {
			t.Fatalf("backoff intervals must be non-decreasing: step %d %v < step %d %v",
				i, notifyBackoff[i], i-1, notifyBackoff[i-1])
		}
	}
}

// TestNotifyRateLimitDoesNotConsumeRetryBudget pins the 'take token, then claim' order.
// Reversed (claim then drop), a rate-limited delivery has already spent an attempts count —
// pure waiting would exhaust the budget and land in failed.
func TestNotifyRateLimitDoesNotConsumeRetryBudget(t *testing.T) {
	// tests the token bucket itself — no Server needed (and shouldn't build one).
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// 1 per minute: a full bucket yields at most 1.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now); got != 1 {
		t.Fatalf("full bucket at 1/min should yield 1 token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("an exhausted bucket should return 0, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(30*time.Second)); got != 0 {
		t.Fatalf("half a period must not refill a token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Minute)); got != 1 {
		t.Fatalf("a full period should refill 1 token, got %d", got)
	}
	// unlimited channels get a finite cap so one round can't be dragged by infinite backlog.
	if got := n.takeTokens(2, 0, notifyUnlimitedBurstPerTick+10, now); got != notifyUnlimitedBurstPerTick {
		t.Fatalf("unlimited should return the per-round cap %d, got %d", notifyUnlimitedBurstPerTick, got)
	}
	// token buckets are independent across channels.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("channel 1's bucket should still be empty, got %d", got)
	}
}

// TestNotifyTakeTokensKeepsUnusedTokens pins the 'take exactly want' semantics.
//
// The old implementation drained the whole bucket and let the caller truncate: a
// rate=100/min channel filled its bucket, used 5 in a round, and the other 95 tokens were
// discarded; a channel with no pending deliveries was charged the same. The comment's
// claimed 'burst rate_per_min items when backlogged' was unreachable in every case.
func TestNotifyTakeTokensKeepsUnusedTokens(t *testing.T) {
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// bucket starts full (100); this round wants 5.
	if got := n.takeTokens(1, 100, 5, now); got != 5 {
		t.Fatalf("want=5 should take exactly 5 tokens, got %d", got)
	}
	// key assertion: the other 95 must still be in the bucket, not drained away.
	// time isn't advanced, so anything taken can only come from stock, not refill.
	if got := n.takeTokens(1, 100, 95, now); got != 95 {
		t.Fatalf("remaining tokens should still be usable (expect 95), got %d — the bucket was fully drained", got)
	}
	if got := n.takeTokens(1, 100, 1, now); got != 0 {
		t.Fatalf("bucket drained — should return 0, got %d", got)
	}
	// want<=0 must not charge any tokens (an empty round is free).
	n2 := &Notifier{buckets: map[int64]*notifyBucket{}}
	if got := n2.takeTokens(1, 20, 0, now); got != 0 {
		t.Fatalf("want=0 should return 0, got %d", got)
	}
	if got := n2.takeTokens(1, 20, 20, now); got != 20 {
		t.Fatalf("the want=0 call must not consume tokens — 20 should still be available, got %d", got)
	}
}

// TestDigestTickPlanDecouplesBatchSizeFromSendBudget pins the digest mode's two units.
//
// Once digest batch size is coupled to the per-tick request budget, a rate_per_min=20
// channel refills only 1 token per 3s tick, so each digest message packs just 1 vuln —
// functionally no digest at all, while the head still says '1 new vuln in the last 30
// minutes'. The regression doesn't error and the end-to-end cases can't see it (they pass
// stepDigest a large limit manually, bypassing the budget math in step), so the decision
// itself is asserted here.
func TestDigestTickPlanDecouplesBatchSizeFromSendBudget(t *testing.T) {
	tokens, claimLimit := digestTickPlan()
	// one batch = one message = one request = one token. Tokens are denominated in messages, not vulns.
	if tokens != 1 {
		t.Fatalf("one digest batch sends one message — should cost exactly 1 token, got %d", tokens)
	}
	if claimLimit != db.MaxDigestBatchSize {
		t.Fatalf("digest batch size should be the memory bound db.MaxDigestBatchSize=%d, got %d",
			db.MaxDigestBatchSize, claimLimit)
	}
	// key relationship: batch size must far exceed the per-tick request budget. Same order
	// of magnitude means 'messages per round' and 'vulns per batch' got fused again.
	if claimLimit <= notifyMaxSendsPerChannelPerTick {
		t.Fatalf("digest batch size %d must not be bounded by per-tick request budget %d — "+
			"the budget is the lease-derived 'requests per round', a different unit from 'vulns per batch'",
			claimLimit, notifyMaxSendsPerChannelPerTick)
	}
}

// TestNotifyTickBudgetFitsWithinLease is another drift guard.
//
// The per-channel per-tick send cap (notifyMaxSendsPerChannelPerTick) is derived backwards
// from the lease duration: one round's worst-case serial delivery must fit under the
// lease, else the tail items' lease expires mid-send and a multi-instance peer re-claims
// and re-sends them. The three constants sit in different places — changing any can break
// the relation without any error — so it's pinned here.
func TestNotifyTickBudgetFitsWithinLease(t *testing.T) {
	worst := time.Duration(notifyMaxSendsPerChannelPerTick) * notifySendTimeout
	if worst >= notifyLease {
		t.Fatalf("one channel's worst-case round %v must not reach or exceed the lease %v"+
			"(notifyMaxSendsPerChannelPerTick=%d \u00d7 notifySendTimeout=%v)\u2014\u2014"+
			"changing any of the three constants requires re-checking the other two",
			worst, notifyLease, notifyMaxSendsPerChannelPerTick, notifySendTimeout)
	}
}
