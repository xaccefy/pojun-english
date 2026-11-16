package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/notify"
)

// Global setting keys (kept in the settings KV table — no new table needed).
const (
	// settingNotifyEnabled is the push master switch. Defaults on: it's a one-click
	// kill switch for maintenance, not the feature gate — the real gate is 'is a channel
	// configured'.
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL is the externally reachable address used to build
	// vuln-detail deep links (e.g. https://pojun.example.com). Empty = messages carry no
	// link button. No reusable external-address config existed, so this key is new.
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes is the digest-mode interval (minutes).
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick is the delivery engine's poll interval. 3s is its latency ceiling and the
	// main delay between 'vuln inserted' and 'message reaches IM'.
	notifyTick = 3 * time.Second
	// notifyLease is the claim lease duration. It must far exceed one delivery's worst
	// time (the notify package HTTP client times out at 15s), or two dispatchers could
	// deliver the same row at once.
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick caps events fanned out per round, so enabling a channel for the
	// first time doesn't expand the whole history backlog into deliveries at once.
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes is the default digest interval.
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick is the per-round delivery cap for channels without a
	// rate limit. It exists so 'unlimited channel + a scan producing thousands of vulns'
	// can't drag one round into a long block.
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick is the per-channel per-round delivery cap.
	//
	// The cap is derived backwards from the **lease duration**: claims stamp rows with a
	// lease (notifyLease = 3 min); if one round serially delivers so many rows that the
	// worst-case time exceeds the lease, the tail items' leases expire mid-send. Within
	// one process that doesn't matter (Run is a single goroutine, ticks never re-enter),
	// but with **two processes on one DB** the peer re-claims lease-expired rows, double
	// -sends them, double-increments attempts, and can mark them failed while the original
	// is still delivering.
	//
	// Value: 3min lease / 30s per-send timeout = 6 is **exactly lease-full**, zero margin —
	// not allowed; 5 leaves a 30s margin on the 150s worst case. The relation is pinned by
	// TestNotifyTickBudgetFitsWithinLease — touching notifyLease, notifySendTimeout, or
	// this value fails that assertion.
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout is one delivery's timeout. It also sets the previous constant's
	// value: the product must stay under notifyLease — see
	// TestNotifyTickBudgetFitsWithinLease.
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff is the failure-retry backoff schedule, indexed by attempts spent.
// 3 chances (incl. the first) correspond to db.MaxNotifyAttempts — change both together.
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// Notifier is the vuln-push delivery engine.
//
// It runs alongside Scheduler as its own goroutine (see server.New). Deliberately not
// reusing Scheduler's tick: push's latency requirement (3s) differs from the trigger's
// business cadence, and their failures stay independent — a stuck push must not stall
// agent triggers.
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu guards buckets. Few channels, low contention — one mutex suffices; finer
	// granularity isn't worth it.
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket is one channel's token bucket.
//
// A token bucket instead of a 'count per minute, reset' sliding window, because the
// window's edge effects are bad: 20 sent at a window's end + 20 right after is 40 in one
// second to the platform — rate-limited. A constant-rate refill avoids that burst shape.
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run loops until ctx ends. Started once by server.New.
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step runs one round: fan out new events, then deliver due tasks.
//
// Any failure is only logged, never breaks the loop — a notification failure must never
// escalate into a process-level problem. Every tick is independent; the next retries
// naturally.
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] event fan-out failed: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] channel read failed: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// the token bucket is denominated in **messages** (equivalently HTTP requests), not
		// vulns. Realtime makes them equal (one vuln, one message); digest packs a whole
		// batch into one message, costing a single token.
		//
		// both modes ask the bucket first, then claim within that allowance — the order
		// can't flip, or rate-limited deliveries would already have spent retries.
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan returns a digest channel's token cost and batch-size bound for this
// round.
//
// The two return values are **two different units** — the reason it's its own function:
//
//   - tokens is a message count. A batch merges into one message and one HTTP request, so
//     it's always 1. rate_per_min therefore still applies to digest (at most that many
//     digest messages per minute).
//   - claimLimit is the max vulns in this batch. Bounded only by the memory cap, unrelated
//     to the request budget.
//
// To make rate_per_min apply to digest, the per-tick request budget
// (notifyMaxSendsPerChannelPerTick, derived from the lease) was once passed down as the
// batch size. Result: a rate_per_min=20 channel refills 1 token per 3s tick, so every
// digest message packed 1 vuln — digest degraded into 'realtime push with digest wording',
// readers got a stream of '1 new vuln in the last 30 minutes', and db.MaxDigestBatchSize
// was unreachable.
//
// The symptom is hard to spot end to end (existing cases pass stepDigest a large limit
// manually, bypassing step's budget math), so the decision lives here, pinned by
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget.
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime claims and delivers one channel's realtime tasks — one vuln per message.
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] realtime claim failed channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("channel kind %q is not registered", ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// a render failure is a local data problem — retries won't heal it.
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest aggregates a channel's pending deliveries into one message when the batch is due.
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] digest-batch check failed channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] digest claim failed channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("channel kind %q is not registered", ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// deliveries whose snapshot broke and never made the message must be failed
	// explicitly. Otherwise they sit outside 'included' — neither in the message nor the
	// failure list; on send success the bulk marking skips them, and they stay in sending
	// until the lease expires and they're re-claimed forever.
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := "event snapshot unparseable; this vuln can't be rendered into a message"
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] marking bad-snapshot deliveries failed channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] skipped %d unparseable-snapshot deliveries channel=%d", len(skipped), ch.ID)
	}
	// only the deliveries that made the message go to send: included[i] corresponds
	// strictly to msg.Items[i] — send relies on that to map 'the channel reported the
	// first K fit' onto the right delivery rows.
	n.send(ctx, channel, cfg, msg, included)
}

// send delivers and transitions state by the result.
//
// A batch of deliveries (possibly dozens in digest mode) shares one send result: either
// all delivered or all retried. No per-item retry — a digest is one message; resending a
// slice of it would scramble batch semantics.
//
// The only exception is **channel-length-cap segmentation**: if the channel reports only
// the first K items fit, item K+1 onward must stay for the next batch instead of being
// marked sent — otherwise the truncated vulns sit neither in the message nor the failure
// list: gone entirely.
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// cap each send so one stuck channel can't stall the rest of this round.
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// the channel can't report more items than there were deliveries; if it does
			// the render layer miscounted — treat as all-delivered and log it, better than
			// corrupting the records.
			log.Printf("[notify] channel reported %d delivered > %d deliveries channel=%s — treating as all delivered",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] marking delivered failed channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// this message hit the channel length cap: the rest re-queue immediately for
			// the next tick's continuation. DeferDeliveries, not RescheduleDeliveries —
			// this isn't a failure and mustn't spend retry budget (claim already
			// optimistically +1'd; Defer decrements it back).
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf("message hit the channel length cap; only the first %d delivered, the rest wait for the next batch", delivered)); err != nil {
				log.Printf("[notify] queueing segmented continuation failed channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// the channel neither errored nor reported a delivered count. Treat as failure
		// (with backoff), else the delivery gets re-claimed forever yet never marked.
		err = fmt.Errorf("channel reported no delivered count (delivered=%d)", delivered)
	}

	// failure handling is decided **per delivery**, not by the batch's max attempt count.
	//
	// It used to be `if maxAttempts(deliveries) >= MaxNotifyAttempts` — the whole batch
	// condemned — but items' attempt counts differ: an old delivery retried twice
	// (attempts=2) would drag a brand-new one (attempts=1) into failed with it, and the new
	// vuln got permanently lost without spending a single retry — the exact opposite of
	// 'don't let old rows sink new rows'.
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] marking failed state errored channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf("still failing after %d attempts: %s", db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] marking failed state errored channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// regroup reschedules by delay: only 3 backoff steps, so groups are few — no per-row
	// UPDATE (a 500-item batch would mean 500 round trips).
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] rescheduling deliveries failed channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] delivery failed channel=%d kind=%s permanent=%d exhausted=%d retrying=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries returns the items in `all` not in `keep` (pointer-identity compare).
// Finds deliveries that 'didn't make the message' — they must be handled explicitly, not
// left in limbo.
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt resolves the channel implementation and parses its config.
// ok=false means the kind is unregistered — fail the delivery outright rather than retry
// forever.
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// on config-parse failure pass an empty map: the channel's own Validate reports
		// 'which field is missing' — more actionable for the user than a JSON parse error.
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle renders a single-vuln message.
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch renders a digest message. Snapshots are parsed one by one — a bad item is
// skipped alone, never sinking the whole batch.
//
// The returned included corresponds **strictly 1:1** with msg.Items (delivery i ↔ item i).
// That correspondence is a hard requirement: the caller marks the first K deliveries sent
// based on 'the channel reported the first K fit'. If a bad snapshot were skipped without
// removing its delivery from included, the indices would shift — the bad item gets marked
// delivered while a good one looks undelivered. Bad ones are failed explicitly by the
// caller, see stepDigest.
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// a bad snapshot joins neither the message nor 'included' — its handling is the
			// caller's job (explicit failure, not smuggling into 'delivered').
			log.Printf("[notify] skipping unparseable snapshot in digest batch delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf("all %d deliveries in the digest batch are unparseable", len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor renders an event snapshot into a push item, resolving asset names and the
// detail deep link along the way.
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// an asset-name resolution failure must not block the push: a missing name is far
		// cheaper than a missing notification — the message just loses an asset line.
		log.Printf("[notify] asset-name resolution failed finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// the detail-page route is web/src/app/(main)/function/findings/detail/page.tsx,
		// which reads the vuln id from query param id.
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens draws **at most want** tokens from the channel bucket, returning how many
// were actually taken.
//
// One token = one message (one HTTP request). Realtime callers pass the number of items;
// digest sends one message per batch — pass 1.
//
// Bucket capacity is the channel's per-minute cap, refilled at a constant rate.
// ratePerMin<=0 means unlimited: return a finite but ample value so one round can't be
// dragged by infinite backlog.
//
// The want bound is required: without it the only option is draining the whole bucket,
// while the caller has its own per-round cap — surplus tokens go unused and vanish before
// the next refill. Accrued burst capacity stays unreachable, and even 'no pending
// deliveries this round' would still get charged.
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// refill by real elapsed time at ratePerMin/60 per second.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// add a tiny epsilon before truncating: tokens accumulate as floats, and two partial
	// refills can sum to 0.9999999999 — int() would truncate it to 0, a mathematically
	// full bucket yielding nothing. 1e-9 is far below one token; it can't pass a real
	// shortfall.
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled reads the master switch.
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL returns the deep-link external address, trailing slash stripped.
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval returns the digest interval, falling back to the default on invalid or
// unset values.
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot parses the snapshot of the delivery's event.
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf("delivery %d's event snapshot is empty", dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf("parsing delivery %d's event snapshot failed: %w", dl.ID, err)
	}
	if snap.Kind == "" {
		// event kind is authoritative on the event row; the snapshot's copy may have been
		// written by an older version.
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
