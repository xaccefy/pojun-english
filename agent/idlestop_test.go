package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// Fake write-back source: the test advances the write-back counter manually.
type fakeWrites struct {
	mu sync.Mutex
	w  WriteCounts
}

func (f *fakeWrites) get() WriteCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w
}

func (f *fakeWrites) addFacts(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.Facts += n
}

// The startup grace period must be skippable — the test shouldn't really wait 3 minutes.
// Here we just change start so 'elapsed run time' exceeds the grace period.
func ageStopper(s *idleStopper, d time.Duration) {
	s.mu.Lock()
	s.start = time.Now().Add(-d)
	s.mu.Unlock()
}

// Reaching the consecutive no-writeback threshold must request wrap-up.
func TestIdleStopFiresAfterNoWrites(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get)
	ageStopper(s, time.Hour) // past the startup grace period

	// First two rounds: threshold not reached yet.
	for i := 0; i < idleStopRounds-1; i++ {
		if prevent, _ := s.check(); prevent {
			t.Fatalf("wrap-up requested on round %d (threshold %d not reached)", i+1, idleStopRounds)
		}
	}
	prevent, reason := s.check()
	if !prevent {
		t.Fatalf("wrap-up should be requested after %d consecutive no-writeback rounds", idleStopRounds)
	}
	if !strings.Contains(reason, "no writeback") {
		t.Errorf("wrap-up reason should mention no writeback: %q", reason)
	}
}

// A write-back resets the counter — a continuously producing worker must never be wrapped.
// This is the key to the 'depth-first unaffected' design.
func TestIdleStopResetsOnWrite(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get)
	ageStopper(s, time.Hour)

	// Two consecutive no-writeback rounds.
	s.check()
	s.check()
	// Third round has a write-back → counter resets.
	fw.addFacts(1)
	if prevent, _ := s.check(); prevent {
		t.Fatal("wrap-up must not be requested when there's a write-back")
	}
	// Another idleStopRounds consecutive rounds before wrap-up.
	for i := 0; i < idleStopRounds-1; i++ {
		if prevent, _ := s.check(); prevent {
			t.Fatalf("counter should reset after write-back, wrapped on round %d", i+1)
		}
	}
	if prevent, _ := s.check(); !prevent {
		t.Fatal("wrap-up should be requested after another threshold of consecutive no-writebacks")
	}
}

// No wrap-up inside the startup grace period — a worker's first rounds may be prep work.
func TestIdleStopHasGracePeriod(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get)
	// Just started (start = now), grace period not passed.
	for i := 0; i < idleStopRounds+3; i++ {
		if prevent, _ := s.check(); prevent {
			t.Fatalf("must not wrap inside the startup grace period (round %d)", i+1)
		}
	}
}

// The first trigger is 'nudge the model to write back', not direct termination —
// direct termination would drop whatever the model 'probed but hasn't written back yet'.
func TestIdleStopNudgesBeforeStopping(t *testing.T) {
	fw := &fakeWrites{}
	inner := &spyHook{}
	h := wrapIdleStop(inner, fw.get, nil)
	ageStopper(h.stop, time.Hour)

	ctx := context.Background()
	// Run to the threshold round: this call returns blocking (a nudge), not prevent.
	// The threshold is round idleStopRounds, so the first idleStopRounds-1 rounds don't trigger.
	var prevent bool
	var blocking []string
	for i := 0; i < idleStopRounds; i++ {
		prevent, blocking, _ = h.Stop(ctx, nil)
		if i < idleStopRounds-1 && (prevent || len(blocking) > 0) {
			t.Fatalf("round %d must not trigger (threshold %d)", i+1, idleStopRounds)
		}
	}
	if prevent {
		t.Fatal("first trigger should nudge the model to write back — not terminate outright")
	}
	if len(blocking) == 0 {
		t.Fatal("should return a blocking nudge")
	}
	if !strings.Contains(blocking[0], "write back") {
		t.Errorf("nudge should mention writing back: %q", blocking[0])
	}
	// Still no stop after the nudge: give idleStopPreventRounds-idleStopRounds more rounds to write back,
	// and really wrap only at the prevent round (v0.4.62: no more 'terminate right after the nudge', no infinite block either).
	p := false
	var msg string
	for i := 0; i < idleStopPreventRounds-idleStopRounds; i++ {
		p, _, msg = h.Stop(ctx, nil)
	}
	if !p {
		t.Fatalf("at the prevent round (%d) it should really terminate", idleStopPreventRounds)
	}
	if msg == "" {
		t.Error("termination should carry the wrap-up reason")
	}
}

// If the model did write back after the nudge → no more wrap-up (the model is wrapping up normally).
func TestIdleStopStopsNudgingAfterWrite(t *testing.T) {
	fw := &fakeWrites{}
	h := wrapIdleStop(nil, fw.get, nil)
	ageStopper(h.stop, time.Hour)

	ctx := context.Background()
	var prevent bool
	var blocking []string
	for i := 0; i < idleStopRounds; i++ {
		prevent, blocking, _ = h.Stop(ctx, nil)
	}
	if prevent || len(blocking) == 0 {
		t.Fatal("first trigger should be a nudge")
	}
	// The model responds to the nudge and writes back results.
	fw.addFacts(1)
	prevent, _, _ = h.Stop(ctx, nil)
	if prevent {
		t.Fatal("no wrap-up after the model writes back")
	}
}

// When inner (interception control) says stop, it must stop — idle-stop can't override control decisions.
func TestIdleStopRespectsInnerStop(t *testing.T) {
	// spyHook.Stop always returns false (it only counts calls); here we use an inner that
	// really calls stop.
	inner := &blockingHook{prevent: true, msg: "platform control intercept"}
	fw := &fakeWrites{}
	h := wrapIdleStop(inner, fw.get, nil)
	ageStopper(h.stop, time.Hour)

	prevent, _, msg := h.Stop(context.Background(), nil)
	if !prevent {
		t.Fatal("inner's stop decision must pass through")
	}
	if msg != "platform control intercept" {
		t.Errorf("inner's message should pass through: %q", msg)
	}
	if inner.stopCalls != 1 {
		t.Errorf("inner should be called once, got %d", inner.stopCalls)
	}
}

// blockingHook is a hook that returns a preset value (to verify inner stop decisions pass through).
type blockingHook struct {
	prevent   bool
	msg       string
	stopCalls int
}

func (b *blockingHook) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	return false, "", nil
}
func (b *blockingHook) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (b *blockingHook) Stop(context.Context, []llm.Message) (bool, []string, string) {
	b.stopCalls++
	return b.prevent, nil, b.msg
}

// When inner says 'continue', idle-stop's own judgment still applies (two independent layers).
func TestIdleStopAppliesWhenInnerAllows(t *testing.T) {
	inner := &spyHook{}
	fw := &fakeWrites{}
	h := wrapIdleStop(inner, fw.get, nil)
	ageStopper(h.stop, time.Hour)

	ctx := context.Background()
	var prevent bool
	var blocking []string
	for i := 0; i < idleStopRounds; i++ {
		prevent, blocking, _ = h.Stop(ctx, nil)
	}
	if prevent {
		t.Fatal("first trigger should be a nudge")
	}
	if len(blocking) == 0 {
		t.Fatal("should have a blocking nudge")
	}
}

// Tool calls must pass through to inner verbatim — idle-stop is a sidecar, it can't affect interception.
func TestIdleStopForwardsToolHooks(t *testing.T) {
	inner := &spyHook{}
	fw := &fakeWrites{}
	h := wrapIdleStop(inner, fw.get, nil)
	ctx := context.Background()

	h.PreToolUse(ctx, "Bash", []byte(`{"command":"ls"}`))
	h.PostToolUse(ctx, "Bash", []byte(`{}`), []byte("ok"), false)

	if inner.preCalls != 1 || inner.postCalls != 1 {
		t.Fatalf("tool events not passed through: pre=%d post=%d", inner.preCalls, inner.postCalls)
	}
}

// A nil write-back function must not panic (defensive: ToolSet always has one, but don't rely on it).
func TestIdleStopNilWritesSafe(t *testing.T) {
	s := newIdleStopper(nil)
	ageStopper(s, time.Hour)
	for i := 0; i < idleStopRounds; i++ {
		s.check()
	}
	if prevent, _ := s.check(); !prevent {
		t.Fatal("should still judge wrap-up with a nil write-back source")
	}
}

// The wrap-up reason must state 'N consecutive no-writeback rounds' — the planner uses it to tell
// 'cut by wall clock' from 'this direction has nothing left' — opposite decisions.
func TestIdleStopReasonExplainsWhy(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get)
	ageStopper(s, time.Hour)
	for i := 0; i < idleStopRounds; i++ {
		s.check()
	}
	_, reason := s.check()
	for _, want := range []string{"consecutive", "no writeback", "output rate"} {
		if !strings.Contains(reason, want) {
			t.Errorf("wrap-up reason missing %q: %q", want, reason)
		}
	}
}

// idleStopMessage must say three things: why stopping, what to do, what not to do.
// Wording directly shapes model behavior: saying 'terminated, budget exhausted' makes the model feel punished
// and inclined to write unverified guesses as conclusions.
func TestIdleStopMessageContent(t *testing.T) {
	for _, want := range []string{"write back", "insert_assets", "record_fact", "save_evidence", "negative results", "Don't"} {
		if !strings.Contains(idleStopMessage, want) {
			t.Errorf("wrap-up message missing %q: %s", want, idleStopMessage)
		}
	}
}

// The nudge mustn't contain 'budget exhausted'-style wording — that reads as punishment,
// pushing the model to write unverified guesses as conclusions.
func TestIdleStopMessageDoesNotSayBudget(t *testing.T) {
	for _, bad := range []string{"budget exhausted", "terminated", "timed out"} {
		if strings.Contains(idleStopMessage, bad) {
			t.Errorf("wrap-up message must not contain %q: %s", bad, idleStopMessage)
		}
	}
}

// Confirms idleStopHooks satisfies the harness.HookRunner interface.
var _ = func(h *idleStopHooks) harness.HookRunner { return h }

// v0.4.62 (issue #2): still no write-back after the nudge → must cancel the run context at the prevent round —
// blocking only tool calls makes the model argue with the hook round after round, burning tokens (production: a
// single intent got blocked for '20 consecutive rounds', 2583 wrap-up log entries in the journal).
func TestIdleStopCancelsRunAfterPreventRounds(t *testing.T) {
	fw := &fakeWrites{}

	var cancelled []error
	h := wrapIdleStop(nil, fw.get, func(string) {}, func(err error) { cancelled = append(cancelled, err) })
	ageStopper(h.stop, time.Hour) // past the startup grace period (age must apply to the stopper the hooks actually use)

	// Advance to the nudge round (rounds==idleStopRounds): first PreToolUse should block and nudge.
	for i := 0; i < idleStopRounds; i++ {
		h.PostToolUse(context.Background(), "Bash", nil, nil, false)
	}
	block, msg, _ := h.PreToolUse(context.Background(), "Bash", nil)
	if !block || !strings.Contains(msg, "write back") {
		t.Fatalf("nudge round should prompt write-back: block=%v msg=%q", block, msg)
	}
	if len(cancelled) != 0 {
		t.Fatalf("nudge round must not cancel")
	}

	// Still no write-back after the nudge; advance to the prevent round: should cancel (AbortIdleStop).
	for i := idleStopRounds; i < idleStopPreventRounds; i++ {
		h.PostToolUse(context.Background(), "Bash", nil, nil, false)
	}
	_, _, _ = h.PreToolUse(context.Background(), "Bash", nil)
	if len(cancelled) == 0 {
		t.Fatalf("at the prevent round (%d) it should cancel the run context", idleStopPreventRounds)
	}
	if !errors.Is(cancelled[0], AbortIdleStop) {
		t.Fatalf("cancel cause should be AbortIdleStop, got %v", cancelled[0])
	}
}

// Write-back after the nudge → counter resets, no more cancel (model gets its write-back chance).
func TestIdleStopWriteAfterNudgeResets(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get)
	ageStopper(s, time.Hour)

	var cancelled []error
	h := wrapIdleStop(nil, fw.get, func(string) {}, func(err error) { cancelled = append(cancelled, err) })

	for i := 0; i < idleStopRounds-1; i++ {
		h.PostToolUse(context.Background(), "Bash", nil, nil, false)
	}
	h.PreToolUse(context.Background(), "Bash", nil) // nudge
	fw.addFacts(1)                                   // the model wrote back
	h.PostToolUse(context.Background(), "record_fact", nil, nil, false)
	// More rounds must not cancel either (counter was reset).
	for i := 0; i < idleStopPreventRounds+2; i++ {
		h.PostToolUse(context.Background(), "Bash", nil, nil, false)
	}
	if len(cancelled) != 0 {
		t.Fatalf("no cancel after write-back: %v", cancelled)
	}
}
