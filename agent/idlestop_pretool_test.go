package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// A worker that keeps calling tools must still be wrapped by the idle-spin criterion.
//
// Regression background (2026-10-21 production measurement): 5 intents on task 5 ran 34–58 rounds with
// **zero write-backs** (tool_results only had Bash/Read/WebFetch — not a single
// record_fact / report_finding / insert_assets) yet never got wrapped.
//
// Root cause: idlestop hung on the harness's **Stop** hook, and the SDK only calls Stop when
// `len(toolUses) == 0` (the model called no tools that round) (harness/query.go:466). A worker
// that keeps working calls tools every round → **Stop never fires** → the idle-spin criterion was dead code.
// **Stop never gets called** → the idle criterion is dead letter.
//
// PreToolUse (harness/tools.go:78) is the hook called **before every tool call** — that's where
// steer_work's correction mechanism hooks in. The idle-spin criterion had to move there.
func TestIdleStopFiresWhileWorkerKeepsCallingTools(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(reason string) {})
	ageStopper(hooks.stop, time.Hour) // past the startup grace period

	// Simulate a worker that keeps calling tools: every PreToolUse passes, every tool 'executes',
	// but nothing ever gets written back. **Stop is never called** (the SDK won't call it in this scenario).
	for round := 0; round < idleStopRounds+2; round++ {
		block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"true"}`))
		if block {
			// Being blocked means the idle criterion works: nudge the model to wrap and write back.
			if !strings.Contains(msg, "write back") {
				t.Errorf("block message should mention writing back: %q", msg)
			}
			if !strings.Contains(msg, "Stop") && !strings.Contains(msg, "stop") {
				t.Errorf("block message should demand stopping probes: %q", msg)
			}
			return
		}
		// The tool 'executed' but nothing was written back → next round is still zero-delta.
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	t.Fatalf("after %d consecutive tool-calling rounds with zero write-back, the idle criterion should block this call", idleStopRounds+2)
}

// A continuously producing worker must never be blocked by PreToolUse — deep exploration unaffected.
func TestIdleStopDoesNotBlockProductiveWorker(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	for round := 0; round < 10; round++ {
		fw.addFacts(1) // write-back every round
		block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		if block {
			t.Fatalf("round %d had a write-back but got blocked — a producing worker must keep running", round+1)
		}
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
}

// PreToolUse blocking must only happen at 'zero write-back hits threshold', with one buffer:
// the first block is a nudge; if the model still doesn't stop, the second really wraps.
func TestIdleStopPreToolUseNudgesThenStops(t *testing.T) {
	fw := &fakeWrites{}
	stoppedReason := ""
	hooks := wrapIdleStop(nil, fw.get, func(reason string) { stoppedReason = reason })
	ageStopper(hooks.stop, time.Hour)

	// Threshold is idleStopRounds consecutive no-writeback rounds — earlier rounds pass.
	// The counter advances in PostToolUse (after the tool runs); the check is in PreToolUse (before) —
	// so 'the Nth tool execution' getting blocked shows up on 'the N+1th PreToolUse'. Running
	// idleStopRounds+1 iterations guarantees hitting the block.
	var block bool
	var msg string
	for i := 0; i < idleStopRounds+1; i++ {
		block, msg, _ = hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		if block {
			break
		}
		// Tool executed (zero write-back) → advance one round of counting.
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	if !block {
		t.Fatalf("after %d consecutive zero-writeback rounds, this tool call should be blocked", idleStopRounds)
	}
	if msg == "" {
		t.Error("blocking must include nudge text")
	}
	if stoppedReason != "" {
		t.Error("first block must not terminate outright (give the model a write-back chance)")
	}

	// Model still doesn't stop after the nudge (keeps zero write-back): keep blocking with reminders,
	// terminate only at the prevent round (v0.4.62: nudge 3 rounds + prevent 5 — no infinite block-arguing).
	var block2 bool
	// After the nudge, advance prevent-nudge more rounds; cancel happens on 'the PreToolUse at the prevent
	// round' (peek criterion) — so one extra PreToolUse after the loop triggers it.
	for i := 0; i < idleStopPreventRounds-idleStopRounds; i++ {
		block2, _, _ = hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		if !block2 {
			t.Fatalf("round %d after the nudge still zero write-back — should keep blocking", i+1)
		}
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	block2, _, _ = hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
	if !block2 {
		t.Fatal("at the prevent round it should still block")
	}
	if stoppedReason == "" {
		t.Errorf("at the prevent round (%d) it should really terminate and record the reason", idleStopPreventRounds)
	}
}

// When blocking a tool call, inner (the guard control chain) must still be called normally —
// our idle criterion can't bypass intercept rules.
func TestIdleStopPreToolUseStillCallsInner(t *testing.T) {
	fw := &fakeWrites{}
	inner := &recordingHookRunner{}
	hooks := wrapIdleStop(inner, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	// Zero write-back at threshold → our criterion blocks.
	for i := 0; i < idleStopRounds; i++ {
		if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`)); !block {
			hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
		}
	}

	// inner was called at least once (the chain wasn't short-circuited).
	if inner.preCalls == 0 {
		t.Error("inner.PreToolUse not called — the intercept chain was short-circuited")
	}
}

// recordingHookRunner records how many times PreToolUse was called.
type recordingHookRunner struct {
	preCalls int
}

func (r *recordingHookRunner) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	r.preCalls++
	return false, "", nil
}

func (r *recordingHookRunner) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
}

func (r *recordingHookRunner) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

var _ harness.HookRunner = (*recordingHookRunner)(nil)

// Write-back tools must never be blocked by the idle criterion.
//
// Regression risk: a worker accumulated results and is about to record_fact — blocking now = all lost.
// Worse than idle-spin — spinning only wastes time; blocking a write-back loses data.
func TestIdleStopNeverBlocksWriteBackTools(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	// Push the counter to threshold first (consecutive zero write-backs).
	for i := 0; i < idleStopRounds+1; i++ {
		if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`)); !block {
			hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
		}
	}

	for _, name := range []string{"record_fact", "insert_assets", "report_finding"} {
		block, msg, _ := hooks.PreToolUse(context.Background(), name, []byte(`{}`))
		if block {
			t.Errorf("write-back tool %q got blocked by the idle criterion (msg=%q) — results would be lost", name, msg)
		}
	}
}

// Write-back tools don't advance the idle counter — a write-back itself is 'produced output' (writes grows,
// which makes refreshLocked reset the counter) — no extra +1, or 'one round with output' counts as two
// rounds, shrinking the threshold from 3 rounds to 1.5.
func TestIdleStopWriteBackDoesNotAdvanceCounter(t *testing.T) {
	fw := &fakeWrites{}
	hooks := wrapIdleStop(nil, fw.get, func(string) {})
	ageStopper(hooks.stop, time.Hour)

	// Two probe tools (zero write-back) → count 2.
	for i := 0; i < 2; i++ {
		hooks.PreToolUse(context.Background(), "Bash", []byte(`{}`))
		hooks.PostToolUse(context.Background(), "Bash", []byte(`{}`), []byte(`ok`), false)
	}
	roundsAfterProbes := hooks.stop.rounds
	if roundsAfterProbes != 2 {
		t.Fatalf("count after two probes = %d, want 2", roundsAfterProbes)
	}

	// One write-back tool: counter must not change (write-back grows writes → refreshLocked resets).
	hooks.PreToolUse(context.Background(), "record_fact", []byte(`{}`))
	hooks.PostToolUse(context.Background(), "record_fact", []byte(`{}`), []byte(`ok`), false)
	if hooks.stop.rounds != roundsAfterProbes {
		t.Errorf("write-back tool advanced the counter: %d → %d (write-backs don't advance)",
			roundsAfterProbes, hooks.stop.rounds)
	}
}
