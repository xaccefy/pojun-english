package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// No-increment auto wrap-up (idle-stop): when a worker goes several consecutive rounds without
// writing anything back, end the run proactively instead of waiting for the wall-clock budget to cut it off.
//
// ## Why it's needed
//
// The status quo is "bound the goal → bound the time → forced summary at deadline → planner re-dispatches". That structure has three
// problems measured in production:
//
//  1. **Wrap-up is passive**: the worker doesn't know "time to stop", only "deadline is near — write fast".
//     Production intent summaries averaged 737 chars, max 2267 — it dumps everything out
//     because the deadline forces it.
//  2. **Exhaustion far outnumbers completion**: production terminal-state distribution was done 18 / exhausted 99 /
//     blocked 82. exhausted is 5.5× done — most probes are **cut off**, not finished.
//
//  3. **Continuation-chain positive feedback**: the planner's instruction on exhausted is "approaching a breakthrough, budget-cut →
//     dispatch 'continue from last progress'". But "approaching a breakthrough" is judged by the planner, which only sees
//     a one-line summary and the trace — the longer the summary, the more the planner feels "almost there, give it one more
//     chance". Long summary → continue → longer intent → longer summary.
//
// Production saw a three-generation chain: #635 → #578 → #660, the summary saying "continue #635/#578,
// interrupted twice by backend restarts, still attacking the crown-jewel chain of ZStack management-API
// credentials (#635 already ran 56 rounds/28 min last round)".
//
// ## Criterion: output rate, not duration
//
// Use "N consecutive rounds without writing back any fact/asset/finding" as the wrap-up criterion, not duration.
// Duration is noise — a worker scanning the same ports for 10 rounds without writing back has no output; but a
// worker writing new assets every round shouldn't be cut even after a full 30 minutes.
//
// Output rate maps directly to "does this direction still have value"; duration doesn't.
//
// ## Which hooks it hangs on (corrected 2026-10-21)
//
// It originally hung only on the **Stop** hook — the comment said "harness.HookRunner.Stop is called after every
// assistant turn" — **that premise was wrong**. The SDK actually only calls Stop
// when `len(toolUses) == 0` (the model called no tools that turn)
// (harness/query.go:466). So:
//
//	a worker that keeps working (calls tools every round) → Stop never gets called
//	→ the spin criterion is dead code
//
// Production: task 5's 5 intents ran 34~58 rounds **without a single writeback** and were never
// wrapped up; the journal had zero "no-increment auto wrap-up" entries.
//
// Now it hangs in **both places**:
//   - **PreToolUse** (harness/tools.go:78, called before every tool call) — the primary criterion.
//     At threshold it **blocks this tool call** and returns "please write back confirmed results and stop" to
//     the model (same pattern as steer_work's correction: block=true + message).
//     A steadily working worker takes exactly this path — so this one actually holds it.
//   - **Stop** (when the model called no tools that round) — kept, covering the "model just wants to talk" case.
//
// ## Why it doesn't hurt "depth first"
//
// Depth-first (punch deep when a high-value entry is found) directly conflicts with "time caps". The criterion
// here sidesteps that conflict: **it only fires when the direction has stopped producing**. A continuously
// producing worker is never interrupted by this mechanism — deep exploration unaffected; only spins get cut.

// idleStopDefaults are the no-increment wrap-up defaults.
const (
	// idleStopRounds is "how many consecutive no-writeback rounds before wrapping up".
	//
	// Why 3: a worker's normal rhythm is "probe → write back → probe → write back". Occasionally
	// 1-2 probe-only rounds are normal (e.g. preparing intermediate steps of a multi-stage exploit chain).
	// 3 consecutive rounds with zero writeback basically means the direction hit a boundary or drifted.
	//
	// Not 1: a single no-writeback round is too common (thinking through a conclusion before writing it) — would kill normal workers.
	// Not 5: measured — a spinning worker burns minutes of LLM time in 5 rounds while producing
	// nothing usable at all.
	idleStopRounds = 3

	// idleStopMinElapsed is "minimum elapsed time before no-increment wrap-up is allowed".
	//
	// Why it exists: a worker's first rounds may be prep work (mkdir, read prior
	// facts, fetch target info) — no writeback there is normal. Give it a grace runway
	// so the start isn't judged a spin.
	idleStopMinElapsed = 3 * time.Minute

	// idleStopPreventRounds is "how long after the notice, still no writeback, before actually wrapping".
	//
	// Separated from the nudge rounds (issue #2's core ask): 3 no-writeback rounds → notice first (give the model a
	// writeback chance), then 2 more rounds; still none → end the run — unlike before, where every tool call got
	// blocked but the run never ended and the model debated the hook round after round, burning tokens (production:
	// a single intent got blocked up to "20 consecutive rounds" before ending — 2583 wrap-up log entries).
	idleStopPreventRounds = 5
)

// idleStopper tracks "consecutive no-writeback rounds" inside one worker run, and requests wrap-up at threshold.
//
// Counting unit: **each Stop callback is one round**. Stop is called after every assistant turn,
// so one round ≈ one "model thinking + batch of tool calls".
type idleStopper struct {
	// writes points at this run's writeback counter (source of ToolSet.Writes).
	writes func() WriteCounts

	// rounds is the count of consecutive no-writeback rounds.
	rounds int
	// lastWrites is the writeback total last seen, for judging "did this round produce".
	lastWrites int
	// start is this run's origin, for the startup grace period.
	start time.Time
	// stopped marks whether wrap-up was already requested (only once).
	stopped bool
	// nudged records whether the "write back and stop" notice was already given. If it still doesn't stop,
	// the next time truly wraps. Same thing as idleStopHooks.nudged, counted in two places — this copy
	// in the stopper is used for "reset after a writeback" (post-recovery, allow one more notice).
	nudged bool
	// nudgedRound is the rounds snapshot at first nudge. Same-round concurrent tool calls (multiple tool_use in
	// one assistant turn is normal and encouraged) enter PreToolUse's nudge/prevent branches in sequence — prevent must
	// **additionally require at least one round of progress after the nudge**, or the second tool call jumps
	// straight from "first notice" to "noticed repeatedly, ending the round" — the worker gets terminated without a
	// chance to write back (issue #8 in production: the very round writing back confirmed RCE results was cut like this, and the results were lost forever).
	nudgedRound int
	// mu guards concurrent access (Stop may run concurrently with tool execution).
	mu sync.Mutex
	// reason records the wrap-up cause for logs/DB.
	reason string
}

func newIdleStopper(writes func() WriteCounts) *idleStopper {
	return &idleStopper{writes: writes, start: time.Now()}
}

// check records this round's state, returning prevent=true to request wrap-up when needed.
//
// The messages param is unused — the criterion only looks at writeback increments, not what the model said. Reading text has two
// downsides: the model could claim "I'm done exploring" to fool the criterion; and a worker carefully building a
// multi-stage chain talks a lot and would be misjudged as "still producing".
//
// "One round" means **one tool execution** (PreToolUse admits → PostToolUse counts once).
// Early versions defined a round as an assistant turn, but the SDK only calls Stop when "no tools were called
// that turn" — that unit never advances on a steadily working worker (see the file-header comment).
func (s *idleStopper) check() (prevent bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Check for new writeback first — any resets the counter (this round produced).
	if s.refreshLocked() {
		return false, ""
	}
	// This round passed — counter +1.
	s.rounds++
	// Still inside the startup grace period — don't wrap up.
	if time.Since(s.start) < idleStopMinElapsed {
		return false, ""
	}
	if s.rounds < idleStopRounds {
		return false, ""
	}
	// Threshold already reached: keep returning prevent.
	if s.stopped {
		return true, s.reason
	}
	s.stopped = true
	s.reason = fmt.Sprintf("%d consecutive rounds with no writeback (%d writebacks this run — output rate zero)", s.rounds, s.totalLocked())
	return true, s.reason
}

// peek judges "are we already at the wrap-up-worthy spin level", **without advancing the counter**.
//
// Why a separate peek: check()'s semantics are "calling advances a round" (the Stop path relies on it).
// But PreToolUse also gets called before each tool execution — if it used check(), the same round would advance
// twice (once in PreToolUse, once in the following Stop), shrinking the threshold from "3 consecutive rounds"
// to "1.5 consecutive rounds" — too aggressive, would kill workers about to write back.
func (s *idleStopper) peek() (prevent bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshLocked() {
		return false, ""
	}
	if s.stopped {
		return true, s.reason
	}
	if time.Since(s.start) < idleStopMinElapsed {
		return false, ""
	}
	if s.rounds < idleStopRounds {
		return false, ""
	}
	return true, fmt.Sprintf("%d consecutive rounds with no writeback (%d writebacks this run — output rate zero)", s.rounds, s.totalLocked())
}

// advance marks one round passed (one tool execution).
//
// The counter is advanced by PostToolUse — the only path a worker **that calls tools every round** takes.
// The Stop path advances separately (see check); the two are mutually exclusive: a turn either called tools
// (PostToolUse advances, Stop isn't called) or didn't (Stop advances) — never double-counted.
func (s *idleStopper) advance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshLocked() {
		// This round produced → refreshLocked already zeroed it, no +1.
		return
	}
	s.rounds++
}

// refreshLocked zeroes the counter on new writebacks, returning "did this round produce".
// The caller must hold s.mu.
func (s *idleStopper) refreshLocked() bool {
	total := s.totalLocked()
	if total > s.lastWrites {
		s.lastWrites = total
		s.rounds = 0
		s.stopped = false
		s.nudged = false
		s.nudgedRound = 0
		return true
	}
	return false
}

// totalLocked reads the current cumulative writebacks. The caller must hold s.mu.
func (s *idleStopper) totalLocked() int {
	if s.writes == nil {
		return 0
	}
	return s.writes().Total()
}

// markNudged records the rounds snapshot at this nudge (caller holds idleStopHooks.mu).
func (s *idleStopper) markNudged() {
	s.mu.Lock()
	s.nudgedRound = s.rounds
	s.mu.Unlock()
}

// advancedSinceNudge judges whether at least one tool-execution round has passed since the nudge.
// Other tool calls issued concurrently in the same round leave rounds unchanged — they must still land in the
// notice tier, not escalate straight to wrap-up.
func (s *idleStopper) advancedSinceNudge() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rounds > s.nudgedRound
}

// idleStopHooks hangs idleStopper on the harness hook chain.
//
// It's a combination of **side-observer + wrap-up requestor**:
//   - PreToolUse/PostToolUse: forwarded verbatim to inner (the log layer doesn't intercept).
//   - Stop: checked after inner's Stop — if inner wants to stop, stop; if inner is fine but the output rate
//     is zero, request wrap-up.
//
// Order: forward to inner first, then judge. inner is the interception control (guard) — if it says stop, we stop;
// we only append a wrap-up request when inner allows AND this round genuinely produced nothing.
//
// ## Why blocking instead of direct prevent
//
// The harness Stop hook has two return shapes:
//   - prevent=true → terminates the run immediately, the model gets **no chance to write back**.
//   - blocking=[]string → the SDK injects those strings as user messages and the model **runs one more round**.
//
// We want the latter: a worker judged spinning mid-run may be holding a pile of "probed but not yet written"
// results. Direct prevent would drop all of that — the real waste. So the flow is:
//
//	1st trigger → blocking: tell the model "this direction yields nothing new — write back confirmed
//	                results and close with a one-line summary"
//	2nd trigger → prevent: the model already got to summarize and still won't stop → truly wrap up
//
// The stopHookActive mechanism prevents infinite loops: after the SDK injects blocking, stopHookActive
// stays set until a real tool round happens.
type idleStopHooks struct {
	inner harness.HookRunner
	stop  *idleStopper
	// cancel cancels this run's context (v0.4.62): when there's still no writeback after the notice, use it to truly
	// wrap up — PreToolUse's block only intercepts a single tool call, the run keeps going and the model debates round by round.
	cancel func(err error)
	// onStop is called once (with the wrap-up reason), for logging/persistence.
	onStop func(reason string)
	// nudged records whether the blocking notice was already given (prevent is only allowed after it).
	nudged bool
	// mu guards nudged (Stop may be called concurrently).
	mu sync.Mutex
}

// PreToolUse is the spin criterion's **primary attachment point**: the SDK calls it before every tool execution
// (harness/tools.go:78), while Stop only fires when "no tools were called that round".
//
// At threshold: block this tool call and return "please write back confirmed results, then stop" as the
// tool result to the model (block=true + message — same pattern as steer_work's correction). The model can then
// use record_fact / report_finding / insert_assets to write results back — those three **don't go through**
// this hook (they're normal tool calls, but the writeback itself resets the counter).
//
// The first block is a notice; if the model still doesn't stop (keeps calling tools, still zero writeback), the second wraps for real.
func (h *idleStopHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	// Writeback tools pass straight through: intercepting a worker about to persist its results = losing those results.
	if idleStopWriteTools[name] {
		if h.inner != nil {
			return h.inner.PreToolUse(ctx, name, input)
		}
		return false, "", nil
	}
	// inner (the guard control chain) runs first — the spin criterion mustn't bypass interception rules.
	if h.inner != nil {
		if block, msg, updated := h.inner.PreToolUse(ctx, name, input); block {
			return block, msg, updated
		}
	}
	prevent, reason := h.stop.peek()
	if !prevent {
		return false, "", nil
	}
	h.mu.Lock()
	alreadyNudged := h.nudged
	h.nudged = true
	h.mu.Unlock()
	if !alreadyNudged {
		// First time: block this tool call, notice the model to write back and stop (it still gets the chance to persist results).
		// Record the rounds snapshot at nudge: other tool_use issued concurrently in the same round must land in the notice tier.
		h.stop.markNudged()
		return true, idleStopMessage, nil
	}
	// Still no writeback after the notice: give it idleStopPreventRounds more rounds; at the point, cancel the run context
	// to truly wrap up (block only intercepts a single tool call — without cancel the model debates the hook round by round).
	// **At least one tool-execution round must have advanced after the nudge** before wrap-up is allowed — the rest of the
	// same round's concurrent tool_use must not jump straight to termination (issue #8).
	if h.stop.rounds >= idleStopPreventRounds && h.stop.advancedSinceNudge() {
		// Record the reason first (for logs/persistence), then cancel the run context; with no cancel wired it degrades to
		// block-only — the Stop hook's prevent path backstops the wrap-up.
		if h.onStop != nil {
			h.onStop(reason)
		}
		if h.cancel != nil {
			h.cancel(AbortIdleStop)
		}
		return true, idleStopMessage + " (noticed repeatedly without wrapping — this round ends now)", nil
	}
	return true, idleStopMessage + " (please write back now and stop calling tools; continuing will end this round)", nil
}

// PostToolUse advances the "one round" counter: one tool execution = one round.
//
// Why here and not PreToolUse: after PreToolUse admits, the tool **may still fail** (command errors,
// network down) — that's still "a round with no output" and should count. PostToolUse counts both
// successful and failed calls.
func (h *idleStopHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
	// Writeback tools don't advance the counter (they're end actions — see idleStopWriteTools).
	if idleStopWriteTools[name] {
		return
	}
	// One tool execution = one round — advance the counter.
	//
	// Why advance here: PreToolUse only judges (peek); Stop is only called when "no tools were called that round".
	// A steadily working worker takes exactly the "calls tools every round" path — its round counter can only
	// advance via PostToolUse, otherwise it stays at 0 forever and the spin criterion never holds.
	h.stop.advance()
}

func (h *idleStopHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.inner != nil {
		prevent, blocking, msg := h.inner.Stop(ctx, messages)
		if prevent {
			return prevent, blocking, msg
		}
	}
	prevent, reason := h.stop.check()
	if !prevent {
		return false, nil, ""
	}
	h.mu.Lock()
	alreadyNudged := h.nudged
	h.nudged = true
	rounds := h.stop.rounds
	h.mu.Unlock()
	if !alreadyNudged {
		// First trigger: give the model one chance to write back confirmed results.
		return false, []string{idleStopMessage}, ""
	}
	// Still no writeback after the notice: only the prevent round truly wraps (before that it's just a reminder —
	// avoids the Stop path cutting earlier than PreToolUse).
	if rounds < idleStopPreventRounds {
		return false, []string{idleStopMessage + " (please write back now and stop calling tools; continuing will end this round)"}, ""
	}
	if h.onStop != nil {
		h.onStop(reason)
	}
	return true, nil, reason
}

// wrapIdleStop wraps idleStopper around the existing hook chain.
func wrapIdleStop(inner harness.HookRunner, writes func() WriteCounts, onStop func(string), cancel ...func(error)) *idleStopHooks {
	h := &idleStopHooks{inner: inner, stop: newIdleStopper(writes), onStop: onStop}
	if len(cancel) > 0 {
		h.cancel = cancel[0]
	}
	return h
}

// idleStopWriteTools are the "writeback-class" tools: they're **end actions**, not probes.
//
// Why they don't participate in the spin criterion:
//   - They must never be intercepted. A worker holding a pile of results about to record_fact — blocking that =
//     losing all results, worse than spinning.
//   - They don't advance the counter. Writeback grows writes, and refreshLocked zeroes the counter naturally;
//     advancing it again would count a "produced" round as two.
var idleStopWriteTools = map[string]bool{
	"record_fact":    true,
	"insert_assets":  true,
	"report_finding": true,
	// save_evidence: attaching evidence = a concrete find (screenshot/data sample/log), and it's a wrap-up action
	// that must never be blocked. Counting it as writeback means 'found something, save evidence first' also resets the spin counter.
	"save_evidence": true,
}

// idleStopMessage is the explanation given to the model on wrap-up.
//
// Explaining "why we're wrapping" matters: a model that sees "budget exhausted, terminated" thinks it's punished and
// tends to write unverified guesses as conclusions; seeing "this direction has no new output — write back what's
// confirmed and stop" makes it correctly collect the confirmed results.
const idleStopMessage = "This run has had no writeback for several consecutive rounds — this direction yields nothing new for now. Stop calling tools immediately and write back during wrap-up:\n\n" +
	"1. Write back **confirmed** results (all four count as output and reset the counter):\n" +
	"   - conclusions/observations/eliminations → record_fact (**negative results count**: 'tested X, no Y, observed Z' is a fact)\n" +
	"   - new assets → insert_assets; confirmed vulns → report_finding; scene evidence → save_evidence\n" +
	"2. After writing back, close the round with a one-sentence plain-text summary of what you found and where you're stuck.\n\n" +
	"This isn't a punishment — it's your chance to persist results; everything written back is kept. Don't write unverified guesses as facts just to 'produce output'."

// logIdleStop logs a wrap-up entry (uniform format for later stats).
func logIdleStop(worker string, taskID int64, intentID int64, reason string) {
	log.Printf("[worker %s] task %d intent #%d no-increment auto wrap-up: %s", worker, taskID, intentID, reason)
}

// summarizeWriteDelta describes one round's writeback delta (debug/logging).
func summarizeWriteDelta(cur, prev WriteCounts) string {
	return fmt.Sprintf("facts+%d assets+%d vulns+%d",
		cur.Facts-prev.Facts, cur.Assets-prev.Assets, cur.Findings-prev.Findings)
}

// idleStopStateText is the one-line explanation for the planner (written into the intent's stop reason).
//
// The planner uses it to tell two kinds of exhausted apart:
//   - 'cut by wall clock' (a clear next step existed, just out of time)
//   - 'probed to the boundary' (the direction itself has nothing left)
//
// These are opposites in the planner's decision — mixing them causes 'keep re-dispatching the same direction'.
func idleStopStateText(reason string) string {
	return strings.TrimSpace(reason)
}
