package server

import (
	"context"
	"path/filepath"

	"fmt"
	"github.com/chu0119/pojun/intercept"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// Task-level timeout coordinator (see docs/rename-impact-and-execution-plan.md §4/§8.5).
// Absolute wall clock: one timer goroutine per timeout-bearing task; at the deadline it
// drives the ordered settle sequence:
//   (1) settling → (2) worker stops claiming new intents / (3) planner drops normal
//   notify → (4) wait for running workers to drain (bounded by grace) → (5) one final
//   planner judging round → (6) commit terminal state (guarded)

const (
	// settleDrainGrace is the cap on waiting for running workers to finish gracefully;
	// past it → hard cancel.
	//
	// Why it was raised 90s→300s (2026-10-21 fix from production): at the deadline up to
	// **12 workers** may be running (worker count = concurrency cap), each doing one SDK
	// settlement round (inject wrapup prompt + ban Bash + write back results + closing
	// summary) — at least 1 LLM call each, and thinking models (minimax-m3.1) take
	// 30-60s per round.
	//
	// Production task 3 measured: deadline hit 13:42:23, drain timed out hard-killing at
	// 13:43:53 — in 90s 12 workers each wrote back only 1-3 facts; in-flight results were
	// lost. The settle window must be 'concurrent workers × one LLM round', not
	// per-worker.
	settleDrainGrace     = 300 * time.Second // cap on graceful worker drain; past it → hard cancel
	deadlinePollInterval = 2 * time.Second   // poll interval while deadline is unstamped / LLM not ready
	deadlineMaxSleep     = 30 * time.Second  // max single sleep (periodically re-check terminal state)
)

// ---------- settling state ----------

func (e *Engine) isSettling(taskID string) bool {
	_, ok := e.settling.Load(taskID)
	return ok
}

// markSettling records the settle reason; returns true only for the first caller.
func (e *Engine) markSettling(taskID, reason string) bool {
	if reason == "" {
		reason = "timeout"
	}
	_, loaded := e.settling.LoadOrStore(taskID, reason)
	return !loaded
}

func (e *Engine) settleReason(taskID string) string {
	v, _ := e.settling.Load(taskID)
	s, _ := v.(string)
	return s
}

// ---------- in-flight counters (worker.Execute + planner.Plan), used by drain ----------

func (e *Engine) inflightCounter(taskID string) *int64 {
	v, _ := e.inflight.LoadOrStore(taskID, new(int64))
	return v.(*int64)
}

// beginTaskOperation atomically registers a task-owned operation unless deletion
// has already installed its barrier. The delete handler can therefore wait for
// inflight==0 without a check-then-start race recreating files after cleanup.
func (e *Engine) beginTaskOperation(taskID string) bool {
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.IsDeleting(taskID) {
		return false
	}
	atomic.AddInt64(e.inflightCounter(taskID), 1)
	return true
}

func (e *Engine) decInflight(taskID string) { atomic.AddInt64(e.inflightCounter(taskID), -1) }
func (e *Engine) inflightCount(taskID string) int64 {
	return atomic.LoadInt64(e.inflightCounter(taskID))
}

// ---------- deadline ----------

// taskDeadline returns the task's absolute deadline (unix). Prefers the in-process
// map (stamped this session); falls back to the DB-loaded value (restart), seeding
// the map. 0 = no timeout / not yet stamped.
func (e *Engine) taskDeadline(t *Task) int64 {
	if v, ok := e.deadline.Load(t.ID); ok {
		return v.(int64)
	}
	deadlineAt := t.lifecycleSnapshot().DeadlineAt
	if deadlineAt > 0 {
		e.deadline.Store(t.ID, deadlineAt)
		return deadlineAt
	}
	return 0
}

// resetTerminalRevival clears per-run state after PostgreSQL has atomically
// committed <terminal status> -> running and reset first_run_at/deadline_at.
// The configured TimeoutSeconds remains on Task, so the next real Planner/Worker
// run stamps a fresh full budget. coordStarted is reset because the coordinator
// that settled the previous run has already completed (or is in its final return
// path) — a revived task must get a live coordinator again, otherwise its new
// deadline would never be enforced.
//
// Covers every terminal status (timeout / done / failed), not just timeout:
// reviving a "done" task hours after its original deadline used to leave an
// expired deadline_at behind, and the restarted coordinator settled the revived
// task within seconds — silently swallowing the human follow-up intent (task 13,
// 2026-11-05: follow-up #7470 created 16:36:16, final wrap-up round 16:36:17).
func (e *Engine) resetTerminalRevival(taskID string) {
	e.settling.Delete(taskID)
	e.deadline.Delete(taskID)
	e.stamped.Delete(taskID)
	e.coordStarted.Delete(taskID)
	// plannerRound is an in-process cumulative counter; a revived task that doesn't
	// reset it re-triggers auto_finish_max_rounds on the very first revival round and
	// instantly settles the human's follow-up.
	//
	// task_progress.round_no is the previous life's planning round: after revival the
	// in-memory count restarts at 1, and if round_no isn't zeroed too, RecordTaskProgress's
	// round_no<=old guard keeps idle_rounds at 0 — auto_idle/auto_coverage silently die
	// for a whole old budget cycle.
	e.plannerRound.Delete(taskID)
	// task_progress.round_no is the previous life's planning round: after revival the
	// in-memory count restarts at 1, and if round_no isn't zeroed too, RecordTaskProgress's
	// round_no<=old guard keeps idle_rounds at 0 — auto_idle/auto_coverage silently die
	// for a whole old budget cycle.
	if err := e.m.pg.ResetPlannerRoundForRevival(taskID); err != nil {
		log.Printf("[revival] task %s planner-round reset failed: %v", taskID, err)
	}
}

// stampFirstRun records first_run_at + deadline_at on the FIRST real run (LLM ready)
// of a timeout task, once per process. No-op when the task has no timeout.
func (e *Engine) stampFirstRun(t *Task) {
	if t.TimeoutSeconds <= 0 {
		return
	}
	if _, loaded := e.stamped.LoadOrStore(t.ID, true); loaded {
		return
	}
	dl, err := e.m.StampTaskFirstRun(t.ID)
	if err != nil {
		log.Printf("[deadline] task %s first_run stamp failed: %v", t.ID, err)
		e.stamped.Delete(t.ID) // allow the next retry
		return
	}
	if dl > 0 {
		e.deadline.Store(t.ID, dl)
		log.Printf("[deadline] task %s first run, deadline %s", t.ID, time.Unix(dl, 0).Format("2006-01-02 15:04:05"))
	}
}

// clockCtx layers the task's TaskClock (absolute deadline) onto a run's context so
// worker/planner can clamp their wall-clock budget and pick per-run vs task-timeout
// wrap-up words. final marks the coordinator-driven terminal planner round.
func (e *Engine) clockCtx(base context.Context, t *Task, final bool, reason string) context.Context {
	dl := e.taskDeadline(t)
	if dl <= 0 && !final {
		return base // no timeout → unchanged behavior
	}
	return agent.WithTaskClock(base, agent.TaskClock{DeadlineUnix: dl, Final: final, FinalReason: reason})
}

// ---------- coordinator ----------

// startDeadlineCoordinator launches the per-task deadline timer once (idempotent).
// Called from Run() and from the restart reload path, so non-active timeout tasks
// still get settled after their deadline even without live planner/worker loops.
func (e *Engine) startDeadlineCoordinator(ctx context.Context, t *Task) {
	if t == nil || t.TimeoutSeconds <= 0 {
		return
	}
	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	if _, loaded := e.coordStarted.LoadOrStore(t.ID, true); loaded {
		e.deleteMu.RUnlock()
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	e.deleteMu.RUnlock()
	runTaskRoutine(rt, func(loopCtx context.Context) { e.deadlineCoordinator(loopCtx, t) })
}

// deadlineCoordinator waits until the task's absolute deadline, then runs the settle
// sequence. Absolute wall-clock: it keeps counting through pauses.
func (e *Engine) deadlineCoordinator(ctx context.Context, t *Task) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return // already finished (goals met / failed) — nothing to time out
		}
		dl := e.taskDeadline(t)
		if dl <= 0 {
			if sleepCtx(ctx, deadlinePollInterval) { // not yet stamped (task hasn't really run)
				return
			}
			continue
		}
		if remaining := time.Until(time.Unix(dl, 0)); remaining > 0 {
			nap := remaining
			if nap > deadlineMaxSleep {
				nap = deadlineMaxSleep
			}
			if sleepCtx(ctx, nap) {
				return
			}
			continue
		}
		e.settleTask(ctx, t)
		return
	}
}

// taskGoalProgress returns this task's achieved-goal count and total (0/0 when no
// goals — nothing to prove).
func taskGoalProgress(t *Task) (met, total int) {
	if t == nil || t.Store == nil {
		return 0, 0
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 1000)
	if err != nil {
		return 0, 0
	}
	for _, g := range goals {
		total++
		if g.State == "met" {
			met++
		}
	}
	return met, total
}

// settleTerminalStatus computes the settle terminal state (demoted in red-team v0.6.31).
//
// Semantics: only 'all goals achieved' allows done; whenever a goal is unachieved, no
// matter the settle reason (timeout / auto-idle / coverage / round cap), the terminal
// state is timeout — the UI shows 'incomplete' instead of marking a half-done task
// complete. totalGoals==0 tasks keep the old semantics.
func settleTerminalStatus(allGoalsMet bool, reason string, finalRoundMet bool) string {
	if !allGoalsMet {
		return "timeout"
	}
	if reason == "timeout" && !finalRoundMet {
		return "timeout"
	}
	return "done"
}

// settleTask runs the ordered settle sequence once (§4 steps ①–⑥).
func (e *Engine) settleTask(ctx context.Context, t *Task) {
	e.settleTaskWithReason(ctx, t, "timeout", "task timeout reached")
}

// settleTaskWithReason is the unified settle entry. reason:
//   - timeout      absolute task deadline (terminal met?done:timeout)
//   - goal_met     planner judged goals met and no intents running (no final round —
//     straight to done)
//   - auto_idle / auto_coverage / auto_rounds  programmatic auto-settle (terminal done)
func (e *Engine) settleTaskWithReason(ctx context.Context, t *Task, reason, detail string) {
	if !e.markSettling(t.ID, reason) {
		return
	}
	t.clearSettle()
	label := reason
	switch reason {
	case "timeout":
		label = "timeout reached"
	case "goal_met":
		label = "planner judged goals met, no intents running"
	case "auto_idle", "auto_coverage", "auto_rounds":
		label = "auto-settle: " + detail
	}
	log.Printf("[settle] task %s entering settle (%s)", t.ID, label)
	if reason != "timeout" {
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("auto-settle: %s", detail)})
	}
	// (4) wait for running workers/planner to drain (running runs self-settle via the
	// clamped MaxDuration); if not empty past grace → hard-cancel the task exec ctx (the
	// settling-aware branches classify it correctly).
	hardStop := time.Now().Add(settleDrainGrace)
	for e.inflightCount(t.ID) > 0 {
		if time.Now().After(hardStop) {
			log.Printf("[settle] task %s drain timed out (%s), hard-cancelling running runs", t.ID, settleDrainGrace)
			e.cancelExec(t.ID, agent.AbortSettleDrainTimeout)
			_ = sleepCtx(ctx, 3*time.Second) // give worker branches a moment to persist/classify
			break
		}
		if sleepCtx(ctx, 500*time.Millisecond) {
			return // whole engine shutting down
		}
	}

	// (5) one final planner round. goal_met is already the planner's final judgement —
	// no extra round; timeout uses the timeout wrapup prompt, auto-settle uses the
	// 'settle by policy' prompt.
	met := reason == "goal_met"
	if reason != "goal_met" {
		met = e.runFinalPlannerRound(ctx, t, reason)
	}
	if !e.beginTaskOperation(t.ID) {
		// the delete barrier / a concurrent op blocked the terminal write. settling is
		// already set (planner/worker stopped); if not cleared, a delete-abort rollback
		// leaves the task stuck in settling forever: planner returns instantly each round,
		// workers idle, the deadline coordinator has exited — only a process restart
		// helps. Clearing it lets the next round retry the settle.
		e.settling.Delete(t.ID)
		t.requestSettle(reason, detail) // continue settling next round after the delete rollback — the trigger must not be dropped
		log.Printf("[settle] task %s terminal write blocked by delete barrier — settling cleared, retry pending", t.ID)
		return
	}
	defer e.decInflight(t.ID)

	// (5') before committing, name the vulns missing reports (no more workers after the
	// final round — can only prompt the human to complete them).
	e.warnFindingsWithoutReport(t)

	// (6) commit terminal state (guarded): only 'all goals proven achieved' counts as
	// done. Demoted in red-team v0.6.31: auto-settles (idle/coverage/rounds) and goal_met
	// with unachieved goals all land on timeout — the UI shows 'incomplete · stopped'.
	// The old 'auto-settle always done' was the source of 'half-finished but shown
	// complete'.
	metGoals, totalGoals := taskGoalProgress(t)
	allGoalsMet := totalGoals == 0 || metGoals >= totalGoals
	status := settleTerminalStatus(allGoalsMet, reason, met)
	if status == "timeout" && !allGoalsMet {
		log.Printf("[settle] task %s goals not all achieved (%d/%d) — terminal state timeout (incomplete), not done", t.ID, metGoals, totalGoals)
	}
	won, err := e.m.SetTaskStatusGuarded(t.ID, status)
	switch {
	case err != nil:
		// terminal write failed: clear settling and re-register, so the task isn't stuck
		// mid-settle forever.
		e.settling.Delete(t.ID)
		t.requestSettle(reason, detail)
		log.Printf("[settle] task %s terminal write failed (retry scheduled): %v", t.ID, err)
	case won:
		log.Printf("[settle] task %s settle done, terminal=%s (%s)", t.ID, status, label)
		// background jobs must not keep hitting targets after terminal state (the
		// authorization window is over).
		if n := agent.KillJobsForTaskDir(filepath.Join(e.m.dir, "tasks", t.ID)); n > 0 {
			log.Printf("[settle] task %s cleaned %d background jobs at settle", t.ID, n)
		}
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("task settle complete: %s; terminal %s", label, status)})
	default:
		log.Printf("[settle] task %s already terminal at settle, keeping state", t.ID)
	}
}

// runFinalPlannerRound drives exactly ONE terminal planner round with the
// task-timeout planner words (final goal judgment; no new intents). Waits for the
// LLM to be ready (bounded by ctx) so a completable task isn't mis-judged timeout.
func (e *Engine) runFinalPlannerRound(ctx context.Context, t *Task, reason string) (met bool) {
	if e.IsDeleting(t.ID) {
		return false
	}
	planner, _ := e.snapshotFor(t)
	waitDeadline := time.Now().Add(90 * time.Second)
	for planner == nil {
		if time.Now().After(waitDeadline) {
			// can't wait forever when the LLM chain is unavailable (provider disabled /
			// quota exhausted): the task would sit in settling forever (workers stop
			// claiming, planner drops wakes, terminal never written). Treat as 'final
			// judgement unavailable' — the caller writes timeout/done per actual goal
			// achievement.
			log.Printf("[settle] task %s waited >90s for the final planner (LLM unavailable?) — skipping final judgement", t.ID)
			return false
		}
		if sleepCtx(ctx, deadlinePollInterval) {
			return false
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return false
		}
		if e.IsDeleting(t.ID) {
			return false
		}
		planner, _ = e.snapshotFor(t)
	}
	// independent ctx (not hung off execCancel, so pause/hard-cancel can't interrupt
	// this last round), with Final wrapup injection: timeout uses the task-timeout
	// prompt, auto-settle the 'end by policy' prompt.
	fctx := e.clockCtx(ctx, t, true, reason)
	fctx = intercept.WithAutopilot(fctx, t.AutopilotEnabled) // autopilot prompt tail (settle round)
	if !e.beginTaskOperation(t.ID) {
		return false
	}
	defer e.decInflight(t.ID)
	emit := func(r db.Activity) { e.emitActivity(t, r) }
	summary := fmt.Sprintf("task-timeout settle · final judgement (round %d)", e.nextPlannerRound(t.ID))
	if reason != "timeout" {
		summary = fmt.Sprintf("auto-settle · final judgement (round %d, reason %s)", e.nextPlannerRound(t.ID), reason)
	}
	e.emitActivity(t, db.Activity{Worker: "planner", Kind: "round", Summary: summary})
	tTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
	e.BeginLLMCall(t.ID)
	// the final round gets the same wall-clock guard as normal planning rounds: fctx is
	// the deadline-free server root ctx and settleTask is blocked waiting to commit — if
	// Plan deadlocks (upstream half-open connection / compactor self-deadlock — both real
	// production incidents), the task would sit in settling forever. Timeout = return as
	// 'not achieved' and run the normal timeout-settle path; a leaked deadlocked
	// goroutine is the lesser evil.
	roundCtx, roundCancel := context.WithTimeout(fctx, plannerRoundLimit())
	defer roundCancel()
	res := runPlannerRound(roundCtx, func(pctx context.Context) (bool, string, error) {
		return planner.Plan(pctx, tTaskID, e.m.assets, t.Store, t.Goal, t.drainTriggers(), emit)
	})
	e.EndLLMCall(t.ID)
	if res.err != nil && roundCtx.Err() != nil {
		log.Printf("[deadline] task %s final planning timed out (%s) — continuing settle as not-achieved", t.ID, plannerRoundLimit())
		return false
	}
	if res.err != nil {
		log.Printf("[deadline] task %s final planning errored: %v", t.ID, res.err)
	} else if res.met {
		log.Printf("[deadline] task %s final judgement: goals achieved: %s", t.ID, res.reason)
	}
	return res.met
}
