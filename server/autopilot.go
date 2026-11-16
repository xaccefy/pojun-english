package server

// Autopilot: hand a task over and the system pushes it to completion by itself.
//
// Three legs (design in the plan file / docs):
//  1. (the public build does NOT auto-approve: the approval gate and intercept rules
//     stay in force; prompts tell agents to avoid actions needing human approval);
//  2. stall watchdog: this file scans autopilot tasks every 60s; long progress silence
//     wakes the planner to re-plan, and consecutive stalls extend the deadline (count
//     persisted, capped);
//  3. finish-last: auto_finish's idle/coverage criteria don't apply to autopilot tasks
//     (see auto_finish.go) — only goal_met and auto_rounds (the cost hard cap) can wrap
//     up.
//
// Key facts (so you don't trip):
//   - engine.LastActivity is refreshed by the planner heartbeat (one round ≥600s) — it
//     can't measure staleness. Progress fingerprint here = graph facts/finding/asset
//     counts (same measure as auto_finish idle).
//   - stall wake-ups must use their own trigger kind (autopilot_stall), never reuse
//     hint — hint is treated by freshDirection as a new direction and resets the idle
//     counter, polluting the wrap-up decision.
//   - a suppressed wrap-up reason must be cleared off the Task and the round must keep
//     planning, else plannerLoop returns unconditionally in the 'pending wrap-up'
//     branch and deadlocks the whole task.

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/chu0119/pojun/db"
)

const (
	settingAutopilotDefault       = "autopilot_default"
	settingAutopilotStallMinutes  = "autopilot_stall_minutes"
	settingAutopilotMaxExtensions = "autopilot_max_extensions"

	defaultAutopilotStallMinutes = 8
	// v0.6.12: default 10 (was 2). relentless mode means 'keep going while there's
	// work' — capped at 2 extensions, long tasks would still get timeout-killed
	// mid-way; the ceiling is still guarded by ExtendTaskDeadline, adjustable 0–10 in
	// settings.
	defaultAutopilotMaxExtensions = 10

	// one extension is at least 15 minutes; extends by half the original budget; single
	// extension capped at 6 hours so it can't stretch till dawn.
	autopilotExtendFloor = 15 * time.Minute
	autopilotExtendCap   = 6 * time.Hour

	// how many consecutive progress-less stall wake-ups trigger one budget extension.
	autopilotNudgesBeforeExtend = 2
)

type autopilotConfig struct {
	Default       bool
	StallMinutes  int
	MaxExtensions int
}

// autopilotConfigFromPG reads global settings, clamped to safe ranges; a read failure
// falls back to defaults — a settings query error must never stop the watchdog.
func autopilotConfigFromPG(pg *db.DB) autopilotConfig {
	c := autopilotConfig{
		Default:       true,
		StallMinutes:  defaultAutopilotStallMinutes,
		MaxExtensions: defaultAutopilotMaxExtensions,
	}
	if pg == nil {
		return c
	}
	c.Default = pg.GetBool(settingAutopilotDefault, true)
	if n, ok := settingInt(pg, settingAutopilotStallMinutes); ok {
		c.StallMinutes = clampInt(n, 3, 120)
	}
	if n, ok := settingInt(pg, settingAutopilotMaxExtensions); ok {
		c.MaxExtensions = clampInt(n, 0, 10)
	}
	return c
}

// autopilotTrack is per-task watchdog memory state (reset on restart — acceptable).
type autopilotTrack struct {
	lastProgressAt time.Time
	lastNudgeAt    time.Time
	nudges         int
	baseline       int64 // facts+findings fingerprint
}

// trackFor gets/creates a task's watchdog state (tick goroutine only — no extra
// locking).
func (e *Engine) trackFor(taskID string) *autopilotTrack {
	v, _ := e.autoTrack.LoadOrStore(taskID, &autopilotTrack{})
	return v.(*autopilotTrack)
}

// startAutopilotLoop starts the watchdog. One per process, exits with the server's
// s.ctx.
func (e *Engine) startAutopilotLoop(ctx context.Context) {
	const tick = 60 * time.Second
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.autopilotTick(now)
		}
	}
}

// autopilotTick is one full scan pass. now is injectable for tests.
func (e *Engine) autopilotTick(now time.Time) {
	pg := e.m.pg
	if pg == nil {
		return
	}
	states, err := pg.AutopilotTaskStates()
	if err != nil {
		log.Printf("[autopilot] task scan failed: %v", err)
		return
	}
	cfg := autopilotConfigFromPG(pg)
	stall := time.Duration(cfg.StallMinutes) * time.Minute

	for id, st := range states {
		t, ok := e.m.Task(id)
		if !ok || t == nil || !t.AutopilotEnabled() {
			e.autoTrack.Delete(id)
			continue
		}
		// extend **early** once under half the budget is left: a running run's
		// TaskClock was snapshotted at start — extending at the wall can't save workers
		// already clamped to MaxDuration≈0 (they'd wrap up anyway). Early extensions
		// are likewise guarded by autopilot_extensions.
		// v0.7.6: threshold raised 10%→50%, single extension half→full budget — a
		// 30-minute task was cutting long-running chains every 15 minutes, producing
		// floods of 'run timeout (exhausted)'.
		if st.Unmet() && cfg.MaxExtensions > 0 && t.TimeoutSeconds > 0 {
			if dl := e.taskDeadline(t); dl > 0 {
				budget := time.Duration(t.TimeoutSeconds) * time.Second
				if time.Until(time.Unix(dl, 0)) < budget/2 {
					e.tryAutopilotExtend(t, cfg)
				}
			}
		}
		// v0.6.23: no longer blanket-skip when intents/LLM calls are running — a slow
		// model or stuck worker can sit 'running but zero write-back' for ages, and the
		// old logic never called it stalled (the task looked frozen in the UI forever —
		// delivery check measured 20+ min of two intents with no write-back on the
		// free model). Now: no running → normal stall window; running → window doubles
		// (respecting nmap-scale scans); the planner only reads posture to re-dispatch/
		// correct, never interrupts workers.
		if !e.Started(id) || e.IsDeleting(id) || e.isSettling(id) {
			continue
		}
		inflight := e.inflightCount(id) > 0 || e.ActiveLLMCalls(id) > 0
		if !st.Unmet() { // all goals met — watchdog bows out
			e.autoTrack.Delete(id)
			continue
		}
		// progress fingerprint = facts + findings + assets. Bare fact count gets
		// flooded by 'restate/fragment'; new assets and new findings are real progress
		// (v0.7.0).
		progress := st.Facts + st.Findings + st.Assets
		tr := e.trackFor(id)
		if tr.lastProgressAt.IsZero() || progress > tr.baseline {
			tr.baseline = progress
			tr.lastProgressAt = now
			tr.nudges = 0
			continue
		}
		if now.Sub(tr.lastProgressAt) < stall {
			continue
		}
		// v0.6.23: with workers running, double the stall window — genuinely long scans
		// aren't misjudged; but 'running yet two windows without write-back' means
		// they're idling/stuck — the planner must be woken.
		if inflight && now.Sub(tr.lastProgressAt) < 2*stall {
			continue
		}
		if !tr.lastNudgeAt.IsZero() && now.Sub(tr.lastNudgeAt) < stall {
			continue // cooldown: one wake-up per stall window
		}

		detail := fmt.Sprintf("No new facts/findings/assets for %d minutes; goals not all met (%d/%d). Dispatch the next step or change direction now; wrapping up as 'exploration done / insufficient info' is forbidden.",
			int(now.Sub(tr.lastProgressAt).Minutes()), st.GoalsMet, st.GoalsTotal)
		if inflight {
			detail = fmt.Sprintf("No new facts/findings/assets for %d minutes (workers are running but nothing is written back); goals not all met (%d/%d). Check whether running intents are idling: add direction / correct running intents, or dispatch the next step; wrapping up as 'exploration done / insufficient info' is forbidden.",
				int(now.Sub(tr.lastProgressAt).Minutes()), st.GoalsMet, st.GoalsTotal)
		}
		t.NotifyAutopilotStall(detail)
		tr.lastNudgeAt = now
		tr.nudges++
		_ = pg.InsertAutopilotEvent(id, "stall_nudge", detail)
		e.emitActivity(t, db.Activity{Worker: "autopilot", Kind: "text",
			Summary: "Autopilot: stall detected — planner woken to re-plan"})
		log.Printf("[autopilot] task %s stalled %s with no progress -> waking planner (wake #%d)",
			id, now.Sub(tr.lastProgressAt).Round(time.Minute), tr.nudges)

		// consecutive wakes, still no progress -> extend the budget (capped, count
		// persisted, per-extension ceiling).
		if tr.nudges >= autopilotNudgesBeforeExtend {
			if e.tryAutopilotExtend(t, cfg) {
				tr.lastProgressAt = now // give the new budget a full window
				tr.nudges = 0
			}
		}
	}
}

// tryAutopilotExtend pushes the task's absolute deadline back. Returns true if
// extended.
//
// Only applies to tasks with a time budget and a stamped deadline — a task without a
// deadline can't time out anyway. The count is guarded by DB autopilot_extensions, so
// restarts can't extend forever.
func (e *Engine) tryAutopilotExtend(t *Task, cfg autopilotConfig) bool {
	if t == nil || cfg.MaxExtensions <= 0 || t.TimeoutSeconds <= 0 {
		return false
	}
	old := e.taskDeadline(t)
	if old <= 0 {
		return false
	}
	// v0.7.6: extend by the full task budget (old impl took half). Half a budget only
	// covered the middle of one long chain — the task re-hit the wall quickly; a full
	// budget gives renewed workers a complete window to finish the exploit chain.
	ext := time.Duration(t.TimeoutSeconds) * time.Second
	if ext < autopilotExtendFloor {
		ext = autopilotExtendFloor
	}
	if ext > autopilotExtendCap {
		ext = autopilotExtendCap
	}
	id, err := parseTaskID(t.ID)
	if err != nil {
		return false
	}
	dl, used, ok, err := e.m.pg.ExtendTaskDeadline(id, int(ext.Seconds()), cfg.MaxExtensions)
	if err != nil {
		log.Printf("[autopilot] task %s deadline extension failed: %v", t.ID, err)
		return false
	}
	if !ok {
		return false
	}
	e.deadline.Store(t.ID, dl.Unix())
	t.updateLifecycle(func(s *taskLifecycleState) { s.DeadlineAt = dl.Unix() })
	detail := fmt.Sprintf("goals unmet with consecutive stalls — deadline auto-extended %s (extension %d/%d) -> %s",
		ext.Round(time.Minute), used, cfg.MaxExtensions, dl.Format("15:04:05"))
	_ = e.m.pg.InsertAutopilotEvent(t.ID, "deadline_extended", detail)
	e.emitActivity(t, db.Activity{Worker: "autopilot", Kind: "text", Summary: "Autopilot: " + detail})
	log.Printf("[autopilot] task %s %s", t.ID, detail)
	return true
}

// suppressAutopilotSettle decides whether a wrap-up reason should be suppressed by
// autopilot. Only 'no-progress' criteria are suppressed; goal_met / timeout (extensions
// exhausted) stand.
func suppressAutopilotSettle(t *Task, reason string) bool {
	if t == nil || !t.AutopilotEnabled() {
		return false
	}
	switch reason {
	case "auto_idle", "auto_coverage", "auto_rounds":
		// auto_rounds is the 'planner-round cap' cost ceiling. In relentless mode it
		// likewise must not wrap up — the user explicitly asked for no budget/cash-out
		// limit; only genuine exhaustion ends it.
		return true
	}
	return false
}
