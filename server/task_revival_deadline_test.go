package server

import (
	"testing"
	"time"
)

// TestTerminalRevivalResetsDeadline is the regression test for the task-13 (2026-11-05)
// incident:
//
// Repro: the task went done on 11-04 ('all goals met'), but first_run_at/deadline_at
// stayed on 11-04's 8-hour budget; on 11-05 a human submitted a 'dig into the vuln'
// follow-up intent → admitTask revived done back to running, but the old code only reset
// clocks for timeout revivals → the revived coordinator read the expired deadline and
// wrapped up again 1 second later (final round: 'generate no new intents') — the manual
// intent was silently swallowed and the task ended in timeout.
//
// After the fix: any terminal state (done/failed/timeout) revival zeroes
// first_run_at/deadline_at, clears the Engine per-run gates
// (settling/deadline/stamped/coordStarted) and leftover pending wrap-up requests; the
// next real run stamps a fresh budget.
func TestTerminalRevivalResetsDeadline(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	defer restoreConcurrencySetting(t, m)()
	// disable concurrency limits: revival starts immediately, no FIFO (this test only
	// cares about clock/gate resets).
	if err := m.SetConcurrency(false, 0); err != nil {
		t.Fatal(err)
	}

	task, err := m.CreateTask("terminal revival deadline regression", "follow-up must get a fresh budget", nil, 3600, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	// reproduce the pre-incident scene: task already ran (stamped), went done with all
	// goals met, and the deadline already expired.
	if _, err := m.StampTaskFirstRun(task.ID); err != nil {
		t.Fatalf("initial stamp: %v", err)
	}
	// go terminal via the real path (DB + memory sync), then overwrite clocks with
	// expired values.
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatalf("mark done: %v", err)
	}
	expiredFirst := time.Now().Add(-26 * time.Hour)
	expiredDeadline := time.Now().Add(-18 * time.Hour)
	if _, err := m.pg.Exec(
		`UPDATE tasks SET first_run_at=$2, deadline_at=$3 WHERE id=$1`,
		task.ID, expiredFirst, expiredDeadline); err != nil {
		t.Fatalf("seed expired clocks: %v", err)
	}

	// leftover state from the old round in Engine memory: deadline map, first stamp,
	// coordinator marker, pending wrap-up request — on the incident day all four made
	// the revival wrap up again immediately.
	s := newAdmissionTestServer(m, nil)
	s.engine.deadline.Store(task.ID, expiredDeadline.Unix())
	s.engine.stamped.Store(task.ID, true)
	s.engine.coordStarted.Store(task.ID, true)
	s.engine.settling.Store(task.ID, true)
	task.requestSettle("auto_idle", "stale settle from the previous life")

	// go through the same entry the UI's 'dig into the vuln' uses: admitTask(resume).
	queued, err := s.admitTask(task, "resume")
	if err != nil {
		t.Fatalf("admit revived task: %v", err)
	}
	if queued {
		t.Fatal("revived task should start immediately with concurrency disabled")
	}

	// DB: both clocks must be zeroed and the state running.
	var status string
	var firstNull, deadlineNull bool
	if err := m.pg.QueryRow(
		`SELECT status, first_run_at IS NULL, deadline_at IS NULL FROM tasks WHERE id=$1`,
		task.ID).Scan(&status, &firstNull, &deadlineNull); err != nil {
		t.Fatalf("read back task: %v", err)
	}
	if status != "running" {
		t.Fatalf("status = %q, want running", status)
	}
	if !firstNull || !deadlineNull {
		t.Fatalf("terminal revival must clear clocks: first_run_at null=%v deadline_at null=%v", firstNull, deadlineNull)
	}

	// memory sync: the deadline coordinator reads lifecycleSnapshot — must be zeroed in
	// step.
	state := task.lifecycleSnapshot()
	if state.Status != "running" {
		t.Fatalf("memory status = %q, want running", state.Status)
	}
	if state.FirstRunAt != 0 || state.DeadlineAt != 0 {
		t.Fatalf("memory clocks not reset: FirstRunAt=%d DeadlineAt=%d", state.FirstRunAt, state.DeadlineAt)
	}

	// Engine gates: all four leftovers cleared, else the revived task wedges on the old
	// deadline/settling.
	if s.engine.isSettling(task.ID) {
		t.Fatal("revival retained the stale settling gate")
	}
	if _, ok := s.engine.deadline.Load(task.ID); ok {
		t.Fatal("revival retained the stale in-memory deadline")
	}
	if _, ok := s.engine.stamped.Load(task.ID); ok {
		t.Fatal("revival retained the stale first-run stamp")
	}
	// new planning/execution re-registers the coordinator; here we only ensure the old
	// marker is gone.
	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("revival retained stale pending settle %q", reason)
	}

	// re-stamping should yield a fresh 'from now' budget, not the old deadline.
	dl, err := m.StampTaskFirstRun(task.ID)
	if err != nil {
		t.Fatalf("re-stamp first run: %v", err)
	}
	if dl <= 0 {
		t.Fatal("stamp returned no deadline for a task with timeout_seconds=3600")
	}
	if dl < time.Now().Add(50*time.Minute).Unix() {
		t.Fatalf("fresh deadline %d looks stale (expected ≈ now+1h)", dl)
	}
}
