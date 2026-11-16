package db

import (
	"database/sql"
	"errors"
	"time"
)

// Persistence layer for autopilot: the switch, the deadline auto-extension counter, and the event audit trail.
// See docs/autonomous-progression.md / the planning file for the design. Only plain SQL lives here; the decision logic is in server/autopilot.go.

// AutopilotTaskState holds every signal one watchdog scan needs (a single query, avoiding N x 3 round trips).
type AutopilotTaskState struct {
	TaskID         string
	IdleRounds     int
	LastRoundAt    time.Time // time of the most recent planning round in task_progress; when there is no row = the task creation time
	Facts          int64
	Findings       int64
	Assets         int64 // number of assets linked to the task (the watchdog uses "new assets/new findings" rather than a raw fact count to judge progress)
	GoalsTotal     int
	GoalsMet       int
	OpenIntents    int
	RunningIntents int
}

// Unmet means not all goals are met yet; total=0 counts as unmet (there are no goals yet, so it cannot be complete).
func (s AutopilotTaskState) Unmet() bool { return s.GoalsMet < s.GoalsTotal || s.GoalsTotal == 0 }

// AutopilotTaskStates scans every "autopilot in progress" task. It only returns tasks that carry the autopilot flag, are
// running, are not paused or queued, and are not deleted -- consistent with the watchdog candidate conditions.
func (d *DB) AutopilotTaskStates() (map[string]AutopilotTaskState, error) {
	rows, err := d.Query(`
SELECT t.id::text,
       COALESCE(p.idle_rounds,0),
       COALESCE(p.updated_at, t.created_at),
       COALESCE(p.fact_count,0),
       COALESCE(p.finding_count,0),
       COALESCE(a.cnt,0),
       COALESCE(g.total,0), COALESCE(g.met,0),
       COALESCE(i.open,0), COALESCE(i.running,0)
FROM tasks t
LEFT JOIN task_progress p ON p.task_id = t.id::text
LEFT JOIN LATERAL (
    SELECT count(*) AS cnt FROM task_asset_links l WHERE l.task_id = t.id
) a ON true
LEFT JOIN LATERAL (
    SELECT count(*) AS total, count(*) FILTER (WHERE n.state='met') AS met
    FROM exploration_nodes n
    WHERE n.exploration_id = t.exploration_id AND n.kind='goal'
) g ON true
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE n.state='open')    AS open,
           count(*) FILTER (WHERE n.state='running') AS running
    FROM exploration_nodes n
    WHERE n.exploration_id = t.exploration_id AND n.kind='intent'
) i ON true
WHERE t.deleted_at IS NULL AND t.autopilot
  AND t.status='running' AND NOT t.paused AND NOT t.queued`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AutopilotTaskState{}
	for rows.Next() {
		var s AutopilotTaskState
		if err := rows.Scan(&s.TaskID, &s.IdleRounds, &s.LastRoundAt, &s.Facts, &s.Findings, &s.Assets,
			&s.GoalsTotal, &s.GoalsMet, &s.OpenIntents, &s.RunningIntents); err != nil {
			return nil, err
		}
		out[s.TaskID] = s
	}
	return out, rows.Err()
}

// SetTaskAutopilot persists a single task's switch.
func (d *DB) SetTaskAutopilot(id int64, on bool) error {
	res, err := d.Exec(`UPDATE tasks SET autopilot=$2 WHERE id=$1 AND deleted_at IS NULL`, id, on)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ExtendTaskDeadline, guarded by "still running, not paused, autopilot, extensions not exhausted", pushes the deadline back
// by seconds and increments the counter. Returns the new deadline, the number used and whether it succeeded.
//
// A single guarded UPDATE rather than read-then-write: after a restart the old and new coordinators may expire at the same
// time, and only one can succeed, so the same task is not extended twice.
func (d *DB) ExtendTaskDeadline(id int64, seconds int, maxExtensions int) (time.Time, int, bool, error) {
	if seconds <= 0 || maxExtensions <= 0 {
		return time.Time{}, 0, false, nil
	}
	var deadline time.Time
	var used int
	// GREATEST(deadline_at, now()): only add on top of the original deadline, never reset a remaining
	// 30-minute budget to now+15. The old implementation used now()+ext, and the worker's TaskClock is
	// snapshotted at run start, so a reset deadline cut long chains short prematurely (measured as many "run timed out").
	err := d.QueryRow(`
UPDATE tasks
SET deadline_at = GREATEST(deadline_at, now()) + make_interval(secs => $2::double precision),
    autopilot_extensions = autopilot_extensions + 1
WHERE id=$1 AND deleted_at IS NULL AND status='running' AND NOT paused
  AND autopilot AND autopilot_extensions < $3
RETURNING deadline_at, autopilot_extensions`, id, float64(seconds), maxExtensions).Scan(&deadline, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, 0, false, nil
	}
	if err != nil {
		return time.Time{}, 0, false, err
	}
	return deadline, used, true, nil
}

// AutopilotEvent is the audit trail of autopilot decisions (for the task detail page / troubleshooting).
type AutopilotEvent struct {
	ID        int64     `json:"id"`
	TaskID    string    `json:"task_id"`
	Kind      string    `json:"kind"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// InsertAutopilotEvent writes one event. A failure does not block the main flow (the caller only logs it).
func (d *DB) InsertAutopilotEvent(taskID, kind, detail string) error {
	_, err := d.Exec(`INSERT INTO autopilot_events(task_id,kind,detail) VALUES($1,$2,$3)`,
		taskID, kind, detail)
	return err
}

// ListAutopilotEvents reads a task's events newest first.
func (d *DB) ListAutopilotEvents(taskID string, limit int) ([]AutopilotEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`SELECT id, task_id, kind, detail, created_at
FROM autopilot_events WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AutopilotEvent
	for rows.Next() {
		var e AutopilotEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.Kind, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteAutopilotEvents cleans up when a task is hard-deleted.
func (d *DB) DeleteAutopilotEvents(taskID string) error {
	_, err := d.Exec(`DELETE FROM autopilot_events WHERE task_id=$1`, taskID)
	return err
}
