package db

import (
	"database/sql"
	"errors"
	"time"
)

// TaskProgress is a task's auto-close progress snapshot (v0.5.0). The engine records one per regular planning
// round; when idle_rounds of consecutive zero growth reaches the threshold and the frontier is drained, the task auto-closes.
type TaskProgress struct {
	TaskID       string    `json:"task_id"`
	RoundNo      int64     `json:"round_no"`
	IdleRounds   int       `json:"idle_rounds"`
	FactCount    int64     `json:"fact_count"`
	FindingCount int64     `json:"finding_count"`
	TestedCount  int64     `json:"tested_count"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RecordTaskProgress records one round of progress. round must be monotonically increasing: a late old round (round <=
// the recorded value) returns the current idle immediately without double counting. Any counter growth -> idle resets to zero; otherwise +1.
func (d *DB) RecordTaskProgress(taskID string, round, facts, findings, tested int64) (int, error) {
	var idle int
	err := d.QueryRow(`
INSERT INTO task_progress(task_id,round_no,idle_rounds,fact_count,finding_count,tested_count,updated_at)
VALUES($1,$2,0,$3,$4,$5,now())
ON CONFLICT (task_id) DO UPDATE SET
    idle_rounds = CASE
        WHEN EXCLUDED.round_no <= task_progress.round_no THEN task_progress.idle_rounds
        WHEN EXCLUDED.fact_count    > task_progress.fact_count
          OR EXCLUDED.finding_count > task_progress.finding_count
          OR EXCLUDED.tested_count  > task_progress.tested_count THEN 0
        ELSE task_progress.idle_rounds + 1
    END,
    fact_count = CASE
        WHEN EXCLUDED.round_no > task_progress.round_no
        THEN GREATEST(task_progress.fact_count, EXCLUDED.fact_count)
        ELSE task_progress.fact_count END,
    finding_count = CASE
        WHEN EXCLUDED.round_no > task_progress.round_no
        THEN GREATEST(task_progress.finding_count, EXCLUDED.finding_count)
        ELSE task_progress.finding_count END,
    tested_count = CASE
        WHEN EXCLUDED.round_no > task_progress.round_no
        THEN GREATEST(task_progress.tested_count, EXCLUDED.tested_count)
        ELSE task_progress.tested_count END,
    round_no = GREATEST(task_progress.round_no, EXCLUDED.round_no),
    updated_at = now()
RETURNING idle_rounds`, taskID, round, facts, findings, tested).Scan(&idle)
	return idle, err
}

// GetTaskProgress reads the progress snapshot (returns nil, nil when absent).
func (d *DB) GetTaskProgress(taskID string) (*TaskProgress, error) {
	var p TaskProgress
	err := d.QueryRow(`
SELECT task_id,round_no,idle_rounds,fact_count,finding_count,tested_count,updated_at
FROM task_progress WHERE task_id=$1`, taskID).
		Scan(&p.TaskID, &p.RoundNo, &p.IdleRounds, &p.FactCount, &p.FindingCount, &p.TestedCount, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

// ResetTaskProgress zeroes idle (called on new goals/hints or when a task is revived). The counter baseline is kept, so
// even with no growth the next round only re-accumulates from 0.
func (d *DB) ResetTaskProgress(taskID string) error {
	_, err := d.Exec(`UPDATE task_progress SET idle_rounds=0, updated_at=now() WHERE task_id=$1`, taskID)
	return err
}

// DeleteTaskProgress cleans up when a task is deleted.
func (d *DB) DeleteTaskProgress(taskID string) error {
	_, err := d.Exec(`DELETE FROM task_progress WHERE task_id=$1`, taskID)
	return err
}

// CountExplorationProgress counts a given exploration graph's facts/findings exactly (without the list cap).
func (d *DB) CountExplorationProgress(expID int64) (facts, findings int64, err error) {
	err = d.QueryRow(`
SELECT COUNT(*) FILTER (WHERE kind='fact'), COUNT(*) FILTER (WHERE kind='finding')
FROM exploration_nodes WHERE exploration_id=$1`, expID).Scan(&facts, &findings)
	return
}

// ResetPlannerRoundForRevival zeroes a task's planning round number (for reviving a terminal task).
// The in-memory plannerRound is already cleared on revival; if task_progress.round_no still holds the previous life's value
// (e.g. 80), RecordTaskProgress's round_no<=old guard would leave idle_rounds stuck at 0 and
// auto_idle/auto_coverage would silently fail for a revived task for a whole old budget period.
func (d *DB) ResetPlannerRoundForRevival(taskID string) error {
	_, err := d.Exec(`UPDATE task_progress SET round_no = 0 WHERE task_id = $1`, taskID)
	return err
}
