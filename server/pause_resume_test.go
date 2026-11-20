package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

// 暂停后恢复必须重置看门狗基线，否则暂停时长会被算成「无进展」。
func TestResumeResetsAutopilotStallBaseline(t *testing.T) {
	e := &Engine{}
	e.autoTrack.Store("42", &autopilotTrack{
		lastProgressAt: time.Now().Add(-time.Hour),
		lastNudgeAt:    time.Now().Add(-time.Hour),
		nudges:         3,
	})
	task := &Task{ID: "42", notify: make(chan struct{}, 1)}
	e.Resume(task)
	if _, ok := e.autoTrack.Load("42"); ok {
		t.Fatal("Resume 后 autoTrack 基线未清除，暂停时长会被误判为停滞")
	}
}

// 恢复时按暂停时长顺延 deadline_at，并把 paused_at 清空。
func TestResumeExtendsDeadlineByPausedDuration(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	task, err := d.CreateTask("pause deadline test", "goal", nil, 600, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	oldDeadline := time.Now().Add(5 * time.Minute)
	if _, err := d.Exec(`UPDATE tasks SET status='running', first_run_at=now()-interval '10 minutes', deadline_at=$1 WHERE id=$2`,
		oldDeadline, task.ID); err != nil {
		t.Fatal(err)
	}
	m := &Manager{pg: d}
	if err := m.ApplyTaskPause(fmt.Sprint(task.ID)); err != nil {
		t.Fatal(err)
	}
	// 模拟已暂停 20 分钟
	if _, err := d.Exec(`UPDATE tasks SET paused_at=now()-interval '20 minutes' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyTaskAdmission(fmt.Sprint(task.ID), "running", "running", false, "resume", false); err != nil {
		t.Fatal(err)
	}

	var deadline time.Time
	var pausedAt *time.Time
	if err := d.QueryRow(`SELECT deadline_at, paused_at FROM tasks WHERE id=$1`, task.ID).Scan(&deadline, &pausedAt); err != nil {
		t.Fatal(err)
	}
	if pausedAt != nil {
		t.Fatal("恢复后 paused_at 应清空")
	}
	// 旧 deadline 5 分钟后；暂停 20 分钟应顺延到约 25 分钟后。
	if got := deadline.Sub(oldDeadline); got < 19*time.Minute {
		t.Fatalf("deadline 只顺延了 %v，期望约 20 分钟", got)
	}
}
