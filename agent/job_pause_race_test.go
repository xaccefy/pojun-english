package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 暂停清理必须等待在途 job_start 完成登记，然后把它杀掉（issue #18）。
func TestPauseCleanupWaitsForInFlightJobStart(t *testing.T) {
	base := t.TempDir()
	taskDir := filepath.Join(base, "tasks", "1")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := &ToolSet{runDir: taskDir, ownerNode: 1}

	launched := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	jobStartAfterStartHook = func(_ int) {
		once.Do(func() { close(launched) })
		<-release
	}
	defer func() { jobStartAfterStartHook = nil }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := ts.jobStart().Call(ctx,
			json.RawMessage(`{"name":"race","command":"sleep 20"}`), nil)
		done <- err
	}()

	<-launched
	cancel() // 暂停：取消执行上下文

	cleanDone := make(chan int, 1)
	go func() { cleanDone <- KillJobsForTaskDir(taskDir) }()

	// 在途 job_start 还没登记完成，清理必须被生命周期写锁挡住。
	select {
	case n := <-cleanDone:
		t.Fatalf("清理在 job_start 登记完成前就返回了 killed=%d", n)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("job_start: %v", err)
	}
	select {
	case n := <-cleanDone:
		if n != 1 {
			t.Fatalf("清理应杀掉刚登记的作业，killed=%d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("清理在 job_start 返回后仍未完成")
	}

	jobsDir := filepath.Join(taskDir, "shared", "jobs")
	m, ok := readJobMeta(jobsDir, "race")
	if !ok {
		t.Fatal("作业元数据缺失")
	}
	if alive, known := jobProcessAlive(m.PID); known && alive {
		_ = jobKillGroup(m.PID)
		t.Fatalf("RACE: 作业 pid=%d 在暂停清理后仍存活", m.PID)
	}
}

// 上下文已取消时直接拒绝启动作业，不留下脚本/进程。
func TestJobStartRejectsCanceledContext(t *testing.T) {
	taskDir := filepath.Join(t.TempDir(), "tasks", "1")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := &ToolSet{runDir: taskDir, ownerNode: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := ts.jobStart().Call(ctx,
		json.RawMessage(`{"name":"canceled","command":"sleep 20"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Flatten() == "" {
		t.Fatal("取消上下文的 job_start 应返回明确错误")
	}
	if _, err := os.Stat(filepath.Join(taskDir, "shared", "jobs", "canceled.json")); !os.IsNotExist(err) {
		t.Fatal("取消上下文后不应登记作业")
	}
}
