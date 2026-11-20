package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 审计 F3：job_start 的「读旧→杀旧→启动→登记」在写锁下必须串行化——
// 否则同名并发启动会让先启动的进程脱离台账，暂停/删除杀不到。
func TestJobStartSameNameConcurrentNoOrphan(t *testing.T) {
	taskDir := filepath.Join(t.TempDir(), "tasks", "1")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := &ToolSet{runDir: taskDir, ownerNode: 1}

	var mu sync.Mutex
	var pids []int
	jobStartAfterStartHook = func(pid int) {
		mu.Lock()
		pids = append(pids, pid)
		mu.Unlock()
	}
	defer func() { jobStartAfterStartHook = nil }()

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ts.jobStart().Call(context.Background(), json.RawMessage(
				`{"name":"conc","command":"sleep 30"}`), nil)
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(pids) != n {
		t.Fatalf("应有 %d 个启动事件，实际 %d", n, len(pids))
	}
	jobsDir := filepath.Join(taskDir, "shared", "jobs")
	m, ok := readJobMeta(jobsDir, "conc")
	if !ok {
		t.Fatal("最终 meta 缺失")
	}
	// 序列化 + 同名杀旧：除最后一个外，其余进程都应已被后续启动杀掉。
	orphans := 0
	for _, pid := range pids[:len(pids)-1] {
		if alive, known := jobProcessAlive(pid); known && alive {
			orphans++
			_ = jobKillGroup(pid)
		}
	}
	if orphans > 0 {
		t.Fatalf("发现 %d 个孤儿进程：同名并发启动未被串行化/杀旧", orphans)
	}
	if alive, known := jobProcessAlive(m.PID); known && !alive {
		t.Fatalf("最终作业 pid=%d 应存活（供 job_status/输出使用）", m.PID)
	}
	// 清理：最终作业也要杀掉，不能留在测试机
	_ = jobKillGroup(m.PID)
	jobWaitGone(m.PID, 3*time.Second)
	if b, err := os.ReadFile(filepath.Join(jobsDir, "conc.log")); err == nil {
		_ = strings.TrimSpace(string(b)) // 日志留档由测试框架临时目录兜底
	}
}
