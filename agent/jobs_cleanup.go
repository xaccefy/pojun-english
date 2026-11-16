package agent

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KillJobsForTaskDir kills still-running background jobs under a task dir (called on task pause/delete/terminal).
//
// Job processes start in their own process group and surviving across runs is by design; but once a task
// pauses/ends, continuing to hit the target exceeds the authorization window — and after the task dir is
// deleted the rc/log paths vanish, leaving ownerless processes. Returns the count of killed jobs. Unreadable
// dirs/metadata are skipped silently (cleanup is best-effort).
func KillJobsForTaskDir(taskDir string) int {
	if strings.TrimSpace(taskDir) == "" {
		return 0
	}
	jobsDir := filepath.Join(taskDir, "shared", "jobs")
	entries, err := os.ReadDir(jobsDir)
	if err != nil {
		return 0
	}
	killed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		m, ok := readJobMeta(jobsDir, name)
		if !ok {
			continue
		}
		if st, _ := jobState(m); st != "running" || m.PID <= 0 {
			continue
		}
		if err := jobKillGroup(m.PID); err != nil {
			continue
		}
		jobWaitGone(m.PID, 2*time.Second)
		_ = os.WriteFile(m.RCFile, []byte("137"), 0o644)
		killed++
	}
	return killed
}
