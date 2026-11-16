//go:build !windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// jobSysProcAttr makes the job process its own process group: job_stop kills the whole group — inner
// scripts/children die too, instead of only killing the outer wrapper shell (leaving scanners hitting the target).
func jobSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func jobKillGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

// jobOwnsProcess checks whether PID is still this job's wrapper process.
//
// Job metadata survives restarts and PIDs get reused by the system (especially after server restart/crash);
// judging liveness by kill(pid,0) alone could treat an unrelated process as ours — pausing/deleting a task
// could even kill someone else's process group. The wrapper command's argv carries this job's unique rc path:
// a cmdline without it isn't our process. When cmdline is unreadable (perms/platform) return true — old
// behavior, better inaction than a mis-kill.
func jobOwnsProcess(m jobMeta) bool {
	if m.PID <= 0 || m.RCFile == "" {
		return m.PID > 0
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", m.PID)); err == nil {
		return strings.Contains(string(b), m.RCFile)
	}
	// Platforms without /proc (e.g. macOS) fall back to ps.
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(m.PID)).Output()
	if err != nil {
		return true
	}
	return strings.Contains(string(out), m.RCFile)
}

// jobWaitGone waits for the target to truly disappear after SIGKILL (max timeout).
// kill(2) only queues the signal — the target may not be scheduled out yet; asserting death right after on CI
// fails spuriously inside that window. Until cmd.Wait reaps it the process is a zombie and kill(pid,0) still
// succeeds — must poll to ESRCH rather than returning immediately after kill.
func jobWaitGone(pid int, timeout time.Duration) {
	if pid <= 0 {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if alive, known := jobProcessAlive(pid); known && !alive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// jobProcessAlive: known=false means the platform can't judge reliably (caller treats by pid>0).
func jobProcessAlive(pid int) (alive bool, known bool) {
	if pid <= 0 {
		return false, true
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM, true
}
