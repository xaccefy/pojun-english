//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const createNewProcessGroup = 0x00000200

func jobSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

// jobKillGroup uses taskkill /T to kill the whole process tree (outer bash + inner script/children).
func jobKillGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
}

// jobOwnsProcess: Windows has no lightweight argv read (QueryFullProcessImageName only gives the
// executable path — can't distinguish jobs sharing bash.exe), so keep the old PID-based liveness check.
// Linux is the production main battlefield; Windows reruns/task cleanup can still hit PID reuse.
func jobOwnsProcess(m jobMeta) bool { return m.PID > 0 }

// jobWaitGone waits for taskkill to actually take effect: after taskkill returns the process handle may
// not be fully released — an immediate tasklist assert occasionally sees residue.
func jobWaitGone(pid int, timeout time.Duration) {
	if pid <= 0 {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if alive, known := jobProcessAlive(pid); known && !alive {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func jobProcessAlive(pid int) (alive bool, known bool) {
	if pid <= 0 {
		return false, true
	}
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return true, false
	}
	return strings.Contains(string(out), strconv.Itoa(pid)), true
}
