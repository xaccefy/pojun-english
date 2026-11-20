package agent

// Task-level background jobs (v0.7.0): job_start / job_status / job_output / job_stop.
//
// ## Why they exist
//
// Field diagnostics showed lots of deep-dives that 'vanished mid-way'; one root cause is the single-intent
// wall clock: long scans, brute-force, multi-step exploit chains must finish inside one intent — time out
// and it's declared dead; the next intent restarts from zero.
// The platform already has Bash backgrounding, but it's bound to a single run's session — once the run ends
// nobody watches the process, and there's no cross-intent 'job ledger'.
// This toolset lands jobs under tasks/<id>/shared/jobs/:
//   - <name>.sh    job script (writes back its exit code at the end)
//   - <name>.log   stdout+stderr
//   - <name>.json  metadata (pid/command/start time/originating intent)
//
// So: worker A starts a long brute-force → the run ending doesn't affect the process → any later intent uses job_status/
// job_output to pull results; the planner can poll jobs instead of re-dispatching new intents.
//
// ## Control
//
// job_start is equivalent to Bash (executes arbitrary commands) — registered in localExecToolNames; logs and scripts
// live inside the task dir, under the same audit trail.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// jobLifecycleMu 串行化「作业启动+登记」与「暂停/删除清理」。
//
// job_start 从开始启动到元数据落盘必须持读锁；KillJobsForTaskDir 持写锁。
// 没有这把锁时，清理会扫描不到「进程已启动、JSON 还没写」的作业，暂停后它
// 继续在后台打目标（issue #18）。锁是进程内全局的：job 启停频率很低，没必要
// 为每个任务目录维护一张锁表。
var jobLifecycleMu sync.RWMutex

// jobStartAfterStartHook 仅测试使用：进程已启动（带 PID）、元数据尚未落盘。生产恒为 nil。
var jobStartAfterStartHook func(pid int)

type jobMeta struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	PID      int    `json:"pid"`
	Started  string `json:"started"`
	Script   string `json:"script"`
	Log      string `json:"log"`
	RCFile   string `json:"rc_file"`
	Intent   int64  `json:"intent_id,omitempty"`
	OwnerEnd string `json:"owner_end,omitempty"`
}

func (t *ToolSet) jobsDir() string {
	dir := t.sharedDir()
	if dir == "" {
		return ""
	}
	j := filepath.Join(dir, "jobs")
	if err := os.MkdirAll(j, 0o755); err != nil {
		return ""
	}
	return j
}

func sanitizeJobName(name string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return -1
	}, strings.TrimSpace(name))
	if clean == "" || len(clean) > 64 {
		return ""
	}
	return clean
}

func readJobMeta(dir, name string) (jobMeta, bool) {
	var m jobMeta
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return m, false
	}
	if json.Unmarshal(b, &m) != nil {
		return m, false
	}
	return m, true
}

// jobState returns (state, exit code). States: running|finished|failed|unknown.
// jobState returns (state, exit code). States: running|finished|failed|unknown.
func jobState(m jobMeta) (string, int) {
	if b, err := os.ReadFile(m.RCFile); err == nil {
		code := -1
		// echo > rc is 'create/truncate then write': a poll can land right on the empty file. When the number
		// won't parse, don't call it failed (that would misreport a just-finished job) — fall back to liveness.
		if n, _ := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &code); n == 1 {
			if code == 0 {
				return "finished", 0
			}
			return "failed", code
		}
	}
	if m.PID > 0 {
		// A just-started wrapper process may not have exec'd yet — /proc cmdline still shows the parent's;
		// skip ownership checks inside the 5s startup window to avoid misjudging a new job as PID reuse.
		startedAt, startErr := time.Parse(time.RFC3339, m.Started)
		inStartup := startErr == nil && time.Since(startedAt) < 5*time.Second
		if !inStartup && !jobOwnsProcess(m) {
		// The PID was reused by the system: the metadata is residue from the previous run — not running,
		// and definitely not a process group to kill on task pause/delete.
			return "failed", -1
		}
		if alive, known := jobProcessAlive(m.PID); known && !alive {
		// On Windows there's a brief window between 'process exited' and 'rc file visible': a just-ended
		// job can't be reported failed immediately. Within 5s of start it's treated as running; only later as crashed.
			if started, err := time.Parse(time.RFC3339, m.Started); err == nil && time.Since(started) < 5*time.Second {
				return "running", -1
			}
			return "failed", -1 // process exited but left no rc (crash/killed externally)
		}
		return "running", -1
	}
	return "unknown", -1
}

func (t *ToolSet) jobStart() actool.CoreTool {
	return writeTool(
		"job_start",
		"Starts a long task in task-level background (long scan/brute-force/listener/multi-step exploit) — the process keeps "+
			"running after the run ends, and any later intent or the planner can pull results via job_status/job_output.\n"+
			"Jobs land in tasks/<id>/shared/jobs/: script, log, exit code. For actions exceeding one intent's budget; "+
			"one-shot short commands still use Bash.\n"+
			"Note: after starting, don't poll job_output in an empty spin — do other work first; check after a while or in a later intent.",
		obj(map[string]any{
			"name":    str("job name (alphanumeric -_; same name overwrites the old job)"),
			"command": str("bash command to run (work dir = task shared dir)"),
			"env":     str("extra env vars, 'K=V&K2=V2' (optional)"),
		}, "name", "command"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name    string `json:"name"`
				Command string `json:"command"`
				Env     string `json:"env"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeJobName(a.Name)
			if name == "" || name != strings.TrimSpace(a.Name) {
				return actool.Errorf("illegal name: only letters/digits/-/_ allowed (no path separators or dots)"), nil
			}
			if strings.TrimSpace(a.Command) == "" {
				return actool.Errorf("command must not be empty"), nil
			}
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("task shared dir unavailable (runDir not injected)"), nil
			}
			// Pause/delete cleanup (KillJobsForTaskDir) takes the write lock. "Start + persist metadata" is put
			// under the write lock as a whole: ① cleanup either finishes before the start (the ctx check then
			// refuses) or scans again after registration and kills it, so a job started mid-way is never missed;
			// ② same-name concurrent starts are serialized — under a read lock two same-name job_starts could both
			// read "no old job" and both start, the later meta write overwrote the first, and the earlier process
			// became an orphan cleanup couldn't find (audit F3). Job starts are rare, so serializing costs nothing.
			jobLifecycleMu.Lock()
			defer jobLifecycleMu.Unlock()
			if err := ctx.Err(); err != nil {
				return actool.Errorf("task paused or execution cancelled — refusing to start a background job"), nil
			}
			script := filepath.Join(dir, name+".sh")
			logPath := filepath.Join(dir, name+".log")
			rcPath := filepath.Join(dir, name+".rc")
			metaPath := filepath.Join(dir, name+".json")
			_ = os.Remove(rcPath)
			// Git Bash (dev machine) is unfriendly to backslash paths; scripts use forward slashes throughout.
			scriptEnv := filepath.ToSlash(script)
			rcEnv := filepath.ToSlash(rcPath)
			workEnv := filepath.ToSlash(filepath.Dir(dir))
			body := "#!/usr/bin/env bash\nset -uo pipefail\ncd " + shellQuote(workEnv) + "\n" +
				a.Command + "\nrc=$?\necho $rc > " + shellQuote(rcEnv) + "\nexit $rc\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				return actool.Errorf("failed to write the job script: " + err.Error()), nil
			}
			logEnv := filepath.ToSlash(logPath)
			// Header written separately; the child writes the log via shell redirection (doesn't depend on the parent
			// holding the handle — on Windows the parent closing it makes the child's later writes silently fail).
			if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				fmt.Fprintf(lf, "\n=== job %s start %s ===\n", name, time.Now().Format(time.RFC3339))
				_ = lf.Close()
			}
			// Same-named job rerun: stop the still-running old process group first — no two scans hitting the target at once.
			if old, ok := readJobMeta(dir, name); ok {
				if st, _ := jobState(old); st == "running" {
					_ = jobKillGroup(old.PID)
					jobWaitGone(old.PID, 2*time.Second)
				}
			}
			cmd := exec.Command(resolveBash(), "-c",
				`bash "$0" >> "$2" 2>&1; rc=$?; echo $rc > "$1"; exit $rc`,
				scriptEnv, rcEnv, logEnv)
			cmd.Dir = filepath.Dir(dir)
			// Separate process group: job_stop kills the whole group — inner scripts/children end together (no longer killing just the outer wrapper shell).
			cmd.SysProcAttr = jobSysProcAttr()
			// A background job must share the foreground Bash's egress: inherit the task egress proxy and
			// override any proxy variables left in the parent process (otherwise a long scan goes direct from
			// the real IP and leaves nothing in the MITM).
			env := mergeProxyEnv(os.Environ(), t.egressProxy, t.egressCA)
			for _, kv := range strings.Split(a.Env, "&") {
				k, v, ok := strings.Cut(kv, "=")
				if ok && strings.TrimSpace(k) != "" {
					env = append(env, strings.TrimSpace(k)+"="+v)
				}
			}
			cmd.Env = env
			if err := ctx.Err(); err != nil {
				return actool.Errorf("task paused or execution cancelled — refusing to start a background job"), nil
			}
			if err := cmd.Start(); err != nil {
				return actool.Errorf("failed to start the job: " + err.Error()), nil
			}
			if jobStartAfterStartHook != nil {
				jobStartAfterStartHook(cmd.Process.Pid)
			}
			pid := cmd.Process.Pid
			// Jobs outlive runs: reap via a background Wait — not Release. Release doesn't reap children;
			// each job would leave a zombie that, over long runs, fills the container pids limit (all subsequent execs fail).
			go func() { _ = cmd.Wait() }()
			m := jobMeta{
				Name: name, Command: a.Command, PID: pid,
				Started: time.Now().Format(time.RFC3339),
				Script:  script, Log: logPath, RCFile: rcPath,
				Intent: t.ownerNode,
			}
			b, err := json.MarshalIndent(m, "", "  ")
			if err == nil {
				err = os.WriteFile(metaPath, b, 0o644)
			}
			if err != nil {
				// With no metadata written the process never enters the job ledger and pause/delete can't find
				// it — kill the whole group at once, never leave an untrackable background process.
				_ = jobKillGroup(pid)
				jobWaitGone(pid, 2*time.Second)
				return actool.Errorf("failed to write job metadata (process terminated): " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"name":   name,
				"pid":    pid,
				"log":    logPath,
				"script": script,
				"note":   "job is running in the background. Check it with job_status/job_output; don't poll in a spin — do other work first.",
			})
		},
	)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// resolveBash picks a usable bash. On Windows, PATH often hits System32\bash.exe first
// (the WSL launcher — can't see C:/ local paths), so prefer Git for Windows' bash.
func resolveBash() string {
	if runtime.GOOS == "windows" {
		for _, p := range []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
		} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return "bash"
}

func (t *ToolSet) jobStatus() actool.CoreTool {
	return readTool(
		"job_status",
		"Views background job status (running/finished/failed + exit code + log tail). Omit name to list all jobs; "+
			"pass name to see one job's recent output.",
		obj(map[string]any{
			"name":       str("job name (optional; omitted = list all)"),
			"tail_lines": intp("log tail line count for a single job, default 40, max 400"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name      string `json:"name"`
				TailLines int    `json:"tail_lines"`
			}
			_ = json.Unmarshal(in, &a)
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("task shared dir unavailable (runDir not injected)"), nil
			}
			if strings.TrimSpace(a.Name) != "" {
				name := sanitizeJobName(a.Name)
				if name == "" {
					return actool.Errorf("illegal name"), nil
				}
				m, ok := readJobMeta(dir, name)
				if !ok {
					return actool.Errorf("job does not exist: " + name), nil
				}
				state, code := jobState(m)
				tail := a.TailLines
				if tail <= 0 {
					tail = 40
				}
				if tail > 400 {
					tail = 400
				}
				out := map[string]any{
					"name": name, "state": state, "exit_code": code,
					"pid": m.PID, "started": m.Started, "log": m.Log,
					"tail": tailLines(m.Log, tail),
				}
				if st, err := os.Stat(m.Log); err == nil {
					out["log_bytes"] = st.Size()
				}
				return jsonResult(out)
			}
			// List all
			entries, _ := os.ReadDir(dir)
			jobs := []map[string]any{}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				name := strings.TrimSuffix(e.Name(), ".json")
				m, ok := readJobMeta(dir, name)
				if !ok {
					continue
				}
				state, code := jobState(m)
				item := map[string]any{"name": name, "state": state, "exit_code": code, "started": m.Started}
				if st, err := os.Stat(m.Log); err == nil {
					item["log_bytes"] = st.Size()
					item["log_mtime"] = st.ModTime().Format(time.RFC3339)
				}
				jobs = append(jobs, item)
			}
			return jsonResult(map[string]any{"count": len(jobs), "jobs": jobs,
				"note": "running jobs survive across intents; for failed ones use job_output to find the cause."})
		},
	)
}

// jobLogLineMax is the per-line retention cap. Long scans can emit super-long single lines (progress bars /
// base64); reading whole lines into memory would drag the process down — oversized tails get truncated and marked.
const jobLogLineMax = 4 << 10

// readLogLine reads one line; any tail beyond jobLogLineMax is dropped (IO still consumed, so line numbers stay right).
func readLogLine(r *bufio.Reader) (string, bool, error) {
	var sb strings.Builder
	truncated := false
	for {
		frag, err := r.ReadSlice('\n')
		if sb.Len() < jobLogLineMax {
			room := jobLogLineMax - sb.Len()
			if len(frag) > room {
				sb.Write(frag[:room])
				truncated = true
			} else {
				sb.Write(frag)
			}
		} else if len(frag) > 0 {
			truncated = true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		line := strings.TrimRight(sb.String(), "\r\n")
		if truncated {
			line += " …(line too long, truncated)"
		}
		if err == io.EOF {
			if line == "" {
				return "", false, io.EOF
			}
			return line, true, nil
		}
		if err != nil {
			return line, line != "", err
		}
		return line, true, nil
	}
}

// readJobLog returns the log's [offset, offset+limit) line window plus the total line count.
//
// offset == 0 means 'read the last limit lines': a ring buffer keeps only the final limit lines,
// so memory doesn't grow with log size (the old impl read the whole file — multi-GB scan logs OOM'd outright).
func readJobLog(path string, offset, limit int) (window []string, total int, err error) {
	if limit <= 0 {
		limit = 1 // the ring buffer uses modulo — 0 would panic
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	if offset <= 0 {
		ring := make([]string, limit)
		filled, pos := 0, 0
		for {
			line, ok, rerr := readLogLine(r)
			if ok {
				ring[pos] = line
				pos = (pos + 1) % limit
				if filled < limit {
					filled++
				}
				total++
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return nil, total, rerr
			}
		}
		out := make([]string, 0, filled)
		for i := 0; i < filled; i++ {
			out = append(out, ring[(pos-filled+i+limit)%limit])
		}
		return out, total, nil
	}
	for {
		line, ok, rerr := readLogLine(r)
		if ok {
			if total >= offset && len(window) < limit {
				window = append(window, line)
			}
			total++
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return window, total, rerr
		}
	}
	return window, total, nil
}

func tailLines(path string, n int) string {
	lines, _, err := readJobLog(path, 0, n)
	if err != nil {
		return ""
	}
	return strings.Join(lines, "\n")
}

func (t *ToolSet) jobOutput() actool.CoreTool {
	return readTool(
		"job_output",
		"Reads a background job's log (default tail 200 lines). Page with offset/lines for big logs; the complete log itself "+
			"lives at tasks/<id>/shared/jobs/<name>.log — Bash can grep it.",
		obj(map[string]any{
			"name":   str("job name"),
			"lines":  intp("lines to return, default 200, max 1000"),
			"offset": intp("start line (0-based) for paging; omitted = read tail"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name   string `json:"name"`
				Lines  int    `json:"lines"`
				Offset int    `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeJobName(a.Name)
			if name == "" {
				return actool.Errorf("illegal name"), nil
			}
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("task shared dir unavailable (runDir not injected)"), nil
			}
			m, ok := readJobMeta(dir, name)
			if !ok {
				return actool.Errorf("job does not exist: " + name), nil
			}
			lines := a.Lines
			if lines <= 0 {
				lines = 200
			}
			if lines > 1000 {
				lines = 1000
			}
			start := a.Offset
			if start < 0 {
				start = 0
			}
			window, total, err := readJobLog(m.Log, start, lines)
			if err != nil {
				return actool.Errorf("failed to read the log: " + err.Error()), nil
			}
			from := start
			if start == 0 && len(window) < total {
				from = total - len(window) // offset=0 means 'read the tail' — derive the start from the actual window
			}
			if from > total {
				from = total
			}
			end := from + len(window)
			state, code := jobState(m)
			res := map[string]any{
				"name": name, "state": state, "exit_code": code,
				"total_lines": total, "from_line": from, "to_line": end,
				"output": strings.Join(window, "\n"),
			}
			if end < total {
				res["next_offset"] = end
			}
			return jsonResult(res)
		})
}

func (t *ToolSet) jobStop() actool.CoreTool {
	return writeTool(
		"job_stop",
		"Stops a background job (SIGKILL) and reads back the exit code. No-op when the job already finished.",
		obj(map[string]any{
			"name": str("job name"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeJobName(a.Name)
			if name == "" {
				return actool.Errorf("illegal name"), nil
			}
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("task shared dir unavailable (runDir not injected)"), nil
			}
			m, ok := readJobMeta(dir, name)
			if !ok {
				return actool.Errorf("job does not exist: " + name), nil
			}
			state, code := jobState(m)
			stopped := false
			if state == "running" && m.PID > 0 {
				if err := jobKillGroup(m.PID); err == nil {
					stopped = true
					// SIGKILL is async: wait for the process to truly exit before returning — otherwise callers (tests, pause/delete
					// cleanup) checking process state right after would see residue and misjudge 'not killed'.
					jobWaitGone(m.PID, 2*time.Second)
					// The outer wrapper was killed too, so rc won't be written; patch in a 137 (SIGKILL) marker —
					// otherwise jobState shows running forever because PID>0.
					_ = os.WriteFile(m.RCFile, []byte("137"), 0o644)
					code = 137
				}
			}
			return jsonResult(map[string]any{
				"name": name, "stopped": stopped, "state_before": state, "exit_code": code,
				"note": "the entire process group was stopped (script plus its children).",
			})
		},
	)
}
