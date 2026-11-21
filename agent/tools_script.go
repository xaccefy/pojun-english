package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// Task-level shared script dir (v0.7.0): tasks/<id>/shared/scripts.
// Each intent's runDir is tasks/<id>/i<intent> — the next intent can't see scripts the previous one wrote;
// PoC/login scripts couldn't be reused. Scripts go to task-level shared: readable/executable across intents.
func (t *ToolSet) sharedDir() string {
	if t.runDir == "" {
		return ""
	}
	root := filepath.Dir(t.runDir)
	if filepath.Base(root) == "tasks" {
		// planner/mainagent get the task dir tasks/<id> injected (no i<intent> layer);
		// taking Dir directly would land on global tasks/ — invisible to worker jobs, and tasks would cross-talk.
		root = t.runDir
	}
	if filepath.Base(root) == "shared" {
		root = filepath.Dir(root)
	}
	dir := filepath.Join(root, "shared")
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		return ""
	}
	return dir
}

func sanitizeScriptName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "/")
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		}
		return -1
	}, name)
	if clean == "" || clean == "." || clean == ".." || len(clean) > 120 {
		return ""
	}
	return clean
}

// saveScript writes a script/PoC into task-level shared/scripts for later intents to reuse.
func (t *ToolSet) saveScript() actool.CoreTool {
	return writeTool("save_script",
		"Writes a script/PoC into the task-level shared dir (tasks/<id>/shared/scripts) — later intents can reuse it via run_script directly. "+
			"Good for: login scripts, signature/encryption restoration, batch probing, exploit PoCs, data parsing. The script text lands on disk and the path is returned.",
		obj(map[string]any{
			"name":    str("filename (alphanumeric -_.; .sh/.py auto-appended by lang when extensionless)"),
			"content": str("script body (≤256KB). May contain placeholders; never hardcode credentials into scripts"),
			"lang":    str("bash|python, default bash"),
		}, "name", "content"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name    string `json:"name"`
				Content string `json:"content"`
				Lang    string `json:"lang"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeScriptName(a.Name)
			if name == "" {
				return actool.Errorf("illegal name: only letters/digits/-/_/. allowed, no path separators"), nil
			}
			if strings.TrimSpace(a.Content) == "" {
				return actool.Errorf("content must not be empty"), nil
			}
			if len(a.Content) > 256<<10 {
				return actool.Errorf("script exceeds 256KB — split it or read data files from the work dir instead"), nil
			}
			lang := strings.ToLower(strings.TrimSpace(a.Lang))
			if lang == "" {
				lang = "bash"
			}
			ext := strings.ToLower(filepath.Ext(name))
			switch {
			case lang == "python" || lang == "py":
				if ext == "" {
					name += ".py"
				}
				if !strings.HasPrefix(a.Content, "#!") {
					a.Content = "#!/usr/bin/env python3\n" + a.Content
				}
			default:
				if ext == "" {
					name += ".sh"
				}
				if !strings.HasPrefix(a.Content, "#!") {
					a.Content = "#!/usr/bin/env bash\nset -uo pipefail\n" + a.Content
				}
			}
			dir := t.sharedDir()
			if dir == "" {
				return actool.Errorf("task shared dir unavailable (runDir not injected)"), nil
			}
			path := filepath.Join(dir, "scripts", name)
			if err := os.WriteFile(path, []byte(a.Content), 0o755); err != nil {
				return actool.Errorf("failed to write the script: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"path": path,
				"name": name,
				"note": "script landed in the task shared dir — any later intent can run it via run_script; cite the relative path in reports.",
			})
		})
}

func scriptInterpreter(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	header, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	if strings.HasPrefix(header, "#!") {
		interpreter := strings.TrimSpace(strings.TrimPrefix(header, "#!"))
		if split := strings.IndexAny(interpreter, " \t"); split >= 0 {
			// The shebang's optional argument is passed as one argument, including env -S.
			return []string{interpreter[:split], strings.TrimSpace(interpreter[split:])}, nil
		}
		if interpreter != "" {
			return []string{interpreter}, nil
		}
	}
	if strings.EqualFold(filepath.Ext(path), ".py") {
		return []string{"python3"}, nil
	}
	return []string{"bash"}, nil
}

// runScript builds a command executing a shared script (goes to Bash — guard/traffic/audit preserved).
func (t *ToolSet) runScript() actool.CoreTool {
	return readTool("run_script",
		"Builds a command running a task-shared script (builds only — Bash executes). The script must already exist under "+
			"tasks/<id>/shared/scripts (written via save_script). Uses the script's shebang; without one, .py uses python3 and other files use Bash. Supports args and timeout; returns a ready-to-run command.",
		obj(map[string]any{
			"path":    str("script path (the path save_script returned, or a filename relative to shared/scripts)"),
			"args":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "argument list (optional)"},
			"timeout": intp("timeout seconds, default 120, max 1800"),
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path    string   `json:"path"`
				Args    []string `json:"args"`
				Timeout int      `json:"timeout"`
			}
			_ = json.Unmarshal(in, &a)
			dir := t.sharedDir()
			if dir == "" {
				return actool.Errorf("task shared dir unavailable (runDir not injected)"), nil
			}
			p := strings.TrimSpace(a.Path)
			if p == "" {
				return actool.Errorf("path is required"), nil
			}
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, "scripts", sanitizeScriptName(p))
			}
			abs, err := filepath.Abs(p)
			if err != nil {
				return actool.Errorf("path resolution failed"), nil
			}
			scriptsRoot, _ := filepath.Abs(filepath.Join(dir, "scripts"))
			rel, err := filepath.Rel(scriptsRoot, abs)
			if err != nil || strings.HasPrefix(rel, "..") {
				return actool.Errorf("only scripts under shared/scripts may be executed"), nil
			}
			if info, err := os.Stat(abs); err != nil || !info.Mode().IsRegular() {
				return actool.Errorf("script does not exist: " + abs), nil
			}
			interpreter, err := scriptInterpreter(abs)
			if err != nil {
				return actool.Errorf("failed to read the script: " + err.Error()), nil
			}
			timeout := a.Timeout
			if timeout <= 0 {
				timeout = 120
			}
			if timeout > 1800 {
				timeout = 1800
			}
			q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
			parts := []string{"timeout", fmt.Sprint(timeout)}
			for _, arg := range interpreter {
				parts = append(parts, q(arg))
			}
			parts = append(parts, q(abs))
			for _, arg := range a.Args {
				parts = append(parts, q(arg))
			}
			return jsonResult(map[string]any{
				"run_with_bash": strings.Join(parts, " "),
				"timeout_sec":   timeout,
				"note":          "run via Bash; when output is large, redirect into the shared dir first then grep.",
			})
		})
}
