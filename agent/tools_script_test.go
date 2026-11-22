package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunScriptExecutesSavedInterpreter(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	python, pythonErr := exec.LookPath("python3")
	args := []string{"space value", "single'quote", "$(printf unwanted)", "`printf unwanted`", ""}
	pythonBody := "import sys\nprint('\\n'.join(sys.argv[1:]))\n"
	bashBody := "printf '%s\\n' \"$@\"\n"
	cases := []struct {
		name, filename, lang, content string
		manual, needsPython           bool
	}{
		{name: "default bash", filename: "check", content: bashBody},
		{name: "python", filename: "check", lang: "python", content: pythonBody, needsPython: true},
		{name: "python alias", filename: "check", lang: "py", content: pythonBody, needsPython: true},
		{name: "shebang overrides extension", filename: "check.sh", lang: "python", content: pythonBody, needsPython: true},
		{name: "explicit interpreter option", filename: "check", content: "#!" + python + " -u\n" + pythonBody, needsPython: true},
		{name: "env split interpreter options", filename: "check", content: "#!/usr/bin/env -S python3 -u\n" + pythonBody, needsPython: true},
		{name: "bash shebang overrides py extension", filename: "check.py", content: "#!/usr/bin/env bash\n" + bashBody},
		{name: "legacy python without shebang", filename: "check.PY", content: pythonBody, manual: true, needsPython: true},
		{name: "legacy bash without shebang", filename: "check.sh", content: bashBody, manual: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needsPython && pythonErr != nil {
				t.Skip("python3 unavailable")
			}
			ts := NewToolSet(nil, "worker")
			ts.SetRunDir(filepath.Join(t.TempDir(), "quoted' task", "tasks", "1", "i1"))
			path := tc.filename
			if tc.manual {
				path = filepath.Join(ts.sharedDir(), "scripts", tc.filename)
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				in, err := json.Marshal(map[string]any{"name": tc.filename, "lang": tc.lang, "content": tc.content})
				if err != nil {
					t.Fatal(err)
				}
				res, err := ts.saveScript().Call(context.Background(), in, nil)
				if err != nil || res.IsError {
					t.Fatalf("save_script: %v %s", err, res.Flatten())
				}
				var saved struct {
					Path string `json:"path"`
				}
				if err := json.Unmarshal([]byte(res.Flatten()), &saved); err != nil {
					t.Fatal(err)
				}
				path = saved.Path
			}
			in, err := json.Marshal(map[string]any{"path": path, "args": args})
			if err != nil {
				t.Fatal(err)
			}
			res, err := ts.runScript().Call(context.Background(), in, nil)
			if err != nil || res.IsError {
				t.Fatalf("run_script: %v %s", err, res.Flatten())
			}
			var built struct {
				Command string `json:"run_with_bash"`
			}
			if err := json.Unmarshal([]byte(res.Flatten()), &built); err != nil {
				t.Fatal(err)
			}
			command := built.Command
			if _, err := exec.LookPath("timeout"); err != nil {
				// macOS lacks GNU timeout; the context bounds this interpreter/quoting check.
				command = "timeout() { shift; \"$@\"; }; " + command
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, "-c", command)
			cmd.WaitDelay = time.Second
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("generated command failed: %v\ncommand: %s\n%s", err, built.Command, out)
			}
			if want := strings.Join(args, "\n") + "\n"; string(out) != want {
				t.Fatalf("script arguments changed: got %q, want %q", out, want)
			}
		})
	}
}
