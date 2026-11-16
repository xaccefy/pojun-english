package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// With local_exec off, the agent must lose ALL local-exec/file-writing tools, keeping only read-only
// checks and platform tools — otherwise 'use spawn_task to delegate' is just words: the model still holds Bash and will DIY (measured).
func TestDropLocalExecTools(t *testing.T) {
	base := actool.DefaultTools()
	// platform/orchestration tools have no SDK row — must survive untouched.
	spawn := actool.Build(actool.Spec{Name: "spawn_task", Description: "d"})
	// shell_* is the interactive-PTY session family — another entry to the same thing as Bash, must go too.
	shellOpen := actool.Build(actool.Spec{Name: "shell_open", Description: "d"})
	base = append(base, spawn, shellOpen)

	kept := DropLocalExecTools(base)
	have := map[string]bool{}
	for _, tl := range kept {
		have[tl.Name()] = true
	}
	for _, banned := range []string{"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "shell_open"} {
		if have[banned] {
			t.Errorf("%s should be stripped (local exec off)", banned)
		}
	}
	for _, want := range []string{"Read", "LS", "Glob", "Grep", "spawn_task"} {
		if !have[want] {
			t.Errorf("%s should be kept (read-only check / platform tool)", want)
		}
	}
}
