package server

import (
	"context"
	"strings"
	"testing"

	"github.com/chu0119/pojun/agent"
)

// v0.4.60: the skill cheat-sheet block must be injected into the system prompt — Skill
// is a meta-tool the model barely calls without an explicit system-prompt nudge (8 calls
// in 56k; zero on task 18).
func TestSkillIndexBlockCoversBindings(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := New(context.Background(), m, "../skills", t.TempDir(), t.TempDir())
	defer s.Close()

	worker, err := s.m.pg.GetAgentByKey("worker")
	if err != nil {
		t.Fatal(err)
	}
	// bind two skills to the worker (simulating user/default binding).
	if err := s.m.pg.SetAgentSkillVisibility(worker.ID, []string{"vuln-hunting", "web-attack-methods"}); err != nil {
		t.Fatal(err)
	}
	blk := agent.SkillIndexBlock("worker")
	if blk == "" {
		t.Fatal("worker has bindings but the cheat-sheet block is empty")
	}
	if !strings.Contains(blk, "vuln-hunting") || !strings.Contains(blk, "web-attack-methods") {
		t.Fatalf("cheat-sheet block missing bindings: %s", blk)
	}
	if !strings.Contains(blk, "Skill(") {
		t.Fatalf("cheat-sheet block missing invocation guidance: %s", blk)
	}
	// unbound agent (goals has no default bindings) → empty block, no prompt pollution.
	if blk := agent.SkillIndexBlock("goals"); blk != "" {
		t.Fatalf("an unbound agent must have no cheat-sheet block: %s", blk)
	}
}
