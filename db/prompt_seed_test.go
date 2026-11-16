package db

import (
	"fmt"
	"testing"
	"time"
)

// SeedPromptVersioned is the mechanism by which "prompt improvements ship with versions"; the rules must be precise:
// system-seeded ones can be upgraded, user-edited ones are never overwritten.
func TestSeedPromptVersioned(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	key := fmt.Sprintf("t_prompt_%d", time.Now().UnixNano())
	var agentID int64
	if err := d.QueryRow(`INSERT INTO agents (key, name, role) VALUES ($1,$2,'worker') RETURNING id`, key, key).
		Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM agents WHERE id=$1`, agentID) })

	const v1 = "first built-in prompt version"
	const v2 = "second built-in prompt version"

	// 1) empty → seed
	up, err := d.SeedPromptVersioned(agentID, v1)
	if err != nil || !up {
		t.Fatalf("initial seed should write, got upgraded=%v err=%v", up, err)
	}
	// 2) content unchanged → do not rewrite
	up, err = d.SeedPromptVersioned(agentID, v1)
	if err != nil || up {
		t.Fatalf("unchanged content should not upgrade, got upgraded=%v err=%v", up, err)
	}
	// 3) code default changed → upgrade, and the old version goes into history
	up, err = d.SeedPromptVersioned(agentID, v2)
	if err != nil || !up {
		t.Fatalf("system-seeded prompt should upgrade with code, got upgraded=%v err=%v", up, err)
	}
	vers, err := d.ListPromptVersions(agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vers) != 2 {
		t.Fatalf("should keep 2 versions (history traceable), got %d", len(vers))
	}
	var cur string
	if err := d.QueryRow(`SELECT p.template_text FROM agents a JOIN agent_prompts p ON p.id=a.current_prompt_id WHERE a.id=$1`, agentID).
		Scan(&cur); err != nil {
		t.Fatal(err)
	}
	if cur != v2 {
		t.Fatalf("current version should be the new one, got %q", cur)
	}

	// 4) after user edits → never overwrite
	if _, err := d.SavePrompt(agentID, "my own edited prompt", "manual edit", "ui"); err != nil {
		t.Fatal(err)
	}
	up, err = d.SeedPromptVersioned(agentID, "third built-in prompt version")
	if err != nil {
		t.Fatal(err)
	}
	if up {
		t.Fatal("user-edited prompt should not be overwritten by automatic upgrade")
	}
	if err := d.QueryRow(`SELECT p.template_text FROM agents a JOIN agent_prompts p ON p.id=a.current_prompt_id WHERE a.id=$1`, agentID).
		Scan(&cur); err != nil {
		t.Fatal(err)
	}
	if cur != "my own edited prompt" {
		t.Fatalf("user content was changed: %q", cur)
	}
}
