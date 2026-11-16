package db

import (
	"strings"
	"testing"
)

// v0.4.60: built-in task playbook seed -- 4 templates land in the DB, idempotent, searchable.
func TestSeedBuiltinTaskPlaybooks(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	// Clean batch: drop this test's historical seed flag and same-name templates (shared test database).
	_, _ = d.Exec(`DELETE FROM task_templates WHERE name LIKE 'Playbook:%'`)
	_, _ = d.Exec(`DELETE FROM settings WHERE key='task_playbooks_v1'`)

	if err := d.seedBuiltinTaskPlaybooks(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	list, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, tpl := range list {
		if strings.HasPrefix(tpl.Name, "Playbook:") {
			count++
			if !strings.Contains(tpl.Goal, "[Internal workflow") && !strings.Contains(tpl.Goal, "[Workflow") && !strings.Contains(tpl.Goal, "[Output]") {
				t.Errorf("playbook %q is missing a structured workflow section", tpl.Name)
			}
		}
	}
	if count != len(builtinTaskPlaybooks) {
		t.Fatalf("playbook count=%d want %d", count, len(builtinTaskPlaybooks))
	}
	// Idempotent: running again adds nothing and does not error (the flag is already done).
	before := len(list)
	if err := d.seedBuiltinTaskPlaybooks(); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	after, _ := d.ListTaskTemplates()
	if len(after) != before {
		t.Fatalf("re-seeding must not add rows: before=%d after=%d", before, len(after))

	}
}
