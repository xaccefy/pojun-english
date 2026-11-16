package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// New parameters of built-in tools must be backfilled into existing rows (SeedTool only inserts, never
// updates); backfilling only adds missing fields and leaves user edits untouched.
func TestMergeToolSchemaProperty(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	const key = "test_merge_prop"
	_, _ = d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	defer d.Exec(`DELETE FROM tools WHERE key=$1`, key)

	old := json.RawMessage(`{"type":"object","properties":{"ids":{"type":"array"},"user_edit":{"type":"string"}}}`)
	if err := d.SeedTool(key, "old desc", old, json.RawMessage(`["planner"]`)); err != nil {
		t.Fatal(err)
	}
	props := map[string]any{"superseded_by": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}}
	if err := d.MergeToolSchemaProperty(key, "superseded_by", props, "new desc"); err != nil {
		t.Fatal(err)
	}
	var schema, desc string
	if err := d.QueryRow(`SELECT schema::text, description FROM tools WHERE key=$1`, key).Scan(&schema, &desc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(schema, "superseded_by") || !strings.Contains(schema, "user_edit") {
		t.Fatalf("backfill should add the new field and preserve existing fields: %s", schema)
	}
	if desc != "new desc" {
		t.Fatalf("backfill should update to the code's default description: %q", desc)
	}
	// idempotent: calling again should not error or duplicate.
	if err := d.MergeToolSchemaProperty(key, "superseded_by", props, "new desc"); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := d.QueryRow(`SELECT schema::text FROM tools WHERE key=$1`, key).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if strings.Count(after, "superseded_by") != 1 {
		t.Fatalf("repeated backfill should not produce duplicate fields: %s", after)
	}
}
