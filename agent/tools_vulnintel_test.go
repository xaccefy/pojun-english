package agent

import (
	"encoding/json"
	"reflect"
	"testing"
)

// CWE→methodology-skill linkage (M1 closure): relatedSkillsFor dedupe-returns skill names by hit CWE;
// with no index injected or no hits it returns nil — related_skills must not appear in tool output:
// the linkage is purely additive and can't change the existing shape.
func TestRelatedSkillsFor(t *testing.T) {
	// No index injected: always nil.
	if got := relatedSkillsFor([]string{"CWE-89"}); got != nil {
		t.Fatalf("nil index should return nil, got=%v", got)
	}

	SetCweSkillIndex(map[string][]string{
		"CWE-89":  {"inj-skill"},
		"CWE-862": {"authz-skill"},
		"CWE-639": {"authz-skill"},
	})
	t.Cleanup(func() { SetCweSkillIndex(nil) })

	// Single CWE hit.
	if got := relatedSkillsFor([]string{"CWE-89"}); !reflect.DeepEqual(got, []string{"inj-skill"}) {
		t.Fatalf("CWE-89 → %v", got)
	}
	// Multi-CWE dedupe: two CWEs pointing at the same skill appear once; case-insensitive.
	got := relatedSkillsFor([]string{"CWE-862", "cwe-639"})
	if !reflect.DeepEqual(got, []string{"authz-skill"}) {
		t.Fatalf("CWE-862+cwe-639 → %v, want deduped [authz-skill]", got)
	}
	// No hits → nil.
	if got := relatedSkillsFor([]string{"CWE-999"}); got != nil {
		t.Fatalf("no hits should return nil, got=%v", got)
	}
}

// The linkage field must be 'absent when empty': get_vuln output without related_skills stays
// consistent with existing callers (the field names written in the prompts).
func TestVulnDetailWithSkillsOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(vulnDetailWithSkills{VulnDetail: nil})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["related_skills"]; ok {
		t.Fatal("related_skills must not appear in output when there's no linkage")
	}
}
