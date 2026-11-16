package db

import (
	"strings"
	"testing"
)

// Empty-value queries: the agent must be able to find assets with "an open port but an
// unrecognized service".
//
// Background: in a real task, 2073 of 2380 service assets had an empty service_name
// (ports were scanned but service identification was not done), and these are exactly the
// surfaces to dig into next. The agent must be able to see them — but `service_name=` is a
// fuzzy match (ILIKE '%%' matches all non-empty values), while `service_name==""` is the
// exact match for the empty string.
func TestDSLEmptyValueQuery(t *testing.T) {
	node, err := ParseDSL(`service_name==""`)
	if err != nil {
		t.Fatalf("service_name==\"\" should parse: %v", err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatalf("failed to build where: %v", err)
	}
	if !strings.Contains(where, "service_name") {
		t.Errorf("where should contain service_name: %s", where)
	}
	// An empty value must match both NULL and the empty string: a large number of HTTP
	// services in the asset DB store service_name as NULL (2073 of 2180 measured), so
	// matching only '' would find nothing.
	if !strings.Contains(where, "IS NULL") {
		t.Errorf("empty-value query should cover NULL: %s", where)
	}
	if !strings.Contains(where, "= ''") {
		t.Errorf("empty-value query should cover empty string: %s", where)
	}
	if len(args) != 0 {
		t.Errorf("empty-value query needs no arguments, got %v", args)
	}
}

// The == semantics for non-empty values are unchanged (exact equality, no ILIKE).
func TestDSLEmptyValueDoesNotAffectNonEmpty(t *testing.T) {
	node, err := ParseDSL(`service_name==mysql`)
	if err != nil {
		t.Fatal(err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(where, "IS NULL") {
		t.Errorf("non-empty value should not carry a NULL check: %s", where)
	}
	if !strings.Contains(where, "= $1") {
		t.Errorf("should be exact equality: %s", where)
	}
	if len(args) != 1 || args[0] != "mysql" {
		t.Errorf("argument should be mysql, got %v", args)
	}
}

// Conversely: `service_name=` cannot be used to query empty values (it is a fuzzy match
// and will match all non-empty values). This assertion pins the semantics down so no one
// later changes `=` to an exact match as well.
func TestDSLFuzzyEmptyValueDoesNotMatchEmpty(t *testing.T) {
	node, err := ParseDSL(`service_name=`)
	if err == nil {
		where, _, _ := buildDSLWhere(node)
		if !strings.Contains(where, "ILIKE") {
			t.Errorf("= should have fuzzy-match (ILIKE) semantics: %s", where)
		}
	}
}
