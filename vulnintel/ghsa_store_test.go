package vulnintel

import (
	"testing"
)

// Conversion of semver ranges → CPE range columns.
//
// Getting this layer wrong would **directly invert version decisions** (judging an
// affected version as unaffected), so every direction needs an assertion.
func TestGhsaRangeToCPERange(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want CPERange
	}{
		{
			name: "less than upper bound",
			expr: "< 3.10.0",
			want: CPERange{EndExcluding: "3.10.0"},
		},
		{
			name: "less than or equal to upper bound",
			expr: "<= 3.10.0",
			want: CPERange{EndIncluding: "3.10.0"},
		},
		{
			name: "greater than lower bound",
			expr: "> 1.0.0",
			want: CPERange{StartExcluding: "1.0.0"},
		},
		{
			name: "greater than or equal to lower bound",
			expr: ">= 1.0.0",
			want: CPERange{StartIncluding: "1.0.0"},
		},
		{
			name: "equal to a version",
			expr: "= 2.5.0",
			want: CPERange{StartIncluding: "2.5.0", EndIncluding: "2.5.0"},
		},
		{
			name: "compound range takes intersection",
			expr: ">= 1.0.0, <= 1.11.0",
			want: CPERange{StartIncluding: "1.0.0", EndIncluding: "1.11.0"},
		},
		{
			name: "whole expression untrusted when a fragment cannot be parsed",
			expr: "^2.0.0",
			want: CPERange{},
		},
		{
			name: "empty range",
			expr: "",
			want: CPERange{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ghsaRangeToCPERange(c.expr)
			if got != c.want {
				t.Errorf("range %q conversion error:\n got %+v\nwant %+v", c.expr, got, c.want)
			}
		})
	}
}

// The converted CPE ranges can be correctly evaluated by the existing VersionInRange logic.
//
// This one is the most critical: the converted boundaries must be consistent with
// cmpVersions' comparison direction
// (version_start_incl: version >= start; version_end_excl: version < end).
func TestGhsaRangeToCPERangeSemanticsMatchVersionInRange(t *testing.T) {
	// "< 3.10.0" → 3.9.0 affected, 3.10.0 not affected.
	r := ghsaRangeToCPERange("< 3.10.0")
	if r.StartIncluding != "" || r.StartExcluding != "" {
		t.Fatalf("should not have a lower bound: %+v", r)
	}
	if r.EndExcluding != "3.10.0" {
		t.Fatalf("upper bound should be exclusive 3.10.0: %+v", r)
	}
	// Manually verify according to VersionInRange semantics.
	if !(cmpVersions("3.9.0", "3.10.0") < 0) {
		t.Error("3.9.0 should be less than 3.10.0")
	}
	if !(cmpVersions("3.10.0", "3.10.0") >= 0) {
		t.Error("3.10.0 should equal 3.10.0 (exclusive upper bound → not affected)")
	}
	// ">= 1.0.0, <= 1.11.0" → 1.11.0 affected, 1.11.1 not affected.
	r2 := ghsaRangeToCPERange(">= 1.0.0, <= 1.11.0")
	if r2.StartIncluding != "1.0.0" || r2.EndIncluding != "1.11.0" {
		t.Fatalf("compound range conversion error: %+v", r2)
	}
	if !(cmpVersions("1.11.0", "1.11.0") <= 0) {
		t.Error("1.11.0 should fall within the closed range")
	}
	if !(cmpVersions("1.11.1", "1.11.0") > 0) {
		t.Error("1.11.1 should be outside the closed range")
	}
}

// Package name → inverted index (vendor, product) form.
//
// Key point: a composer package name is `vendor/package`, while a CPE product is a single
// segment — without a form conversion it will never match an asset's technology fingerprint.
func TestGhsaIndexRows(t *testing.T) {
	rows := ghsaIndexRows(GhsaPackage{Ecosystem: "composer", Name: "contao/core-bundle"})
	if len(rows) == 0 {
		t.Fatal("should produce index rows")
	}
	// Must have the vendor=contao product=core_bundle form.
	found := false
	for _, r := range rows {
		if r.vendor == "contao" && r.product == "core_bundle" {
			found = true
		}
	}
	if !found {
		t.Errorf("should contain the (contao, core_bundle) form, got %+v", rows)
	}
	// Should also have the de-hyphenated form (corebundle) — it is the fallback when a
	// technology fingerprint is written as "Contao".
	foundCompact := false
	for _, r := range rows {
		if r.product == "corebundle" {
			foundCompact = true
		}
	}
	if !foundCompact {
		t.Errorf("should contain the corebundle form, got %+v", rows)
	}
}

// Index forms must match tokens from technical fingerprints (this is the actual criterion for the linkage).
func TestGhsaIndexRowsMatchTechTokens(t *testing.T) {
	rows := ghsaIndexRows(GhsaPackage{Ecosystem: "composer", Name: "contao/core-bundle"})
	tech := techTokens("Contao 5.3")
	hit := false
	for _, r := range rows {
		for _, ct := range cpeTokens(r.product) {
			for _, t := range tech {
				if t == ct {
					hit = true
				}
			}
		}
	}
	if !hit {
		t.Errorf("GHSA package contao/core-bundle should match technical fingerprint %v", tech)
	}
}

// Single-segment package names (no slash) must also be indexable.
func TestGhsaIndexRowsSingleSegment(t *testing.T) {
	rows := ghsaIndexRows(GhsaPackage{Ecosystem: "npm", Name: "lodash"})
	if len(rows) != 1 {
		t.Fatalf("single-segment package name should produce 1 row, got %d: %+v", len(rows), rows)
	}
	if rows[0].product != "lodash" {
		t.Errorf("product should be lodash, got %q", rows[0].product)
	}
}
