package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// tag parsing: standard frontmatter form.
func TestParseSkillTags(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "SKILL.md")
	content := `---
name: demo
description: for-testing
tags:
  cwe: [cwe-269, CWE-862, " cwe-639 "]
  attack: [t1190, T1210]
  class: [Authz, IDOR]
---
# body
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tags := ParseSkillTags(p)
	if len(tags.CWE) != 3 {
		t.Fatalf("expected 3 CWEs, got %v", tags.CWE)
	}
	// case normalization: CWEs use the uppercase convention.
	for _, want := range []string{"CWE-269", "CWE-862", "CWE-639"} {
		found := false
		for _, c := range tags.CWE {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected normalized %s, got %v", want, tags.CWE)
		}
	}
	// ATT&CK is uppercased too.
	if tags.Attack[0] != "T1190" || tags.Attack[1] != "T1210" {
		t.Errorf("ATT&CK should be uppercase-normalized, got %v", tags.Attack)
	}
	// class uses the lowercase convention.
	if tags.Class[0] != "authz" || tags.Class[1] != "idor" {
		t.Errorf("class should be lowercase-normalized, got %v", tags.Class)
	}
	if tags.Empty() {
		t.Error("tagged input must not report Empty")
	}
	// match by id (case-insensitive).
	if !tags.MatchesCWE("cwe-269") {
		t.Error("MatchesCWE should be case-insensitive")
	}
	if tags.MatchesCWE("CWE-0000") {
		t.Error("a CWE that isn't there must not match")
	}
}

// no tags / broken frontmatter → empty tags (not an error).
//
// third-party uploads often lack tags — they're optional metadata.
func TestParseSkillTagsOptional(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"no tags":        "---\nname: a\ndescription: x\n---\nbody",
		"no frontmatter": "# just a body",
		"broken YAML":    "---\nname: [broken\n---\nbody",
		"missing file":   "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, "SKILL.md")
			if content != "" {
				if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = os.Remove(p)
			}
			tags := ParseSkillTags(p)
			if !tags.Empty() {
				t.Errorf("expected empty tags, got %+v", tags)
			}
		})
	}
}

// LoadSkillTags parses a whole directory, keyed by **directory name** (matching
// agent_skill_visibility's binding key — not the frontmatter name).
func TestLoadSkillTagsKeysByDirName(t *testing.T) {
	dir := t.TempDir()
	// deliberately make frontmatter name differ from dir name — the binding key must
	// be the dir name.
	if err := os.MkdirAll(filepath.Join(dir, "my-skill"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "my-skill", "SKILL.md"), []byte(
		"---\nname: totally-different-name\ntags:\n  class: [demo]\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// directories without SKILL.md produce no entries.
	if err := os.MkdirAll(filepath.Join(dir, "no-skill-md"), 0o755); err != nil {
		t.Fatal(err)
	}
	tags := LoadSkillTags(dir)
	if _, ok := tags["my-skill"]; !ok {
		t.Fatalf("key should be dir name my-skill, got %v", tags)
	}
	if _, ok := tags["totally-different-name"]; ok {
		t.Error("frontmatter name must not be used as the key")
	}
	if _, ok := tags["no-skill-md"]; ok {
		t.Error("a directory without SKILL.md must not produce an entry")
	}
}

// **guarding test**: a tagged skill must still load normally under norma.
//
// It's the safety premise of the tag mechanism: norma's frontmatter parse ignores
// unknown fields, so tags can't break skill loading. But 'can't break' only holds while
// this test stands — it goes red first when norma is upgraded or the SKILL.md format
// changes.
func TestTaggedSkillsStillLoadWithNorma(t *testing.T) {
	// locate the repo's skills dir (../skills relative to this test file).
	skillDir := filepath.Join("..", "skills")
	if _, err := os.Stat(skillDir); err != nil {
		t.Skip("skills dir not found (test may not be running from the repo root)")
	}
	reg, err := skill.LoadDir(skillDir)
	if err != nil {
		t.Fatal(err)
	}
	loaded := map[string]bool{}
	for _, s := range reg.List() {
		loaded[s.Name] = true
		if s.Description == "" {
			t.Errorf("skill %s loaded with empty description — frontmatter may be broken by tags", s.Name)
		}
	}
	// all built-in skills must load.
	for _, name := range []string{"vuln-hunting", "api-recon", "scopesentry-mcp"} {
		if !loaded[name] {
			t.Errorf("tagged skill %s was not loaded by norma", name)
		}
	}
}

// built-in skills' tags must have real coverage (the capability matrix's starting
// point).
//
// this test also guards 'the tags were actually written' — a hand-edit that drops the
// tags block goes red here.
func TestShippedSkillsHaveSubstantiveTags(t *testing.T) {
	skillDir := filepath.Join("..", "skills")
	if _, err := os.Stat(skillDir); err != nil {
		t.Skip("skills dir not found")
	}
	tags := LoadSkillTags(skillDir)
	vh, ok := tags["vuln-hunting"]
	if !ok {
		t.Fatal("vuln-hunting should carry tags")
	}
	// authz-bypass/IDOR/race are the seven-dimension methodology's core — CWE tags must
	// cover them.
	for _, want := range []string{"CWE-269", "CWE-862", "CWE-639", "CWE-362"} {
		if !vh.MatchesCWE(want) {
			t.Errorf("vuln-hunting should cover %s (core CWEs of authz/IDOR/race), got %v", want, vh.CWE)
		}
	}
	if len(vh.Class) < 4 {
		t.Errorf("vuln-hunting's class tags should cover at least 4 dimensions, got %v", vh.Class)
	}
	if ar, ok := tags["api-recon"]; !ok || len(ar.Class) == 0 {
		t.Error("api-recon should carry class tags")
	}
}

// BuildCweSkillIndex's inverted shape: each CWE of the same skill becomes its own key;
// untagged dirs don't enter the index; whether an empty dir returns an empty map vs nil
// doesn't matter — what matters is 'read failure must not panic' (missing linkage just
// means no hints).
func TestBuildCweSkillIndex(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, cwes string) {
		t.Helper()
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + name + "\ndescription: test\n"
		if cwes != "" {
			body += "tags:\n  cwe: [" + cwes + "]\n"
		}
		body += "---\n\nbody\n"
		if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("authz-skill", "CWE-862, CWE-639")
	mk("inj-skill", "CWE-89")
	mk("untagged", "")

	idx := BuildCweSkillIndex(dir)
	if got := idx["CWE-862"]; len(got) != 1 || got[0] != "authz-skill" {
		t.Fatalf("CWE-862 → %v, expected [authz-skill]", got)
	}
	if got := idx["CWE-89"]; len(got) != 1 || got[0] != "inj-skill" {
		t.Fatalf("CWE-89 → %v, expected [inj-skill]", got)
	}
	if _, ok := idx["CWE-999"]; ok {
		t.Fatal("a CWE with no hits must not appear in the index")
	}
}
