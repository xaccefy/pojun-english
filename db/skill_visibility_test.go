package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// Built-in skills must be loadable correctly by norma's loader.
//
// Why test this: a skill's frontmatter is YAML, and a formatting mistake (a newline in
// the description, an unquoted colon) causes a **silent** parse failure — norma can't get
// the name/description, so the skill neither shows up nor is ever visible to the model.
// And such problems are completely invisible in the UI (the page's skill list is a DB-side
// visibility binding, which is a different thing from file parsing).
//
// So here we use norma's real LoadDir to load the repository's skills/ directory and
// assert one by one that name/description were both retrieved.
func TestShippedSkillsLoadWithNormaLoader(t *testing.T) {
	skillDir := shippedSkillDir(t)
	reg, err := skill.LoadDir(skillDir)
	if err != nil {
		t.Fatalf("failed to load skill directory: %v", err)
	}
	all := reg.List()
	if len(all) == 0 {
		t.Fatal("no skills were loaded")
	}
	for _, s := range all {
		if strings.TrimSpace(s.Name) == "" {
			t.Errorf("skill is missing name (frontmatter parse failed)")
		}
		if strings.TrimSpace(s.Description) == "" {
			t.Errorf("skill %q is missing description — the model relies on it to decide whether to call it", s.Name)
		}
	}
}

// vuln-hunting must be loadable, and its description must clearly state "when to use it" —
// the description is the only basis for the model to decide "whether to open this skill".
func TestVulnHuntingSkillIsLoadable(t *testing.T) {
	skillDir := shippedSkillDir(t)
	reg, err := skill.LoadDir(skillDir)
	if err != nil {
		t.Fatalf("failed to load skill directory: %v", err)
	}
	var found *skill.Skill
	for _, s := range reg.List() {
		if s.Name == "vuln-hunting" {
			cp := s
			found = &cp
			break
		}
	}
	if found == nil {
		t.Fatal("vuln-hunting skill was not loaded — frontmatter parse failed or wrong directory name")
	}
	// The description must contain trigger clues about "when to use it", otherwise the model won't think to use it.
	for _, want := range []string{"hunting", "vulnerability"} {
		if !strings.Contains(found.Description, want) {
			t.Errorf("vuln-hunting's description is missing %q: %s", want, found.Description)
		}
	}
}

// vuln-hunting's reference.md must be in the skill directory — SKILL.md references it,
// and if it's missing the agent won't find the content when it expands on demand.
func TestVulnHuntingHasReferenceFile(t *testing.T) {
	skillDir := shippedSkillDir(t)
	p := filepath.Join(skillDir, "vuln-hunting", "reference.md")
	if _, err := os.Stat(p); err != nil {
		t.Errorf("vuln-hunting/reference.md is missing: %v", err)
	}
}

// vuln-hunting must be bound to planner and worker —
// the planner decides whether to dispatch "dig for unknown vulnerabilities" intents,
// and the worker needs the methodology when executing.
func TestVulnHuntingVisibilityBound(t *testing.T) {
	agents, ok := builtinSkillVisibility["vuln-hunting"]
	if !ok {
		t.Fatal("vuln-hunting has no visibility binding — no one can use it")
	}
	has := func(k string) bool {
		for _, a := range agents {
			if a == k {
				return true
			}
		}
		return false
	}
	if !has("planner") {
		t.Error("vuln-hunting is not bound to planner — it can't dispatch hunting-type intents based on it")
	}
	if !has("worker") {
		t.Error("vuln-hunting is not bound to worker — it can't see the methodology when executing hunting intents")
	}
}

// shippedSkillDir locates the repository's skills/ directory.
//
// Tests run in the db package, while skills/ is at the repository root — search upward with relative paths.
func shippedSkillDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		cand := filepath.Join(dir, "skills")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("cannot find the repository's skills/ directory")
	return ""
}

// Newly added built-in skills must be bound automatically on upgrade — users shouldn't have to manually enable them in the UI.
//
// seedBuiltinSkillVisibility has no flag gate and runs at every startup, relying on
// ON CONFLICT DO NOTHING to distinguish two cases:
//   - new skill (no conflicting row) → insert the binding, effective immediately on upgrade;
//   - existing skill (conflicting row) → preserve the user's toggle state, don't revive a user's "off".
//
// This test locks in the premise that "new skills get into the builtinSkillVisibility table" —
// missing it means a new skill will never be used by anyone.
func TestNewBuiltinSkillsAreBoundByDefault(t *testing.T) {
	// Each skill must be bound to at least one agent, otherwise it won't appear in any agent's tools.
	for name, agents := range builtinSkillVisibility {
		if len(agents) == 0 {
			t.Errorf("built-in skill %q is not bound to any agent", name)
		}
	}
	// vuln-hunting must be in the built-in table (not just exist as a file).
	if _, ok := builtinSkillVisibility["vuln-hunting"]; !ok {
		t.Error("vuln-hunting is not in builtinSkillVisibility — it won't be auto-bound after upgrade, so no one can use it")
	}
	// Reverse direction: skill names in the table must all have corresponding directories (otherwise there's no file to load even if bound).
	skillDir := shippedSkillDir(t)
	for name := range builtinSkillVisibility {
		p := filepath.Join(skillDir, name, "SKILL.md")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("built-in skill %q has a binding but no file: %v", name, err)
		}
	}
}

// Gatekeeper test (v0.4.56): every skill shipped in the repository must have a default
// visibility binding, otherwise it "exists but no one can see it" — this is exactly the
// problem a user reported on 2026-11-05: redteam-ops / playwright-cli etc. were written
// but never bound to any agent.
//
// Exceptions must be explicitly listed here with a reason; forgetting to bind a newly
// added skill will turn this red immediately.
func TestEveryShippedSkillIsBoundOrExplicitlyOptOut(t *testing.T) {
	optOut := map[string]string{
		"scopesentry": "depends on an external ScopeSentry MCP configuration, enable on demand",
	}
	dirs, err := os.ReadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Skip("cannot find skills directory")
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		name := d.Name()
		if _, ok := optOut[name]; ok {
			continue
		}
		if len(builtinSkillVisibility[name]) == 0 {
			t.Errorf("skill %q has no default visibility binding (nor a reason in optOut) — written but no one can see it", name)
		}
	}
	// Reverse direction: every key in the binding table must have a real skill directory (to prevent stale keys dangling after a rename).
	for name := range builtinSkillVisibility {
		if _, err := os.Stat(filepath.Join("..", "skills", name, "SKILL.md")); err != nil {
			t.Errorf("visibility-bound skill %q does not exist in the skills/ directory", name)
		}
	}
}

// src-hunting is the knowledge-base entry point for the SRC scenario: references/ and rules/
// must be distributed completely with the package, otherwise all the indexes in SKILL.md
// are dead links (the model fails to open files, and the methodology can't be used).
func TestSrcHuntingSkillShipsKnowledgeBase(t *testing.T) {
	base := filepath.Join("..", "skills", "src-hunting")
	entries, err := os.ReadDir(filepath.Join(base, "references"))
	if err != nil {
		t.Fatalf("src-hunting references directory is missing: %v", err)
	}
	md := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			md++
			if info, err := e.Info(); err != nil || info.Size() < 100 {
				t.Errorf("references/%s is empty or too small", e.Name())
			}
		}
	}
	if md < 40 {
		t.Fatalf("knowledge base file count is %d, fewer than the expected 40+ (incomplete distribution)", md)
	}
	rules, err := os.ReadDir(filepath.Join(base, "rules"))
	if err != nil {
		t.Fatalf("src-hunting rules directory is missing: %v", err)
	}
	if len(rules) < 10 {
		t.Fatalf("rule file count is %d, fewer than the expected 10+", len(rules))
	}
	// Required entry-point files
	for _, f := range []string{"breach-shortlist.md", "recon-methodology.md"} {
		if _, err := os.Stat(filepath.Join(base, "references", f)); err != nil {
			t.Errorf("missing entry-point file references/%s", f)
		}
	}
}
