package server

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Standardized skill tags (CWE / ATT&CK / class).
//
// ## Why tags
//
// An untagged skill is an island: you can't query by CWE ('do we have a methodology for
// this vuln class?'), can't compute coverage (capability matrix), and can't match
// skills to incoming tasks by tag — the model would have to memorize every skill
// description. The mechanism is borrowed from the comparison with open-source peers
// (docs/vuln-hunting-capability-comparison.md) — Anthropic-Cybersecurity-Skills tags all 818 skills with
// framework labels.
//
// ## Tag format (SKILL.md frontmatter)
//
//	---
//	name: vuln-hunting
//	description: ...
//	tags:
//	  cwe: [CWE-269, CWE-862]        # MITRE CWE ids
//	  attack: [T1190]                 # MITRE ATT&CK technique ids
//	  class: [authz, idor, race]      # platform-internal classes (lowercase-hyphen)
//	---
//
// norma's skill.LoadDir doesn't know the tags field — but yaml.Unmarshal ignores
// unknown fields by default, so a tagged SKILL.md is fully transparent to norma (db's
// TestShippedSkillsLoadWithNormaLoader guards this).
// POJUN parses tags itself: ParseSkillTags in this file.
//
// ## What each tag class is for
//
//   - cwe: ties into vuln intel — CVE/GHSA entries carry CWE ids and get matched to
//     methodologies by number (GHSA's cwes field is parsed in vulnintel/ghsa.go).
//   - attack: aligns with kill-chain stages — ids like T1190 (exploit public-facing
//     application) are a cross-tool common language.
//   - class: platform-internal categories organized by our own concepts
//     ('authz-bypass / enumerable / race') — closer to the vuln-hunting seven-dimension
//     vocabulary than CWE.

// SkillTags is a skill's standardized tags.
type SkillTags struct {
	// CWE lists MITRE CWE ids (uppercase-normalized: CWE-269).
	CWE []string `json:"cwe,omitempty"`
	// Attack lists MITRE ATT&CK technique ids (uppercase-normalized: T1190).
	Attack []string `json:"attack,omitempty"`
	// Class lists platform-internal categories (lowercase-normalized:
	// authz / idor / race).
	Class []string `json:"class,omitempty"`
}

// Empty reports whether there are no tags at all.
func (t SkillTags) Empty() bool {
	return len(t.CWE) == 0 && len(t.Attack) == 0 && len(t.Class) == 0
}

// MatchesCWE reports whether the skill covers the given CWE id (case-insensitive).
func (t SkillTags) MatchesCWE(cwe string) bool {
	want := strings.ToUpper(strings.TrimSpace(cwe))
	if want == "" {
		return false
	}
	for _, c := range t.CWE {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

// skillTagFrontmatter declares only the tags-related fields; yaml.Unmarshal ignores
// the rest — other frontmatter keys (name/description/allowed-tools…) are untouched.
type skillTagFrontmatter struct {
	Tags struct {
		CWE    []string `yaml:"cwe"`
		Attack []string `yaml:"attack"`
		Class  []string `yaml:"class"`
	} `yaml:"tags"`
}

// ParseSkillTags parses tags from one SKILL.md.
//
// No tags / broken frontmatter → empty SkillTags (not an error): tags are optional
// metadata — an untagged skill is still legal (third-party uploads often lack them).
func ParseSkillTags(path string) SkillTags {
	var out SkillTags
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	head, ok := frontmatterHead(string(data))
	if !ok {
		return out
	}
	var fm skillTagFrontmatter
	if err := yaml.Unmarshal([]byte(head), &fm); err != nil {
		return out // frontmatter isn't valid YAML → no tags
	}
	out.CWE = normalizeUpper(fm.Tags.CWE)
	out.Attack = normalizeUpper(fm.Tags.Attack)
	out.Class = normalizeLower(fm.Tags.Class)
	return out
}

// LoadSkillTags parses tags for every skill under the skills dir.
//
// Returns dirName → tags (matching agent_skill_visibility's binding key — directory
// name, not the frontmatter name). A directory read failure returns an empty map: tag
// decoration must not fail the skill list wholesale.
func LoadSkillTags(dir string) map[string]SkillTags {
	out := map[string]SkillTags{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name(), "SKILL.md")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if tags := ParseSkillTags(p); !tags.Empty() {
			out[e.Name()] = tags
		}
	}
	return out
}

// BuildCweSkillIndex builds the inverted index CWE id → skill directory name.
//
// Purpose: injected into the agent's vuln-intel tools at server start
// (agent.SetCweSkillIndex) — when search_vulns / get_vuln hits an entry carrying CWEs,
// the corresponding methodology skill is suggested — the last link in the 'looked up a
// CVE → auto-suggest its methodology skill' chain (capability-comparison M1). A
// directory read failure returns an empty map: missing linkage is just missing hints,
// it must not fail startup.
func BuildCweSkillIndex(dir string) map[string][]string {
	out := map[string][]string{}
	for name, t := range LoadSkillTags(dir) {
		for _, c := range t.CWE {
			out[c] = append(out[c], name)
		}
	}
	return out
}

// frontmatterHead extracts the YAML frontmatter at a SKILL.md's head (between --- and
// ---).
//
// Same boundary rule as norma's skill.parse (looks for "\n---") so both sides read the
// same file identically.
func frontmatterHead(s string) (string, bool) {
	if !strings.HasPrefix(s, "---") {
		return "", false
	}
	rest := strings.TrimLeft(strings.TrimPrefix(s, "---"), "\r\n")
	i := strings.Index(rest, "\n---")
	if i < 0 {
		return "", false
	}
	return rest[:i], true
}

// normalizeUpper uppercases and trims (CWE-269 / T1190 are uppercase by convention).
func normalizeUpper(in []string) []string {
	return normalizeTags(in, strings.ToUpper)
}

// normalizeLower lowercases and trims (class uses lowercase-hyphen convention).
func normalizeLower(in []string) []string {
	return normalizeTags(in, strings.ToLower)
}

func normalizeTags(in []string, conv func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(conv(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
