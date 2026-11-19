package intercept

import "testing"

// The default enabled set must cover every tool with host/target side effects —
// a missing name silently bypasses BOTH rule matching and the fallback judge
// (guard.applyIntercept returns early on IsToolEnabled=false). This regressed
// once already (job_start/mcp__/NotebookEdit were absent while exec-equivalent).
func TestDefaultEnabledToolsCoverSideEffectTools(t *testing.T) {
	ic := New(nil) // nil db → code defaults
	for _, name := range []string{
		"Bash", "WebFetch", "web_search",
		"shell_open", "shell_send",
		"listener_start", "listener_stop", "goal_met",
		"Write", "Edit", "MultiEdit", "NotebookEdit",
		"job_start", "job_stop",
		"run_script", "save_script", "save_evidence", "poc_scaffold",
		"http_request", "session_login", "http_probe", "auth_request",
		"js_audit", "scan_with_nuclei",
	} {
		if !ic.IsToolEnabled(name) {
			t.Errorf("%s missing from default intercept set — calls bypass rules and judge", name)
		}
	}
}

// '*' suffix entries match by prefix: mcp__<srv>__<tool> names are dynamic and
// can't be enumerated, so the default set ships "mcp__*".
func TestIsToolEnabledWildcardPrefix(t *testing.T) {
	ic := New(nil)
	if !ic.IsToolEnabled("mcp__filesystem__write_file") {
		t.Error("mcp__ tool not covered by the mcp__* default")
	}
	if ic.IsToolEnabled("mcpfake_tool") {
		t.Error("prefix match must require the mcp__ delimiter, not bare 'mcp'")
	}
	// Read-only tools stay out (same policy as before — no deny-worthy side effects).
	for _, name := range []string{"job_status", "job_output", "listener_sessions", "list_artifacts", "list_facts"} {
		if ic.IsToolEnabled(name) {
			t.Errorf("%s unexpectedly in default intercept set", name)
		}
	}
}

func TestSplitEnabledTools(t *testing.T) {
	m, prefixes := splitEnabledTools([]string{"Bash", "mcp__*", "job_start"})
	if !m["Bash"] || !m["job_start"] {
		t.Error("exact names lost in split")
	}
	if m["mcp__*"] {
		t.Error("wildcard stored as exact name — would never match")
	}
	if len(prefixes) != 1 || prefixes[0] != "mcp__" {
		t.Errorf("prefix extraction wrong: %v", prefixes)
	}
}
