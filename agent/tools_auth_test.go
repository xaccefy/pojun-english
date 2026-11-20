package agent

import (
	"os/exec"
	"strings"
	"testing"
)

// Credential parsing: asset auth fields don't have fixed shapes (historically username/password/
// token/type/description and other key variants) — recognize loosely, use strictly.
func TestParseAuthEntriesRecognizesCommonKeys(t *testing.T) {
	raw := []map[string]any{
		{"type": "wordpress", "username": "admin", "password": "p@ss"},
		{"type": "bearer", "token": "abc.def.ghi"},
		{"user": "bob", "pass": "secret"},       // key-name variant
		{"token": "tk", "description": "admin"}, // with description
		{"nothing": "here"},                     // no usable field → placeholder (order kept)
	}
	entries := parseAuthEntries(raw)
	// Audit F1: output must be the same length and order as the input array — list_assets shows
	// the model the raw array order, and session_login's auth_index must share that source, or the
	// credential the model picked differs from the one actually sent.
	if len(entries) != 5 {
		t.Fatalf("parsed %d entries, should be 5 (same length as the input array, invalid entries as placeholders)", len(entries))
	}
	if entries[0].Username != "admin" || entries[0].Password != "p@ss" {
		t.Errorf("entries[0] should keep the original order: %+v", entries[0])
	}
	if entries[1].Token != "abc.def.ghi" {
		t.Errorf("entries[1] should keep the original order: %+v", entries[1])
	}
	if entries[4].valid() {
		t.Errorf("invalid entry should hold a zero value: %+v", entries[4])
	}
	// Key-name variants must be recognized.
	found := false
	for _, e := range entries {
		if e.Username == "bob" && e.Password == "secret" {
			found = true
		}
	}
	if !found {
		t.Error("key-name variant (user/pass) not recognized")
	}
	// The valid-index hint must exclude invalid entries.
	if got := validAuthIndices(entries); got != "0,1,2,3" {
		t.Errorf("validAuthIndices=%q, want 0,1,2,3", got)
	}
}

// With no credentials it returns a same-length placeholder list (the caller errors via valid()); the tool
// reports 'no credentials registered'.
func TestParseAuthEntriesEmptyWhenNoUsableFields(t *testing.T) {
	entries := parseAuthEntries([]map[string]any{{"foo": "bar"}, {"note": "x"}})
	if len(entries) != 2 {
		t.Fatalf("no credential fields must still match the input array length, got %d", len(entries))
	}
	for _, e := range entries {
		if e.valid() {
			t.Errorf("invalid entry should be a zero-value placeholder: %+v", e)
		}
	}
}

// Command building: auth scheme must match credential form.
func TestBuildAuthCurlAuthenticationForms(t *testing.T) {
	cases := []struct {
		name    string
		entry   authEntry
		wantHas []string
		wantNot []string
	}{
		{
			name:    "token goes via Authorization Bearer",
			entry:   authEntry{Token: "tk123"},
			wantHas: []string{"Authorization: Bearer tk123"},
			wantNot: []string{"Cookie:"},
		},
		{
			name:    "cookie-typed token goes via Cookie header",
			entry:   authEntry{Type: "session_cookie", Token: "PHPSESSID=abc"},
			wantHas: []string{"Cookie: PHPSESSID=abc"},
			wantNot: []string{"Authorization:"},
		},
		{
			name:    "user+pass goes via -u",
			entry:   authEntry{Username: "admin", Password: "pw"},
			wantHas: []string{"-u 'admin:pw'"},
			wantNot: []string{"Authorization:"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, err := buildAuthCurl("https://t.example.com/x", "GET", "", "", c.entry)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range c.wantHas {
				if !strings.Contains(cmd, w) {
					t.Errorf("command missing %q:\n%s", w, cmd)
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(cmd, w) {
					t.Errorf("command must not contain %q:\n%s", w, cmd)
				}
			}
		})
	}
}

// Special characters in credentials must escape correctly — generated passwords often contain ' $ " \;
// unescaped, the shell interprets them and the command runs **different credentials**.
//
// This is the classic 'looks runnable, actually runs wrong': the request returns 401, the model misjudges
// 'credential invalid' — the real cause is escaping dropped characters.
//
// Assertion method: **let shell parse it back to the original** — if escaping is right, what the shell restores equals the credential.
// More accurate than 'can the original string be found in the command' (after escaping it shouldn't appear verbatim anyway).
func TestBuildAuthCurlEscapesSpecialCharacters(t *testing.T) {
	tricky := []struct {
		name string
		val  string
	}{
		{"single quote", "pa'ss"},
		{"double quote", `pa"ss`},
		{"dollar sign", "pa$ss"},
		{"backtick", "pa`ss"},
		{"backslash", `pa\ss`},
		{"semicolon", "pa;ss"},
		{"space", "pa ss"},
		{"exclamation", "pa!ss"},
		{"parens", "pa(ss)"},
	}
	for _, c := range tricky {
		t.Run(c.name, func(t *testing.T) {
			cmd, err := buildAuthCurl("https://t.example.com/x", "GET", "", "",
				authEntry{Username: "admin", Password: c.val})
			if err != nil {
				t.Fatal(err)
			}
			// Extract the -u arg from the command, hand it to shell for parsing,
			// and check whether what it restores equals the original credential.
			got, ok := evalShellArg(t, cmd, "-u")
			if !ok {
				t.Fatalf("can't find -u arg in command:\n%s", cmd)
			}
			want := "admin:" + c.val
			if got != want {
				t.Errorf("shell-restored credential=%q, should be %q\ncommand: %s", got, want, cmd)
			}
		})
	}
}

// body and header need escaping too (bodies often carry JSON full of quotes).
func TestBuildAuthCurlEscapesBodyAndHeader(t *testing.T) {
	body := `{"a":"b","c":"d"}`
	header := "X-Test: it's fine"
	cmd, err := buildAuthCurl("https://t.example.com/x", "POST", body, header, authEntry{Token: "tk"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "--data-raw") {
		t.Errorf("missing --data-raw:\n%s", cmd)
	}
	// Double quotes inside body are literal under single-quote wrapping — shell restores them verbatim.
	gotBody, ok := evalShellArg(t, cmd, "--data-raw")
	if !ok {
		t.Fatalf("can't find --data-raw in command:\n%s", cmd)
	}
	if gotBody != body {
		t.Errorf("restored body=%q, should be %q", gotBody, body)
	}
	// The single quote in the header must be escaped (or it closes quoting early — everything after is a syntax error).
	gotHdr, ok := evalShellArg(t, cmd, "-H")
	if !ok {
		t.Fatalf("can't find -H in command:\n%s", cmd)
	}
	// -H appears twice (Authorization + extra header) — take the last.
	if gotHdr != "Authorization: Bearer tk" && gotHdr != header {
		t.Errorf("restored header=%q, should be %q or the Authorization header", gotHdr, header)
	}
	// The command must show escape traces (single quote turned into '\'').
	if !strings.Contains(cmd, `'\''`) {
		t.Errorf("single quote in header not escaped:\n%s", cmd)
	}
}

// Method must normalize to uppercase; default is GET.
func TestBuildAuthCurlNormalizesMethod(t *testing.T) {
	cmd, err := buildAuthCurl("https://t.example.com/x", "post", "", "", authEntry{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "-X 'POST'") {
		t.Errorf("method not uppercased:\n%s", cmd)
	}
	// Default method.
	cmd2, err := buildAuthCurl("https://t.example.com/x", "", "", "", authEntry{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd2, "-X 'GET'") {
		t.Errorf("default method should be GET:\n%s", cmd2)
	}
}

// evalShellArg uses a **real shell** to parse the command and extract the given option's arg value.
//
// Why a real shell: the criterion for correct escaping is 'the shell-restored value equals the original',
// which string assertions can't do — the original string shouldn't appear verbatim in an escaped command anyway.
// Only by letting sh parse it itself can you prove 'what runs is really that credential set'.
//
// Skip when sh isn't found (CI is ubuntu — always has sh; local Windows has Git Bash's sh).
func evalShellArg(t *testing.T, cmd, opt string) (string, bool) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found — skipping shell parse verification")
	}
	// Split words via `set --`, then print the arg after opt.
	script := `set -- ` + cmd + `
i=0
for a in "$@"; do
  if [ "$prev" = "` + opt + `" ]; then printf '%s' "$a"; exit 0; fi
  prev="$a"
done
exit 1`
	out, err := exec.Command(sh, "-c", script).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}
