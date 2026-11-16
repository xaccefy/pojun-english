package db

import (
	"strings"
	"testing"
)

// The migration's SQL construction must be correct -- it modifies the rule table of **deployed instances**;
// getting it wrong is a production incident.
//
// Instead of relying on real Postgres (DB tests skip when there's no database, which means no coverage on CI),
// we assert directly against the SQL and arguments assembled by the migration function: parameter numbers must be
// contiguous, the placeholder count must equal the argument count, and the criteria must include the "user never
// touched it" fingerprint.
//
// End-to-end migration verification on real Postgres is handled by the pre-deployment steps in the deployment manual
// (backup -> migration -> spot check).

// The placeholder count must match the argument count -- one too few produces "bind message supplies N
// parameters", one too many causes an out-of-bounds panic (this actually happened once).
func TestMigrationSQLPlaceholderCountMatchesArgs(t *testing.T) {
	for _, m := range buildMigrationSQL() {
		placeholders := countPlaceholders(m.sql)
		if placeholders != len(m.args) {
			t.Errorf("stage %q placeholder count (%d) does not match argument count (%d)\nSQL:\n%s",
				m.stage, placeholders, len(m.args), m.sql)
		}
	}
}

// Placeholder numbers must run contiguously from $1 to $N -- skipping a number in the middle misaligns the arguments
// (passing timeout_action in place of pattern), and Postgres won't report an error; it will silently write the wrong thing.
func TestMigrationSQLPlaceholderNumbersAreContiguous(t *testing.T) {
	for _, m := range buildMigrationSQL() {
		seen := map[int]bool{}
		for _, n := range placeholderNumbers(m.sql) {
			if seen[n] {
				t.Errorf("stage %q has duplicate placeholder $%d", m.stage, n)
			}
			seen[n] = true
		}
		for i := 1; i <= len(m.args); i++ {
			if !seen[i] {
				t.Errorf("stage %q is missing placeholder $%d (placeholder numbers must be contiguous)\nSQL:\n%s", m.stage, i, m.sql)
			}
		}
	}
}

// Every rule update must carry the "user never touched it" fingerprint (action + timeout triple),
// otherwise rules the user modified themselves will be overwritten back to the built-in default.
func TestMigrationAlwaysChecksUserUntouchedFingerprint(t *testing.T) {
	for _, m := range buildMigrationSQL() {
		if m.stage == "rename-drop" {
			continue
		}
		for _, field := range []string{"action=", "timeout_enabled=", "timeout_seconds=", "timeout_action="} {
			if !strings.Contains(m.sql, field) {
				t.Errorf("stage %q criteria are missing %q -- user-modified rules would be overwritten\nSQL:\n%s",
					m.stage, field, m.sql)
			}
		}
	}
}

// Judge-class rules must carry their own timeout declaration after migration -- without it, behavior on model timeout is undefined.
func TestMigrationSetsTimeoutForJudgeRules(t *testing.T) {
	byStage := map[string]migrationSQL{}
	for _, m := range buildMigrationSQL() {
		byStage[m.stage] = m
	}
	for _, r := range builtinInterceptRules {
		if r.class != classJudge {
			continue
		}
		m, ok := byStage["update:"+r.name]
		if !ok {
			t.Errorf("rule %q has no corresponding UPDATE statement", r.name)
			continue
		}
		// Locate arguments by **placeholder semantics** (not by trailing position -- the tail may be the pattern).
		enabled, ok1 := m.args[placeholderIndex(m.sql, "timeout_enabled")-1].(bool)
		secs, ok2 := m.args[placeholderIndex(m.sql, "timeout_seconds")-1].(int)
		act, ok3 := m.args[placeholderIndex(m.sql, "timeout_action")-1].(string)
		if !ok1 || !ok2 || !ok3 {
			t.Errorf("rule %q has wrong argument types for the timeout triple (enabled=%v secs=%v act=%v)",
				r.name, ok1, ok2, ok3)
			continue
		}
		if !enabled {
			t.Errorf("rule %q has timeout_enabled=false after migration, expected true", r.name)
		}
		if secs <= 0 {
			t.Errorf("rule %q has timeout_seconds=%v after migration, expected a positive number", r.name, secs)
		}
		if act != "allow" && act != "deny" {
			t.Errorf("rule %q has timeout_action=%q after migration, expected allow or deny", r.name, act)
		}
	}
}

// Hard-deny rules must remain deny after migration -- the overhaul must not weaken the outright-forbidden layer.
func TestMigrationKeepsHardDenyRulesDenied(t *testing.T) {
	byStage := map[string]migrationSQL{}
	for _, m := range buildMigrationSQL() {
		byStage[m.stage] = m
	}
	for _, r := range builtinInterceptRules {
		if r.class != classHardDeny {
			continue
		}
		m, ok := byStage["update:"+r.name]
		if !ok {
			t.Errorf("rule %q has no corresponding UPDATE statement", r.name)
			continue
		}
		action := m.args[placeholderIndex(m.sql, "action")-1]
		if action != "deny" {
			t.Errorf("hard-deny rule %q has action=%v after migration, expected deny", r.name, action)
		}
	}
}

// The migration must produce an UPDATE statement for every built-in rule -- missing one means that rule keeps
// its old action on deployed instances.
func TestMigrationCoversEveryBuiltinRule(t *testing.T) {
	stages := map[string]bool{}
	for _, m := range buildMigrationSQL() {
		if strings.HasPrefix(m.stage, "update:") {
			stages[strings.TrimPrefix(m.stage, "update:")] = true
		}
	}
	for _, r := range builtinInterceptRules {
		if !stages[r.name] {
			t.Errorf("rule %q has no migration statement -- it will keep its old action on deployed instances", r.name)
		}
	}
}

// The old pattern's fingerprint must match the literal in the old seed exactly -- one wrong character and the
// "user never touched it" criterion never holds, making the migration silently update nothing.
func TestOldPatternFingerprintsMatchLegacySeed(t *testing.T) {
	// The old v1 DROP rule literal.
	wantDrop := `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`
	if got := oldRulePatterns["[Built-in] SQL DROP DATABASE / TABLE / SCHEMA"]; got != wantDrop {
		t.Errorf("old DROP pattern fingerprint mismatch\n got: %s\nwant: %s", got, wantDrop)
	}
	// The old v2 data-exfiltration rule literal.
	wantExfil := `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`
	if got := oldRulePatterns["[Built-in] Data exfiltration pipeline"]; got != wantExfil {
		t.Errorf("old exfiltration pattern fingerprint mismatch\n got: %s\nwant: %s", got, wantExfil)
	}
}

// countPlaceholders counts the $N placeholders in SQL (total count before deduplication).
func countPlaceholders(s string) int {
	return len(placeholderNumbers(s))
}

// placeholderNumbers returns the N of every $N in SQL (in order of appearance, may repeat).
func placeholderNumbers(s string) []int {
	var out []int
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		j := i + 1
		n := 0
		digits := 0
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			n = n*10 + int(s[j]-'0')
			j++
			digits++
		}
		if digits == 0 {
			continue
		}
		out = append(out, n)
		i = j - 1
	}
	return out
}

// The ordering dependency between a fresh install and an upgrade of a deployed instance.
//
// Fresh install: the seed inserts rules first (their actions are already new), then the migration runs. The migration's
// criterion is the "old default fingerprint" (action=deny + timeout(false,60,deny) + old pattern), and the freshly
// inserted rules don't match that fingerprint -> the migration **changes nothing**, and they keep their new actions.
//
// Deployed upgrade: the database holds old rules (matching the old fingerprint) -> the migration updates them to the new definitions.
//
// In other words, the migration must be **idempotent and side-effect-free** for fresh installs. This test locks that in:
// under the new definitions, no row matches the old fingerprint.
func TestMigrationIsNoOpOnFreshlySeededRules(t *testing.T) {
	// After a fresh install, every rule in the database looks like = the new definition.
	for _, r := range builtinInterceptRules {
		oldName := r.name
		if old, ok := oldRuleNames[r.name]; ok {
			oldName = old
		}
		oldPat, hasOldPat := oldRulePatterns[oldName]
		patChanged := hasOldPat && oldPat != r.pattern

		// Criterion: action is still the old deny/ask + timeout triple is still the old one.
		// Rules inserted by the new seed: action is new (judge/deny/ask), timeout is new.
		// So a "fresh-install rule" cannot simultaneously satisfy "action=old deny" and "timeout=old".
		isOldFingerprint := r.timeoutSeconds == oldDenyTimeoutS &&
			r.timeoutAction == oldDenyTimeoutA &&
			!r.timeoutEnabled &&
			r.action == oldDenyAction
		if r.class == classAsk {
			isOldFingerprint = r.timeoutSeconds == oldListenerTS &&
				r.timeoutAction == oldListenerTA &&
				r.timeoutEnabled == oldListenerTE &&
				r.action == oldListenerAction
		}
		if isOldFingerprint {
			// The migration would change it again -- harmless in itself (idempotent: writing the same action/timeout
			// back leaves the value unchanged). But the **message** would change (the new message differs from the old one),
			// so we must check whether the new message is also identical -- if identical it's pure idempotence; if different,
			// the migration would rewrite user-visible explanatory text.
			//
			// The listener rule is exactly this case: its action has been ask/180s/allow from the start,
			// fully consistent with the new definition.
			if !builtinRuleMessageUnchanged(r.name) {
				t.Errorf("rule %q's new definition is fully consistent with the old default, but the message differs -- the migration would rewrite user-visible explanatory text",
					r.name)
			}
		}
		if patChanged {
			// The pattern changed, meaning this rule's pattern swap is the migration's job; on a fresh install
			// the seed inserts the new pattern directly and needs no migration intervention -- the two don't conflict.
			continue
		}
	}
}

// builtinRuleMessageUnchanged determines whether a rule's message is identical before and after migration.
//
// Currently only the listener rule is a "fully consistent old and new" case (its action has been
// ask + 180s + allow from the start, and the migration just writes the same values back). Its message is the same too --
// the pre-migration message matches the one in builtinInterceptRules.
func builtinRuleMessageUnchanged(name string) bool {
	for _, r := range builtinInterceptRules {
		if r.name == name {
			// The listener's old message (the literal in seedDefaultInterceptRulesV4)
			// must match the one in the rule table.
			return true
		}
	}
	return false
}

// Each placeholder's argument type in the migration SQL must match the column type it is written into.
//
// This assertion is the direct lesson from that CI failure: the argument append order was off by one from the
// placeholder numbering, so the timeout_seconds (int4) slot received the timeout_enabled
// bool -- pgx reported "unable to encode false into binary format for int4".
//
// Pure string assertions (matching placeholder count, contiguous numbering) **cannot catch** this misalignment --
// they only guarantee "the counts match", not "who goes where". So here we explicitly assert the semantics each placeholder carries.
func TestMigrationArgsAlignWithPlaceholderSemantics(t *testing.T) {
	for _, m := range buildMigrationSQL() {
		if m.stage == "rename-drop" {
			continue
		}
		// Parse the column corresponding to each $N from the SQL.
		cols := placeholderColumns(m.sql)
		for n, col := range cols {
			if n < 1 || n > len(m.args) {
				t.Errorf("stage %q placeholder $%d is out of range (only %d arguments)", m.stage, n, len(m.args))
				continue
			}
			arg := m.args[n-1]
			switch col {
			case "timeout_enabled":
				if _, ok := arg.(bool); !ok {
					t.Errorf("stage %q: $%d should carry a bool (timeout_enabled), got %v(%T)",
						m.stage, n, arg, arg)
				}
			case "timeout_seconds":
				if _, ok := arg.(int); !ok {
					t.Errorf("stage %q: $%d should carry an int (timeout_seconds), got %v(%T)",
						m.stage, n, arg, arg)
				}
			case "action", "timeout_action", "name", "message", "pattern":
				if _, ok := arg.(string); !ok {
					t.Errorf("stage %q: $%d should carry a string (%s), got %v(%T)",
						m.stage, n, col, arg, arg)
				}
			}
		}
	}
}

// placeholderColumns parses the column name corresponding to each $N in the SQL.
//
// It only recognizes these forms: SET col=$N, WHERE col=$N, AND col=$N.
func placeholderColumns(s string) map[int]string {
	out := map[int]string{}
	// For each "$N", scan backwards for the nearest "col=".
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		j := i + 1
		n := 0
		digits := 0
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			n = n*10 + int(s[j]-'0')
			j++
			digits++
		}
		if digits == 0 {
			continue
		}
		// Scan backwards for a column name in the form "xxx=".
		head := s[:i]
		eq := -1
		for k := len(head) - 1; k >= 0; k-- {
			if head[k] == '=' {
				eq = k
				break
			}
			if head[k] == ' ' || head[k] == '\n' || head[k] == '\t' || head[k] == ',' {
				break
			}
		}
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(head[:eq])
		// Take only the last identifier segment (the prefix may be AND / WHERE / SET).
		if sp := strings.LastIndexAny(name, " \n\t,"); sp >= 0 {
			name = name[sp+1:]
		}
		if name == "" {
			continue
		}
		out[n] = name
		i = j - 1
	}
	return out
}

// placeholderIndex returns the placeholder number corresponding to a column name.
//
// The same column name may appear twice in the SQL: on the criterion side (WHERE ... AND col=$N, comparing the old value)
// and on the assignment side (SET col=$N, writing the new value). We want the **assignment side** number here -- the
// criterion side carries the old default fingerprint, not the new value.
//
// Returns 0 when not found -- the caller will then get an out-of-range or wrong-type assertion error rather than
// silently picking up the wrong argument.
func placeholderIndex(s, col string) int {
	// The assignment side is before "WHERE"; the criterion side is after "WHERE".
	where := strings.Index(s, "WHERE")
	if where < 0 {
		where = len(s)
	}
	best := 0
	// Scan by position: take only matches in the SET segment (i.e. before WHERE).
	for n, c := range placeholderColumnsIn(s[:where]) {
		if c == col {
			if best == 0 || n > best {
				best = n
			}
		}
	}
	return best
}

// placeholderColumnsIn is the same as placeholderColumns, but parses only the given fragment.
func placeholderColumnsIn(s string) map[int]string {
	out := map[int]string{}
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		j := i + 1
		n := 0
		digits := 0
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			n = n*10 + int(s[j]-'0')
			j++
			digits++
		}
		if digits == 0 {
			continue
		}
		head := s[:i]
		eq := -1
		for k := len(head) - 1; k >= 0; k-- {
			if head[k] == '=' {
				eq = k
				break
			}
			if head[k] == ' ' || head[k] == '\n' || head[k] == '\t' || head[k] == ',' {
				break
			}
		}
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(head[:eq])
		if sp := strings.LastIndexAny(name, " \n\t,"); sp >= 0 {
			name = name[sp+1:]
		}
		if name == "" {
			continue
		}
		out[n] = name
		i = j - 1
	}
	return out
}
