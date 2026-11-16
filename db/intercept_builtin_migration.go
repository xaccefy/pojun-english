package db

import "fmt"

// One-off migration of built-in rule actions: change "always deny" into the three-way split
// "outright forbidden / hand to the Agent for judgement / human confirmation".
//
// Background (the 2026-10-22 overhaul): built-in rules were previously **all** deny, so the rule layer
// decided every kind of call -- "outright forbidden" and "hand to the Agent for judgement" were not
// separated at the rule layer at all and the model never got a chance to see these commands. That cut both ways:
//   - what should be blocked was blocked, but every hit burned a model round trip that could have been skipped;
//   - what should not be blocked was blocked outright (legitimate operations like dropping a test table you created were treated as destructive).
//
// The new boundary (criterion in db/intercept_builtin_rules.go): irreversible in any context with no
// legitimate use -> still deny; the target depends on context -> judge; only changes platform state -> ask.
//
// ## How user-modified rules are protected
//
// Built-in rules are a first-insert-only seed, so changing the code has no effect on deployed instances;
// hence a one-off migration. "This row is still the built-in default" is decided with the **old default fingerprint**:
// the row is updated only when its action / pattern / timeout combination still matches the old default.
// If the user switched the rule to judge, disabled it, changed the pattern or changed the timeout policy, behavior is always preserved.

// Old default fingerprint: the old default for v1/v2/v3 is uniformly deny + timeout(false, 60, deny);
// the v4 listener old default is ask + timeout(true, 180, allow).
const (
	oldDenyAction   = "deny"
	oldDenyTimeoutE = false
	oldDenyTimeoutS = 60
	oldDenyTimeoutA = "deny"

	oldListenerAction = "ask"
	oldListenerTE     = true
	oldListenerTS     = 180
	oldListenerTA     = "allow"
)

// oldRuleNames records each new rule's name in an old database.
//
// The v1 DROP rule was **one** merged rule covering DATABASE/TABLE/SCHEMA/INDEX/VIEW/...;
// the overhaul split it into two:
//   - DROP DATABASE / SCHEMA -> outright forbidden
//   - DROP TABLE / INDEX / VIEW etc. -> hand to the Agent for judgement
//
// The split must **rename** the old rule to the judge one (preserving the "user never touched it" decidability),
// while the hard-deny one is a new name -- it must be **inserted** (not renamed, otherwise the hard-deny rule would be missing).
// So "old name -> new name" here expresses a rename, and renameTargets marks which ones need renaming.
var oldRuleNames = map[string]string{
	"[Built-in] SQL DROP DATABASE / SCHEMA":    "[Built-in] SQL DROP DATABASE / TABLE / SCHEMA",
	"[Built-in] SQL DROP TABLE / INDEX / VIEW": "[Built-in] SQL DROP DATABASE / TABLE / SCHEMA",
}

// oldRulePatterns records the pattern of some rules in an old database.
//
// Only the ones **that differ from the new definition** are registered -- the rest never changed their pattern,
// so the migration need not touch it (nor use it as a "user never touched it" criterion).
//
// Two purposes:
//  1. as the "user never touched the pattern" criterion -- a rule whose pattern the user changed must not be overwritten;
//  2. to swap the old pattern for the new one during migration (changing the data-exfil rule pattern is part of this overhaul).
var oldRulePatterns = map[string]string{
	"[Built-in] SQL DROP DATABASE / TABLE / SCHEMA": `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
	"[Built-in] Data exfiltration pipeline":              `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
}

// migrationSQL is the shape of the two UPDATEs migrateBuiltinRuleActions actually executes.
//
// Why it is factored out as a testable pure function: the migration function itself needs a DB to run, while the
// correctness of the SQL (consecutive placeholder numbers, matching argument count, complete fingerprints) is a
// pure string problem -- only by peeling it away from the DB dependency can CI really test it.
type migrationSQL struct {
	sql   string
	args  []any
	stage string
}

// buildMigrationSQL builds every UPDATE the migration will execute (isomorphic to migrateBuiltinRuleActions).
// The real implementation calls it and the tests assert on it -- the two cannot drift apart.
func buildMigrationSQL() []migrationSQL {
	var out []migrationSQL

	// 1) Rename: the old merged DROP rule -> the judge rule's new name.
	oldDropName := "[Built-in] SQL DROP DATABASE / TABLE / SCHEMA"
	newDropJudgeName := "[Built-in] SQL DROP TABLE / INDEX / VIEW"
	out = append(out, migrationSQL{
		stage: "rename-drop",
		sql: `
UPDATE intercept_rules SET name=$2
 WHERE name=$1
   AND action=$3 AND timeout_enabled=$4 AND timeout_seconds=$5 AND timeout_action=$6
   AND pattern=$7`,
		args: []any{oldDropName, newDropJudgeName,
			oldDenyAction, oldDenyTimeoutE, oldDenyTimeoutS, oldDenyTimeoutA,
			oldRulePatterns[oldDropName]},
	})

	// 2) Update one by one.
	for _, r := range builtinInterceptRules {
		oldName := r.name
		if old, ok := oldRuleNames[r.name]; ok {
			oldName = old
		}
		oldPat, hasOldPat := oldRulePatterns[oldName]
		patChanged := hasOldPat && oldPat != r.pattern

		cond := `action=$2 AND timeout_enabled=$3 AND timeout_seconds=$4 AND timeout_action=$5`
		args := []any{r.name, oldDenyAction, oldDenyTimeoutE, oldDenyTimeoutS, oldDenyTimeoutA}
		if r.class == classAsk {
			args = []any{r.name, oldListenerAction, oldListenerTE, oldListenerTS, oldListenerTA}
		}
		if hasOldPat {
			cond += fmt.Sprintf(" AND pattern=$%d", len(args)+1)
			args = append(args, oldPat)
		}
		// The new values follow the criterion arguments, and the numbering must be consecutive.
		//
		// The append order of arguments must match the placeholder order in the SQL **exactly**:
		//   $1        name (criterion)
		//   $2..$5    old default fingerprint (action / timeout triple)
		//   $6        old pattern (only when the rule has a known old pattern)
		//   $7..$11   new values (action / message / timeout_enabled / timeout_seconds /
		//             timeout_action)
		//   $12       new pattern (only when the pattern really changes)
		//
		// Previously the pattern was appended first and the new values after, the reverse of the SQL numbering --
		// the whole argument list shifted and CI reported "encode false into int4" (the timeout_seconds slot
		// received a bool). This kind of misalignment only shows up by actually running PG once, which is why it
		// is also the origin of the "argument order must match placeholder order" assertion.
		setSQL := fmt.Sprintf(`
UPDATE intercept_rules
   SET action=$%d, message=$%d, timeout_enabled=$%d, timeout_seconds=$%d, timeout_action=$%d`,
			len(args)+1, len(args)+2, len(args)+3, len(args)+4, len(args)+5)
		args = append(args, r.action, r.message, r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction)
		if patChanged {
			setSQL += fmt.Sprintf(", pattern=$%d", len(args)+1)
			args = append(args, r.pattern)
		}
		out = append(out, migrationSQL{
			stage: "update:" + r.name,
			sql:   setSQL + "\n WHERE name=$1 AND " + cond,
			args:  args,
		})
	}
	return out
}

// migrateBuiltinRuleActions changes built-in rule actions to the new three-way split and adds the split-out
// new rules, replacing the patterns that need replacing.
//
// The migration has three steps and the order cannot change:
//  1. Rename: change the old merged DROP rule to the judge rule's new name (before renaming, use the old default
//     fingerprint to decide "the user never touched it").
//  2. Update: update action / message / timeout / pattern per the new definition.
//  3. Insert: insert the split-out new rule (the hard-deny DROP DATABASE/SCHEMA).
func (d *DB) migrateBuiltinRuleActions() error {
	const flag = "intercept_builtin_rule_actions_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	for _, m := range buildMigrationSQL() {
		if _, err := d.Exec(m.sql, m.args...); err != nil {
			return fmt.Errorf("migrate builtin rule actions (%s): %w", m.stage, err)
		}
	}
	// 3) Insert: the split-out new rule (the hard-deny DROP DATABASE / SCHEMA).
	//
	// Use INSERT ... WHERE NOT EXISTS: do not overwrite when the user already created a rule with the same name.
	for _, r := range builtinInterceptRules {
		if _, ok := oldRuleNames[r.name]; !ok {
			continue // already in the old database; the rename or update handled it

		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("insert split rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting(flag, "done")
}
