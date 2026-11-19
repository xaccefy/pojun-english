// Package db is the PostgreSQL data source for POJUN (replaces the old single-file SQLite graph).
// It opens connections, applies the schema, and seeds the built-in agents and variable catalog.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chu0119/pojun/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns is the connection pool cap; see the note in Open. The value is far below PostgreSQL's
// default max_connections=100, and at the same time far above the app's own nested connection depth
// (the startup schema advisory lock holds one connection while seedBuiltins takes another), so it cannot self-deadlock.
const maxOpenConns = 32

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env POJUN_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql puts no cap on connections by default: with no idle connection in the pool it
	// unconditionally opens a new one until PostgreSQL max_connections (default 100) refuses it, so
	// peak-hour queries get an **error** like `FATAL: sorry, too many clients already`. With a cap,
	// excess queries queue for an idle connection instead -- under the same load things get slower
	// rather than failing, and callers no longer have to tell "cannot read" apart from "there is
	// nothing". maxOpenConns must leave headroom for psql / reset-password.sh and other instances that may coexist; if max_connections was lowered, lower this too.
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // default interactive shell switch at row-creation time; ON CONFLICT does not overwrite a user's later manual toggle
	runSeconds            *int // per-run wall-clock cap at row-creation time (seconds); nil=seed default (1200), 0=unlimited
}

type promptVar struct{ name, desc, example, source string }

// intp returns a pointer to v, used to give a builtinAgent optional field (such as runSeconds) an explicit value.
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). Built-in tools are not persisted; only agents + the variable catalog are seeded here.
// Note: the interactive shell default for planner/worker/mainagent/auto is set uniformly by the
// interactive_shell_default_v1 block below (respecting later toggles); interactiveShell here only applies to new agents that must be on from row creation.
var builtinAgents = []builtinAgent{
	{"goals", "Goal decomposition", "goals", "Break a pentest task goal into several independent, verifiable sub-goals.", []promptVar{
		{"EngagementDescription", "Task description (target/background)", "Test the example.com site", "exploration"},
		// Now is a global runtime variable (see server.globalPromptVars) and is no longer defined in
		// each agent catalog, otherwise withGlobalVars would append a name collision with the global entry.
	}, false, nil},
	{"planner", "Planning", "planner", "Read the situation, judge the goal, and only add exploration intents when there is genuinely an uncovered new direction (one planning loop per task).", []promptVar{
		{"Goal", "Overall task goal", "Obtain admin access to example.com", "exploration"},
		{"AssetSummary", "Asset count/type distribution summary (optional)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "Main", "main", "Human interface: watch progress and turn a human intent into a hint or a high-priority intent.", []promptVar{
		{"Goal", "Current task goal", "Obtain admin access to example.com", "exploration"},
		{"AssetSummary", "Opening situation summary (optional)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "Confirmed findings summary (optional)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "Execution", "worker", "Claim one intent and execute it, then stop after writing the discovered facts/findings back to the knowledge graph.", []promptVar{
		{"ProxyAddr", "Recorded proxy address (drives the if double wording)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "worker self-identifier (optional)", "worker-1", "runtime"},
	}, false, nil},
	// Auto: the built-in "platform operations" agent. It does not take part in the pentest orchestration loop; it is driven from the chat page and operates the platform with tools.
	{"auto", "Auto", "assistant", "Platform operations assistant: manages tasks (create/view/pause/hint) and assets with tools, and can create/modify skills, custom tools, and MCP servers.", nil, false, nil},
	// Pentest: the built-in "standalone pentest" agent. Driven from the chat page, one agent runs the whole chain from recon to wrap-up, planning, executing and verifying on its own. Interactive shell on by default.
	{"pentest", "Pentest", "assistant", "Standalone pentest agent: one agent runs the whole chain recon -> attack surface -> exploitation -> verification -> wrap-up, planning, executing and adversarially verifying on its own.", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// After 'Now' was promoted from each agent catalog to a global runtime variable, old databases
	// still have a leftover 'Now' under goals that collides with the global entry (duplicate key in the frontend variable list); clear it too.
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Auto is by nature the "platform operations assistant": it should turn pentest requests into
	// tasks via spawn_task rather than running them on the machine with Bash/Write itself. Give
	// it Bash and the model almost inevitably acts on its own (measured: after being told to
	// delegate, Auto wrote a Python scanner and swept 10.10.0.0/16 without creating a single task) -- so local execution is off by default. One-shot + flag guard: if the user turns it back on later, a restart will not force it off again.
	if v, _, _ := d.GetSetting("local_exec_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET local_exec=false WHERE key='auto'`); err != nil {
			return fmt.Errorf("seed local_exec defaults: %w", err)
		}
		_ = d.SetSetting("local_exec_default_v1", "true")
	}
	// Seed the built-in browser (Playwright) MCP once — DISABLED by default (the user
	// enables it when needed), no proxy by default. The traffic-capture toggle injects/strips
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedBuiltinTaskPlaybooks(); err != nil {
		return fmt.Errorf("seed task playbooks: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return fmt.Errorf("seed intercept rules v2: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return fmt.Errorf("seed intercept rules v3: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV4(); err != nil {
		return fmt.Errorf("seed intercept rules v4: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV5(); err != nil {
		return fmt.Errorf("seed intercept rules v5: %w", err)
	}
	if err := d.seedInterceptToolCoverageV6(); err != nil {
		return fmt.Errorf("seed intercept tool coverage v6: %w", err)
	}
	if err := d.migrateListenerRuleTimeout(); err != nil {
		return fmt.Errorf("migrate listener rule timeout: %w", err)
	}
	if err := d.migrateBuiltinRulePatterns(); err != nil {
		return fmt.Errorf("migrate builtin rule patterns: %w", err)
	}
	if err := d.migrateBuiltinRuleActions(); err != nil {
		return fmt.Errorf("migrate builtin rule actions: %w", err)
	}
	if err := d.migrateJudgeTimeoutSeconds(); err != nil {
		return fmt.Errorf("migrate judge timeout: %w", err)
	}
	if err := d.migrateAgentRunSeconds(); err != nil {
		return fmt.Errorf("migrate agent run seconds: %w", err)
	}
	if err := d.migrateContextWindowK(); err != nil {
		return fmt.Errorf("migrate context window k: %w", err)
	}
	if err := d.seedDefaultAssetInterceptRules(); err != nil {
		return fmt.Errorf("seed asset intercept rules: %w", err)
	}
	return nil
}

// seedDefaultAssetInterceptRules inserts the built-in asset blocklist (fuzzy
// domain matches for government / education sites) once on first startup. Gated
// by a settings flag so a user's later disable/delete is never resurrected on
// restart — same policy as the intercept-rule seed.
func (d *DB) seedDefaultAssetInterceptRules() error {
	if v, _, _ := d.GetSetting("asset_intercept_default_rules_v1"); v == "done" {
		return nil
	}
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[Built-in] Government sites (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[Built-in] Government sites (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[Built-in] Education sites (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[Built-in] Education sites (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin)
VALUES (true, $1, $2, $3, true)
ON CONFLICT DO NOTHING`, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return d.SetSetting("asset_intercept_default_rules_v1", "done")
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. Binding policy (since v0.4.56): execution-class skills (attack techniques/post-exploitation/verification/reporting)
// are bound to worker and pentest by default; direction-class skills (intel/recon/0day/code audit) are also bound to planner,
// because "should we invest in this direction" is the planner's call. scopesentry (platform integration) stays
// invisible by default -- it depends on external MCP configuration, so the user enables it on demand. ON CONFLICT DO NOTHING ensures
// the user's later toggles are never resurrected by a restart.
var builtinSkillVisibility = map[string][]string{
	// Recon and interfaces
	"api-recon":            {"auto", "pentest", "worker"},
	"attack-surface-recon": {"planner", "pentest", "worker"},
	"api-security-testing": {"pentest", "worker"},
	// Methodology and verification
	"vuln-hunting":             {"planner", "worker"},
	"web-attack-methods":       {"pentest", "worker"},
	"component-vuln-intel":     {"planner", "pentest", "worker"},
	"source-code-hunting":      {"planner", "pentest", "worker"},
	"zero-day-research":        {"planner", "pentest", "worker"},
	"pentest-verification":     {"pentest", "worker"},
	"pentest-output-standards": {"pentest", "worker"},
	"src-acceptance":           {"planner", "pentest", "retester", "reporter", "worker"},
	// Scenario-specific
	"redteam-ops":              {"pentest", "worker"},
	"redteam-opsec":            {"pentest", "worker"},
	"cloud-attack-methods":     {"pentest", "worker"},
	"active-directory-attack":  {"pentest", "worker"},
	"ai-llm-app-attack":        {"pentest", "worker"},
	"binary-mobile-reversing":  {"pentest", "worker"},
	"smart-contract-audit":     {"pentest", "worker"},
	"wireless-hardware-attack": {"pentest", "worker"},
	// SRC methodology library (48 knowledge-base entries + 11 rules): the planner sets direction, executors look up details
	"src-hunting": {"planner", "pentest", "worker"},
	// Browser automation: available when a worker probes an SPA or authenticated state
	"playwright-cli": {"pentest", "worker"},
	"apk-reverse":    {"pentest", "worker"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedBuiltinInterceptRulesBatch inserts one batch of built-in intercept rules.
//
// The rule content all comes from builtinInterceptRules (db/intercept_builtin_rules.go) -- that is
// the single source of truth for built-in rules, and the classes (outright forbidden / hand to the
// Agent for judgement / human confirmation) are declared there with their rationale. This only decides "whether to insert".
//
// The batching is historical: built-in rules were added batch by batch, each batch has its own settings flag
// (intercept_default_rules_v1...v4), and a deployed instance uses the flag to decide "should this batch still be inserted".
// On a fresh install all four batches run in order, which is equivalent to inserting everything at once.
//
// Instances whose flag is already "done" are skipped outright -- the user's later disables/deletes/action changes are never resurrected.
func (d *DB) seedBuiltinInterceptRulesBatch(batch, flag string) error {
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	for _, r := range builtinInterceptRules {
		if r.seedBatch != batch {
			continue
		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting(flag, "done")
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	return d.seedBuiltinInterceptRulesBatch("v1", "intercept_default_rules_v1")
}

// seedDefaultInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. Gated by its own flag so it also lands on DBs that already ran
// v1. Unlike the old guard.go floor, these are plain [Built-in] rules — the user can
// disable or delete them.
func (d *DB) seedDefaultInterceptRulesV2() error {
	return d.seedBuiltinInterceptRulesBatch("v2", "intercept_default_rules_v2")
}

// seedDefaultInterceptRulesV3 adds the delete-endpoint path rule. The v1 HTTP rules
// only catch the DELETE *method*, so a plain `curl 'http://t/api/user/delete?id=1'`
// (a delete endpoint reached with GET/POST, which is how most web apps expose
// deletion) would otherwise slip through every built-in rule.
//
// deleteEndpointPathPattern is the regex of the "delete-class endpoint path" rule.
//
// Derived from the built-in rule table (rather than copied again) -- a rule pattern is defined in one place,
// avoiding the drift of "changed the one in the table, forgot the one in the constant". The name is kept so
// a unit test can assert this regex directly without a database.
var deleteEndpointPathPattern = builtinRulePattern("[Built-in] Delete-class endpoint path")

func (d *DB) seedDefaultInterceptRulesV3() error {
	return d.seedBuiltinInterceptRulesBatch("v3", "intercept_default_rules_v3")
}

// seedDefaultInterceptRulesV4 re-seeds the callback-listener approval boundary
// (v0.3.87: the listener tools got a real implementation, so the ask rule is
// back and the intercept gate needs the tool names again).
//
// ⚠️ Fix for an upgrade-path defect (measured on Kali, 2026-10-30): the v4 flag was already set
// to "done" in v0.3.86 -- the rule was deleted at that point. Going straight through the batch
// returns at the flag early-exit, so the new rule never lands on existing instances. So, outside
// the flag, this **re-seeds by rule name**: insert when the rule row does not exist (leave it alone when it does -- any user edit stays in effect).
func (d *DB) seedDefaultInterceptRulesV4() error {
	if err := d.seedBuiltinInterceptRulesBatch("v4", "intercept_default_rules_v4_listener"); err != nil {
		return err
	}
	// Re-seed by name: the flag early-exit can also swallow a new rule (instances that installed v0.3.86 fresh and upgraded to v0.3.87).
	for _, r := range builtinInterceptRules {
		if r.name != "[Built-in] Start/stop reverse-connection receiver" {
			continue
		}
		var exists bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM intercept_rules WHERE name=$1)`, r.name).Scan(&exists); err != nil {
			return fmt.Errorf("probe listener rule: %w", err)
		}
		if exists {
			continue // already present (seeded by v0.3.85 or edited by the user) -- leave it alone
		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("reseed listener rule: %w", err)
		}
	}
	// No persisted list means Interceptor uses its code defaults (which already
	// include the listener tools). Existing installations need a one-time append.
	if raw, ok, err := d.GetSetting("intercept_enabled_tools"); err != nil {
		return err
	} else if ok {
		if merged, changed := mergeEnabledInterceptTools(raw, "listener_start", "listener_stop"); changed {
			if err := d.SetSetting("intercept_enabled_tools", merged); err != nil {
				return err
			}
		}
	}
	return nil
}

// seedInterceptToolCoverageV6 merges the v6 coverage additions into a persisted
// enabled-tools list (the same one-shot append as V4/V5 — instances that never
// saved a list pick them up through the code defaults). These are the
// side-effect/exec/network tools that used to silently bypass interception:
// job_start (Bash-equivalent exec), script/evidence writes, target/network tools,
// the mcp__* prefix wildcard, and every already-enabled non-shell custom tool
// (their keys are user-chosen so they can't ride the code defaults — creation
// now merges them, this backfills the pre-existing ones). One-shot, flag-guarded
// like the rule batches.
func (d *DB) seedInterceptToolCoverageV6() error {
	const flag = "intercept_enabled_tools_v6"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	additions := []string{
		"job_start", "job_stop",
		"run_script", "save_script", "save_evidence", "poc_scaffold",
		"http_request", "session_login", "http_probe", "auth_request",
		"js_audit", "scan_with_nuclei", "NotebookEdit", "mcp__*",
	}
	if customs, err := d.ListCustomTools(); err == nil {
		for _, ct := range customs {
			if ct.Enabled && ct.Kind != "shell" {
				additions = append(additions, ct.Key)
			}
		}
	}
	if raw, ok, err := d.GetSetting("intercept_enabled_tools"); err != nil {
		return err
	} else if ok {
		if merged, changed := mergeEnabledInterceptTools(raw, additions...); changed {
			if err := d.SetSetting("intercept_enabled_tools", merged); err != nil {
				return err
			}
		}
	}
	return d.SetSetting(flag, "done")
}

// MergeEnabledInterceptTools is the exported form of the append-only merge:
// callers that can't reach mergeEnabledInterceptTools (e.g. the server wiring a
// new custom tool into interception) use it. It does NOT write — returns the
// merged JSON so the caller decides when/if to persist.
func (d *DB) MergeEnabledInterceptTools(raw string, additions ...string) (string, bool) {
	return mergeEnabledInterceptTools(raw, additions...)
}

// mergeEnabledInterceptTools appends newly introduced tools to a persisted
// intercept-enabled list without reordering or removing the user's choices. A
// malformed setting is left untouched instead of silently replacing user data.
func mergeEnabledInterceptTools(raw string, additions ...string) (string, bool) {
	var tools []string
	if err := json.Unmarshal([]byte(raw), &tools); err != nil {
		return raw, false
	}
	seen := make(map[string]struct{}, len(tools)+len(additions))
	for _, name := range tools {
		seen[name] = struct{}{}
	}
	changed := false
	for _, name := range additions {
		if _, ok := seen[name]; ok {
			continue
		}
		tools = append(tools, name)
		seen[name] = struct{}{}
		changed = true
	}
	if !changed {
		return raw, false
	}
	encoded, err := json.Marshal(tools)
	if err != nil {
		return raw, false
	}
	return string(encoded), true
}

// migrateBuiltinRulePatterns swaps two built-in rules that measured as false positives for narrowed regexes.
//
// The false positives (all from production intercept history, all legitimate pentest probe commands):
//
//	rm -f /tmp_out.$$                     -> hit "delete system critical directory" (bare / branch)
//	rm -f /usr/share/nmap/scripts/_t.nse  -> same
//	for p in /api/.../reboot ...          -> hit "shutdown / reboot" (the reboot inside a path)
//
// Rules are a first-insert-only seed, so changing the code has no effect on deployed instances; hence a one-off migration
// to sync the pattern. **Only the pattern changes; action/enabled/priority do not** -- on instances where
// the user switched the rule to judge or disabled it, behavior is preserved.
func (d *DB) migrateBuiltinRulePatterns() error {
	const flag = "intercept_builtin_rule_patterns_v2"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	updates := []struct{ name, pattern string }{
		{
			"[Built-in] Delete critical system directories",
			`\brm\b[^"'\n]{0,60}["'\s](/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:["'\s]|$|/(?:["'\s]|$)))`,
		},
		{
			"[Built-in] Shutdown / reboot",
			`(?:^|[;&|]\s*|\b(?:sudo|doas)\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b`,
		},
	}
	for _, u := range updates {
		if _, err := d.Exec(`UPDATE intercept_rules SET pattern=$2 WHERE name=$1`, u.name, u.pattern); err != nil {
			return fmt.Errorf("rule %q: %w", u.name, err)
		}
	}
	// Add the "clear system critical directory" rule (rm -rf /var/lib/* empties the whole tree).
	// The narrowed "delete system critical directory" no longer covers this shape, so it needs its own rule.
	const clearName = "[Built-in] Clear critical system directories"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, 100, 'tool_input', 'regex', $2, 'deny', $3, false, 60, 'allow'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
		clearName,
		`\brm\b[^"'\n]{0,120}["'\s][^"'\n]{0,80}/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)/\*`,
		"Emptying the contents of a system critical directory is forbidden",
	); err != nil {
		return fmt.Errorf("rule %q: %w", clearName, err)
	}
	return d.SetSetting(flag, "done")
}

// migrateContextWindowK changes the LLM config context window from "unset (treated as 200K)" to
// an explicit 1000K (1M).
//
// Why: the minimax-m3.1-flash-free commonly used on this platform has a native 1M context (the model
// self-reports 1000000), while an empty profile context_window_k made the code use 200K (the Claude
// default) for the compaction threshold. Compaction then triggered far below the limit -- and compaction
// itself costs an extra LLM call (with a 32768 budget), burning budget for nothing and slowing things down.
//
// Only rows still at 0 (unset) change: instances where the user filled in a window size are left alone.
func (d *DB) migrateContextWindowK() error {
	const flag = "llm_profiles_context_window_1000k_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`UPDATE llm_profiles SET context_window_k=1000 WHERE COALESCE(context_window_k,0)=0`); err != nil {
		return fmt.Errorf("context window k: %w", err)
	}
	return d.SetSetting(flag, "done")
}

// migrateAgentRunSeconds moves each agent's per-run wall-clock budget from 3600s back to 1200s.
//
// Background: the 2026-10-20 migration (agents_run_seconds_3600_v1) raised 1200s to 3600s,
// on the judgement that it was "too tight" -- measured in production, 89 intents ended exhausted vs 8 done.
//
// That attribution was wrong. exhausted is not a failure signal, it means "this small step did not finish": the
// POJUN-upstream seed default is 1200s, and the loop "short run -> exhausted -> planner reads the
// trace to judge progress -> dispatch again or change approach" forms a short-step loop that never needs a long run.
//
// Stretching it to 3600s broke that loop instead: a run dragged out to an hour hits hard limits,
// the planner sees nothing but "run timed out" -> dispatches the same chain again -> on 2026-10-21,
// of 26 measured intents 4 ran the full 3600s and then ended exhausted, 4.1 machine-hours in total with zero facts produced.
//
// The other confounder at the time has since been fixed separately: the context window went from 200K to 1M.
// Compacting too early burns a whole round of LLM budget and indirectly makes an intent look "unfinishable" --
// that was a context problem, not a wall-clock problem. Changing both at once meant attributing two mixed variables to one.
//
// Only rows still at 3600 change: instances the user tuned are left alone.
func (d *DB) migrateAgentRunSeconds() error {
	const flag = "agents_run_seconds_1200_v2"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if err := d.applyAgentRunSeconds(3600, 1200); err != nil {
		return err
	}
	return d.SetSetting(flag, "done")
}

// applyAgentRunSeconds changes rows with run_seconds=from to to.
//
// It is factored out so the "migration direction" invariant can be tested directly: that earlier 1200->3600
// migration was the root of the detour, and it is a one-off migration -- once it has run it is gone and the direction can never be verified afterwards.
// Keeping it as testable pure logic (rather than hidden behind a one-off flag) is what lets a unit test lock it down.
func (d *DB) applyAgentRunSeconds(from, to int) error {
	if _, err := d.Exec(`UPDATE agents SET run_seconds=$2 WHERE run_seconds=$1`, from, to); err != nil {
		return fmt.Errorf("agent run seconds %d->%d: %w", from, to, err)
	}
	return nil
}

// migrateJudgeTimeoutSeconds raises the model verdict wall-clock cap from 90s to 180s.
//
// Why: a thinking model's verdict time (MiniMax-M3.1 and others that force adaptive thinking) varies with
// command length -- measured 4-26 seconds for short commands, and for long commands (shell scripts of
// hundreds to thousands of characters) clearly longer; and an empty body triggers a higher-budget retry
// (32768 -> 65536) that has to fit inside the same timeout window. 90s turns "the model could actually
// have decided this" into a timeout failure (24 such timeout records were already measured in production).
//
// Only instances still at the default 90 change: values the user tuned are left alone.
func (d *DB) migrateJudgeTimeoutSeconds() error {
	const flag = "intercept_judge_timeout_180_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`
UPDATE settings SET value='180', updated_at=now()
WHERE key='llm_judge_timeout_seconds' AND value IN ('90','90.0',' 90 ')`); err != nil {
		return fmt.Errorf("judge timeout: %w", err)
	}
	return d.SetSetting(flag, "done")
}

// seedDefaultInterceptRulesV5 brings goal_met into the intercept system
// (v0.3.88 review S3): add the judge rule + merge goal_met into the saved enabled tool set
// (instances that never saved use the code default defaultEnabledTools, which already includes it).
func (d *DB) seedDefaultInterceptRulesV5() error {
	if err := d.seedBuiltinInterceptRulesBatch("v5", "intercept_default_rules_v5_goalmet"); err != nil {
		return err
	}
	// Re-seed by name: the flag early-exit can also swallow a new rule (the V4 lesson: instances that
	// installed v0.3.86 fresh and upgraded to 0.3.87 were missing the listener rule -- the flag was set to done before the rule entered the catalog).
	for _, r := range builtinInterceptRules {
		if r.seedBatch != "v5" {
			continue
		}
		var exists bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM intercept_rules WHERE name=$1)`, r.name).Scan(&exists); err != nil {
			return fmt.Errorf("probe v5 rule %q: %w", r.name, err)
		}
		if exists {
			continue // edited by the user or already inserted -- leave it alone
		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("reseed v5 rule %q: %w", r.name, err)
		}
	}
	// Instances that already saved an enabled tool set get goal_met appended (the same one-off append as V4).
	if raw, ok, err := d.GetSetting("intercept_enabled_tools"); err != nil {
		return err
	} else if ok {
		if merged, changed := mergeEnabledInterceptTools(raw, "goal_met"); changed {
			if err := d.SetSetting("intercept_enabled_tools", merged); err != nil {
				return err
			}
		}
	}
	return nil
}

// migrateListenerRuleTimeout changes the timeout policy of the "start/stop callback listener" ask rule
// from deny to allow and the duration from 300s to 180s.
//
// Why: ask **blocks synchronously** and the worker waits for a human decision. With no operator at the
// keyboard, deny means the whole pentest chain is stuck on that one command. Allowing it only affects that
// one command; the record is still visible on the "Intercept Approvals" page afterwards and can be ratified.
//
// The seed is first-insert only (ON CONFLICT DO NOTHING), so changing the seed has no effect on
// deployed instances; hence a one-off migration. Only the timeout field changes; action is untouched --
// instances where the user switched the rule to judge are unaffected.
func (d *DB) migrateListenerRuleTimeout() error {
	const flag = "intercept_listener_rule_timeout_allow_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`
UPDATE intercept_rules
   SET timeout_enabled = true,
       timeout_seconds = 180,
       timeout_action = 'allow'
 WHERE name = '[Built-in] Start/stop reverse-connection receiver'
   AND timeout_action <> 'allow'`); err != nil {
		return err
	}
	return d.SetSetting(flag, "done")
}
