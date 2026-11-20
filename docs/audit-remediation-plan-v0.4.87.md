# Audit remediation plan v0.4.87

> Source: the "this week (P1/P2 fixes)" batch from the 2026-11-18 three-agent audit
> (backend security B / functional quality F) + research (A) action list, 7 items. After
> it completes, move on to the "next batch".

## Scope (7 items, by audit id)

| Id | Level | Title |
|---|---|---|
| B4 | P2 | A mihomo subscription can inject listeners and open a public port |
| F4 | P2 | poc_scaffold cmdi regex double escaping false negative |
| F3 | P2 | job_start orphan processes on same-name concurrency (pause/delete can't kill them) |
| B2 | P2 | auth/init first-init squatting window |
| B3 | P2 | No request-body cap on authenticated endpoints (memory DoS) |
| F2 | P2 | Task delete/archive leaves intercept_pending/task_progress/credentials behind |
| F1 | P2 | auth_index out of step with list_assets credential order |

## Fixes

### B4: `mihomo/mihomo.go` writeConfig
- Append `delete(cfg, "listeners")` to the delete list
- Test: a YAML with `listeners: [{listen: 0.0.0.0}]` has no listeners key after the rewrite

### F4: `agent/poc_scaffold.go` cmdi template
- `r"uid=\\d+\\("` → `r"uid=\d+\("` (backticks pass through verbatim)
- Test: the generated script has the right regex and no `\\d`

### F3: `agent/tools_jobs.go` jobStart
- `jobLifecycleMu.RLock()` upgraded to `Lock()`: the whole "read old → kill old → start → register" is mutually exclusive for the same name
- Test: two goroutines starting the same-named job concurrently → only 1 surviving process, 1 meta entry, killable by cleanup

### B2: `server/auth.go` + `cmd/pojun/main.go`
- New `ensureSetupToken(dataDir)`: with no password set, ensure `<dataDir>/setup-token` (0600)
- `authInit` requires a matching `X-Setup-Token`; the file is deleted on success; 403 retained when a password is already set
- Test: refused without a token / succeeds with a token and deletes the file / 403 once set

### B3: `server/server.go`
- New `limitBody(32<<20)` middleware (outside `requireAuth`), exempting
  `POST /api/workspace/upload` (512MB) and `POST /api/chat/upload` (128MB)
- Test: 40MB JSON → 413; exempt paths unaffected

### F2: `db/tasks.go` + `db/task_archives_restore.go`
- DeleteTaskCascadePrepared's transaction gains DELETE statements: intercept_pending (task_id::text),
  task_progress, credential_access_log, credentials
- CompleteTaskArchive gains: task_progress / credentials / credential_access_log
- Test: the four tables are empty after a hard delete and an archive

### F1: `agent/tools_auth.go` + `agent/tools_http.go`
- parseAuthEntries drops the sort, invalid entries hold a placeholder (same length and order as the DB array)
- session_login: an all-empty placeholder reports "auth_index=N is not a valid credential entry" and lists the valid indices
- auth_request: without an index, picks the first valid credential
- Tool descriptions updated: auth_index follows the asset auth array's original order

## Verification

1. New unit tests per item (mihomo/poc_scaffold/jobs/auth/server/agent)
2. Full regression: `go build/vet` + `go test -p 1 ./db ./agent ./server ./guard ./intercept ./mihomo ./egress ./vault ./traffic` (recreate pojun_ci) + `tsc`
3. Kali field checks:
   - Temporary Windows instance: auth/init 403 without token → 200 with token and file deleted → 403 once set
   - Kali: mihomo start with a YAML carrying listeners → no listeners in the config on disk
   - Kali: diagnostics bundle export regression (19 sections, 0 errors)
   - Kali: health/version line check after deployment

## Release

CHANGELOG v0.4.87 (each fix entry lists its audit id) → tag/push → CI → Kali deploy v0.4.87.

## Risk and compatibility

- B2 is a behavior change: a brand-new deployment must read the setup-token (log + file, two entry points); existing deployments with a password set are unaffected
- B3's global 32MB is imperceptible for normal JSON; the two large upload paths are explicitly exempt
- F1 changes the default auth_index semantics (no longer token-first) — more predictable, tool descriptions follow
