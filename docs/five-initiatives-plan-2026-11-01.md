# Five-Item Implementation Plan — 2026-11-01

> Source: the carried-over items in `docs/deep-optimization-plan-2026-10-31.md` + the defect list in `docs/product-improvement-list-2026-10-29.md`,
> with the scope confirmed in the 2026-11-01 session. Target version v0.3.96 (the release action is left for human confirmation and is not executed automatically by this plan).

## Scope at a glance

| # | Item | Batch | Size estimate | Risk |
|---|------|------|----------|------|
| 1 | B10 independent profile for the compactor (backend + settings + frontend) | Batch 1 | ~150 lines | Low |
| 2 | B2 review trigger for exhausted with zero write-back | Batch 2 | ~60 lines | Low |
| 3 | B6 attribution samples for Guard | Batch 2 | ~50 lines | Low |
| 4 | B7 intent-level token accounting | Batch 2 | ~120 lines | Medium (includes a table migration) |
| 5 | Engineering friction debt: devtest script / conditional mock / JWT query tightening | Batch 3 | ~120 lines | Low |
| — | N2 scope-aware intercept v1 | Batch 4 · if progress allows | ~200 lines | Medium |
| — | Attack-chain presentation (G6 chain graph + Word attack path) | Batch 4 · if progress allows | Large | — |

Explicitly **not doing**: the norma `llm.Config` thinking_budget knob (needs a fork release, too heavy);
hourly windowing of B2 attribution samples (disproportionate complexity; land the ring buffer first).

Key discipline (AGENTS.md): when changing tables outside schema.sql, maintain their own migrations at the same time; a new tool must go into all three lists
(this plan adds no agent tools, so that doesn't apply); frontend verification `cd web && npx tsc --noEmit`; the backend `go build ./...`
issues along with the full Docker PG test run.

---

## Batch 1 · B10 independent profile for the compactor

### Current state
`agentsForTask` (`server/task_llm.go:711`): `agent.NewCompactor(plannerRuntime, "task-router")` —
the compactor shares the planner's model and follows the task LLM chain (failover, quota rotation). Cold-node major/minor compaction is a one-shot
**Complete call** (`agent/compaction.go`), so its model requirements differ completely from the planner's long-session needs, yet it is forced to share them.
The scenario where a user pins a cheap fast model to run the planner and then has compaction burn expensive quota really happens.

### Approach

1. `server/task_llm.go`
   - `taskLLMRuntime` gains a `pin int64` field (0 = not pinned, follow the original chain).
   - `current()` (:119-156) gains a pin branch at the entry:
     ```go
     if r.pin > 0 {
         if prov, cfg, ok := r.s.providerForProfile(r.pin); ok {
             sel.provider, sel.retry = prov, cfg.Retry
             return sel, nil // binding semantics: profileID stays 0, a quota error doesn't advance the task chain
         }
         // pin invalid (config deleted / no key) → fall back to the original chain and keep running
     }
     ```
   - `agentsForTask`: read `s.m.pg.GetSetting("compactor_profile_id")` to build an independent runtime,
     `agent.NewCompactor(compactorRuntime, "task-router")`. The runtime struct carries
     methods such as `CompactionWindow/nonStreaming/maxTokens` (same semantics as plannerRuntime; the measured behaviour is authoritative).
2. `server/server.go`
   - `settingsPayload()` gains `"compactor_profile_id": <int64>` (0 = follow the planner; echoed back so it is visible).
   - `putSettings` gains `CompactorProfile *int64 \`json:"compactor_profile_id"\``,
     `*v >= 0` stores `SetSetting("compactor_profile_id", int)` (<=0 clears it). Effect timing: the setting is read at
     agentsForTask **build time**, so a changed value applies to later tasks while the current task's compactor keeps running — the same
     semantics as the `workers` setting (applies to tasks started afterwards); state this in a comment.
3. Frontend
   - the `Settings` type in `web/src/lib/types.ts` gains `compactor_profile_id?: number`.
   - `web/src/app/(main)/system/settings/page.tsx`: the compaction settings card (where
     `compaction_max_tokens` lives now, around :66/:110) gains a "compactor model" dropdown:
     options = `Follow planner (default)` + the profiles list (`api.listLLMProfiles()`; the llm page already fetches it the same way).

### Verification
`go build ./...`; the manual persuasion case = set the pin → run a round of a new task and watch the profile_name of the `compactor/session`
row in llm_usage change (with llm_record on, look at the session id `exp%d-compactor`).

---

## Batch 2 · B2 / B6 / B7 (finishing "judgement has data")

### B2 review trigger for exhausted with zero write-back

Current state: in the settlement block at `server/engine.go:1264-1303`, an intent that ended exhausted (step cap hit / timeout) with `wrote == (agent.WriteCounts{})`
(the `agent` package; fields Facts/Assets/Findings, zero judged by `.Total()==0`) is a direction that "burned a whole round of tokens and left
no fact at all", and the planner usually treats it as an ordinary done — B1 persisted stop_reason but nothing triggers the review itself.

Approach:
1. `server/manager.go`, mirroring `NotifyCancelled` (around :2075), add
   `NotifyReview(intentID int64, detail string)` → `pendingTriggers` appends
   `agent.TriggerEvent{Kind: "review", IntentID: intentID, Detail: detail}`.
2. `server/engine.go`: in the settlement block, after `case reason == harness.ReasonMaxTurns / ReasonTimeout` and before the terminal state is
   persisted (where the state is already determined), check:
   ```go
   if state == "exhausted" && wrote.Total() == 0 {
       // collect the intent's last ~3 step summaries (worker trace); source and truncation below
       t.NotifyReview(intent.ID, fmt.Sprintf("...zero-writeback review instruction + step digest"))
   }
   ```
   Step-digest collection: reuse the worker trace read (the same db method as `list_worker_traces`; if no cheap
   existing interface turns up, substitute the recent worker event summaries for that intent from the activity stream — pick one at implementation
   time and note it in a comment). **Do not** go through the engine's timeout settlement path (the settling branch in `engine_timeout.go`) — context is missing there and it is already overdue.
3. `agent/planner.go` `renderTriggers` (:178-225) gains `case "review"`:
   the event text = intent #id (summary) + Detail (step recap + instruction);
   the instruction's tone: "this round wrote almost nothing back (facts 0 / assets 0) — keep the step lineage (land one fact via derived_from) before judging".
   **Don't change the planner seed prompt** (avoiding SeedPromptVersioned churn; the trigger instruction is embedded in the event text).

Verification: run a single simulated worker scenario that hits the step cap (the growth harness already has an exhausted precedent test to adapt),
and assert the planner's next-round input contains the review text.

### B6 Attribution samples for Guard

Current state: `guard/guard.go` has only counters (`attrib map[string]int`, postToolUse :171-186); the planner sees blocked/error counts without knowing **which
command was blocked**, and can't match them up during an exhausted review.

Approach:
1. `guard/guard.go`
   - add `type AttribSample struct{ Tool, Command string; TS int64 }` and `attribSamples map[string][]AttribSample`,
     keeping the last 3 per category with the command truncated to 200 bytes.
   - `AttributionStats() map[string]any`: `{"blocked": n, "error": n, "ok": n,
     "samples": {"blocked": [{tool,command}...], "error": [...]}}`.
   - `Attributions()` (map[string]int) is **kept**, not deleted (other callers exist: the task page reads attribution counts directly).
2. `server/task_llm.go:704/:730`: `pl.SetAttributions(t.Guard.Attributions)` becomes the adapter closure
   `func() map[string]any { return t.Guard.AttributionStats() }`; `main.SetAttributions` likewise.
3. `agent/tools.go`: the `ToolSet.attributions` field and the `SetAttributions` signature go from `map[string]int` to
   `map[string]any`; the render site `out["guard_attributions"]` (:603-607) needs no big change (drop the map straight in).
   The planner prompt isn't lengthened — the data carries its own shape and the sample-array field names are self-explanatory.

### B7 Intent-level token accounting

Current state: `parseSession` at `llmrec/llmrec.go:90-110` drops the `i3` suffix of `exp1-worker-i3` outright → llm_usage
only has exp granularity, so colouring intents in the posture by "which direction burned how much money" is impossible.

Approach:
1. `llmrec/llmrec.go`
   - `parseSession` gains a third return value `intentID int64` (suffix shaped like `i<n>`, otherwise 0);
     this also covers the existing `exp2-planner` (no suffix → 0). The return signature changes → update the call sites :126/:248 in step
     (the second is Complete? measured: two recordUsage calls at :170/:248 and one parseSession call).
   - `recordUsage` gains an intentID parameter, passed on to `db.InsertLLMUsage`.
2. `db/llm_usage.go`
   - `LLMUsage` gains `IntentID int64`;
   - **`llm_usage` is not in schema.sql; it is managed by the `llmUsageSchema` constant** (:29-48) — the new column
     `intent_id BIGINT` goes into the constant (new DBs) + `EnsureLLMUsageTable` adds
     `ALTER TABLE llm_usage ADD COLUMN IF NOT EXISTS intent_id BIGINT` after creating the table (old DBs, PG14+ syntax;
     CI uses PG16 so that's fine).
   - `InsertLLMUsage` SQL gains the column.
   - `ExplorationStore` gains `TokenByIntent()` (the token area of `db/exploration.go`, near `TokenStatsByWorker`
     :1544):
     ```sql
     SELECT intent_id, COUNT(*), SUM(input_tokens+cache_read+cache_write), SUM(output_tokens)
     FROM llm_usage WHERE exploration_id=$1 AND intent_id>0 GROUP BY intent_id
     ```
     returning `[]IntentTokenUsage{IntentID, Calls, InputTokens, OutputTokens}`.
3. `agent/tools.go` `graphOverviewData` (:470-619)
   - `compactIntents` (:22-) gains a fourth parameter `tokens map[int64]int64` (total tokens, omitted when 0);
     the three call sites `open/running/recent_done` pull the map once from `t.ts.TokenByIntent()` and pass it in.
   - the rendered field name is `tokens`; the intent card shows `≈✕K tok`.

### Verification
- B7: the full Docker PG test run (the table migration goes through EnsureLLMUsageTable's old-DB ALTER branch — a new DB has the column in its schema directly).
- B6/B2: unit tests for the guard sample ring + the engine's pending-write-back branch (constructing a blocked worker response).

---

## Batch 3 · Engineering friction debt

### scripts/devtest (codifying the AGENTS.md recipe)

New files `ARTEX/scripts/devtest.ps1` (primary on Windows) + `ARTEX/scripts/devtest.sh` (CI/Git Bash):
- if the `artex-devtest-pg` container isn't running, `docker run -d --name artex-devtest-pg -e ... postgres:16-alpine`,
  then wait for ready (a bounded `pg_isready` loop);
- `DROP DATABASE IF EXISTS artex_ci; CREATE DATABASE artex_ci OWNER artex` (a fresh DB; a shared DB invites false failures);
- `POJUN_PG_DSN=postgres://artex:artextest@127.0.0.1:15432/artex_ci?sslmode=disable go test -p 1 ./... -count=1`.
- a `-SkipFresh` parameter (don't recreate the DB) for quick iteration; the default is **always** a fresh DB.

### Conditional web mock (~242KB off the first screen)

Current state: `web/src/lib/api.ts:7-8,128` unconditionally does `import { mockHandle } from "@/lib/mock/handler"`,
dragging `mock/data.ts` (242KB of Vercel demo data) into the main bundle — loaded for nothing in production (with NEXT_PUBLIC_MOCK unset).

Approach: turn that spot in `api.ts` into a dynamic import:
```ts
if (MOCK) {
  const { mockHandle } = await import("@/lib/mock/handler");
  return mockHandle<T>(init?.method ?? "GET", path, init?.body ?? null);
}
```
When `MOCK === false`, webpack's DefinePlugin replacement + DCE means the chunk is never reached (regardless of whether the chunk is still emitted),
so the first-screen main bundle no longer contains data.ts. The function is already async (returns a Promise), so callers are unaffected.
Verification: `cd web && npx tsc --noEmit` + `NEXT_EXPORT=1 npx next build`, comparing main chunk sizes.

### JWT query token tightening (half of the N1 debt)

Current state: `extractToken` at `server/auth.go:258-266` accepts a `?token=` query on any path — a risk of the token landing in
access logs/Referer. It originally existed for SSE (the browser's EventSource can't send headers).

Approach: only allow `?token=` for SSE endpoints accessed directly by URL (whitelist prefix/exact match; check the registrations in `server.go:680-1000`):
`/api/exploration/activity/stream`, `/api/logs/stream`, `/api/update/stream`,
`/api/side-questions/{requestID}/events`. Other paths no longer take the token from the query (cookie/bearer are
still supported and unaffected). The frontend already uses both cookie and sessionStorage paths, so there's no regression surface.
Verification: a manual curl with no token returns 401 and an SSE request with a token returns 200.

---

## Batch 4 · If progress allows (not guaranteed by this session's main line)

### N2 scope-aware intercept v1
Direction: intercept rules take effect per task/intent scope (today the three global rule sets cross-harm each other when tasks run concurrently). The change stays inside
`intercept/` and `seedBuiltinInterceptRulesBatch`; it involves a new DB column + the frontend rule-edit page, roughly
~200 lines + a migration, so do it only if batches 1-3 go smoothly and more than 1.5h remains.

### Attack-chain presentation (G6 chain graph + Word exploration/attack-path chapter)
Large in size (a frontend graph + a new hand-written OOXML chapter in report), out of scope for this session, left for the next version.

---

## Verification wrap-up (after each batch)

1. `go build ./...`
2. `scripts/devtest.ps1` (= the full Docker PG `-p 1` run; the script created this session gets its first user)
3. Batches with frontend changes (batch 1/batch 3): `cd web && npx tsc --noEmit`
4. Report after everything is done; **commit/tag only after user confirmation**.

---

## Landing record (implemented 2026-11-01)

### Done
- **B10**: `taskLLMRuntime.pin` + the `current()/activeCfg()` pin branch; `agentsForTask` builds
  `compactorRuntime` (the pin comes from settings); adds `settingCompactorProfileID` + the Manager
  `CompactorProfileID/SetCompactorProfileID`; `GET/PUT /api/settings` read and write
  `compactor_profile_id` (`invalidateTaskAgents` after saving); the frontend `Settings` type +
  the system settings page's `Context compaction parameters` card gains a `Compactor model` dropdown (**deviation**: the plan put it on the LLM config page,
  but the compaction parameter card actually lives on the settings page, and keeping the selector next to budget/timeout is more cohesive).
- **B2**: `db.ExplorationStore.ActivityTraceTailTerminalIntent` (DESC takes the last N then reverses to ascending order);
  `Task.NotifyReview`; the `exhausted && wrote.Total()==0` trigger in `engine.go`'s settlement block; the planner
  `TriggerEvent` comment + the `"review"` branch of `renderTriggers` (the instruction is embedded in the event text; the seed prompt untouched).
  Unit test: `agent/planner_review_trigger_test.go`.
- **B6**: guard `AttribSample` + a ring buffer of the last 3 per category (command truncated to 200B) +
  `AttributionStats()`; `ToolSet.attributions`/`SetAttributions`/Planner/MainAgent signatures changed to
  `map[string]any`; both wiring points switched to `AttributionStats`. Unit test: `guard/guard_test.go`
  `TestAttributionSampleRing`.
- **B7**: `parseSession`'s third return value `intentID` (the `i<n>` suffix); `LLMUsage.IntentID`;
  `llmUsageSchema` gains the column + `llmUsageMigrations` (old DBs get `ADD COLUMN IF NOT EXISTS`) +
  `InsertLLMUsage` inserts the column; `ExplorationStore.TokenByIntent`; `compactIntents` gains an optional tokens parameter, and
  each intent in the overview's open/running/recent_done carries `tokens`. Unit test: the `llmrec` parseSession cases extended.
- **Engineering friction debt**: `scripts/devtest.ps1` (Windows PS 5.1 compatible: UTF-8 BOM, native commands don't trigger
  NativeCommandError) + `scripts/devtest.sh`; `api.ts` mock switched to a dynamic import (data.ts out of the first screen);
  `auth.go` `?token=` limited to the 4 SSE endpoints accessed directly by URL (`queryTokenAllowed`); everything else accepts only
  Authorization / cookie.

### Deferred (not done this session; suggested for v0.3.97)
- **N2 scope-aware intercept v1**: involves a DB column + the rule-edit page + confirming the concurrency semantics, ~200 lines; untouched.
- **Attack-chain presentation (G6 chain graph + Word exploration/attack-path chapter)**: large; untouched.
