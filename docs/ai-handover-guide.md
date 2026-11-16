# AI Handover Guide (AI taking over this project: please read it all first)

> Last updated: 2026-11-07 (v0.4.62 released and deployed to the test machine)
> Reader: the AI assistant taking over the Pojun project. This document assumes you can read code, run tests and operate Linux.
> Credentials (SSH/database passwords/LLM keys) are **never written into this repo** (it is a public repo); they exist only in the maintainer's local memory file — ask the maintainer when needed.

## 1. What the project is

**Pojun** (`github.com/chu0119/Pojun`, named ARTEX before 2026-11-02) is an **LLM multi-agent autonomous pentest platform**: give it a one-sentence objective and it automatically completes the whole flow of "goal decomposition -> recon -> vulnerability hunting -> exploitation -> post-exploitation -> reporting", with a human able to step in and correct course at any time.

- **Go monolithic backend** (`github.com/chu0119/pojun`, embedding the Next.js static frontend via `-tags embedui`)
- **PostgreSQL** is the only persistence layer (schema.sql idempotent migrations)
- The agent engine is based on the **norma SDK** (a fork: `go.mod` replace points to `github.com/chu0119/Norma`)
- Positioning: long-running deployment on a Linux server, for authorized pentests/SRC only
- History: forked from the now-deleted Autumn-27/ARTEX (v0.3.15 baseline); the 700+ commits since are the current maintainer's independent evolution; the external narrative is always as an **independent new project**

**For the full version history see [CHANGELOG.md](../CHANGELOG.md)** (every version has a detailed entry); this document only covers "what state things are in now, where things are, and how work gets done".

## 2. Repo and environment map

| Location | Content |
|---|---|
| `D:\xiangmu\aiai\ARTEX` | Main repo workspace (Windows, Git Bash) |
| `github.com/chu0119/Pojun` | Main repo (PUBLIC; the ghcr.io/chu0119/pojun image is published automatically with each tag) |
| `D:\xiangmu\ARTEX-SKILL` -> `chu0119/pojun-skill` | Portable single-skill edition (v2.0, same source as the platform methodology; changes must be synced both ways) |
| `github.com/chu0119/Norma` | agent harness SDK fork (go.mod replace points at it; changing the SDK requires a separate release and a replace version bump) |
| **Kali test machine** `192.168.198.128` | The real running instance (SSH user xingchuan, paramiko direct connection; credentials in local memory). Services: `systemctl {pojun,pojun-hostd}`, directory `/opt/pojun`, DB is the PostgreSQL database **`artex`** (a historical leftover name), the instance runs as user `pojun` |
| Local Docker | Test PG: container `pojun-audit-pg` (port 15432; `docker start` before running tests) |
| Public machine 120.55.171.237 | Semi-deployed handover state (user-managed, v0.3.85 + nginx); do not touch it unprompted |

**Test database**: locally `POJUN_PG_DSN='postgres://pojun:pojuntest@127.0.0.1:15432/pojun_ci?sslmode=disable'`; before running tests `docker exec pojun-audit-pg psql -U pojun -d postgres -c "DROP DATABASE IF EXISTS pojun_ci; CREATE DATABASE pojun_ci;"` (leftover data in a shared database causes false failures).

## 3. Core mechanisms -> code locations (where to change what)

| Mechanism | Code | Key points |
|---|---|---|
| Multi-agent orchestration loop | `server/engine.go` (plannerLoop/workerLoop/runIntent), `agent/planner.go`, `agent/worker.go`, `agent/mainagent.go` | Graph-change debounce wakes the planner -> add_intent dispatch -> worker claims, executes and writes back; **read engine.go's header and each branch's comments before changing orchestration logic (they are all records of real pitfalls)** |
| Dual-graph architecture | `db/exploration*.go` (exploration graph), `db/task_scope.go`+`db/assets*.go` (asset graph) | Node table `exploration_nodes` (kind=goal/intent/fact/finding/hint/digest), payload is JSONB — **there is no summary column, use `payload->>'summary'`**; the `activity` table **has no task_id column, use `exploration_id`** |
| Intent terminal states and stop reasons | `server/engine.go` branching at the end of runIntent, `db/task_context.go` constants | The reason code goes in the `blocked_reason` column: max_turns/timeout/error/task_timeout/shutdown/killed/**idle_stop**; `ReasonStopHookPrevented` also has a dedicated branch (v0.4.62) |
| idle-stop (settling with no progress) | `agent/idlestop.go` | nudge for 3 rounds -> prevent for 5 rounds -> **cancel the run context** (`AbortIdleStop` cause) to truly settle; write-back tools (record_fact/insert_assets/report_finding/save_evidence) neither block nor count a round; the settle reason lands in `blocked_reason=idle_stop` (v0.4.62 fixed the previously invisible problem) |
| Task terminal-state settlement | `server/engine_timeout.go` (settleTaskWithReason/runFinalPlannerRound/TaskClock), `server/auto_finish.go` | goal_met/timeout/auto_idle/auto_coverage/auto_rounds; goalless tasks (no open goal) go straight to done once the frontier is drained; before settling `warnFindingsWithoutReport` names the vulnerabilities with empty reports |
| Terminal-state revival | `server/goals.go` admitTaskWhen + `server/engine_timeout.go` resetTerminalRevival | Reviving from any terminal state (done/failed/timeout): clear first_run_at/deadline_at (fresh budget) + clear engine gates + clear pending settlement + **reopen canceled blocked intents**; regression test `server/task_revival_deadline_test.go` |
| Evidence grading and mechanical verification | `agent/finding_recorder.go` (validateFindingEvidence/validateMechanicalEvidence), `agent/tools.go` addFinding (ToolOutputLedger evidence-source verification) | critical/high must have mechanically reproducible evidence (HTTP status code/curl output/tool hit); pure version matching is rejected; on reporting it automatically traces back and binds same-intent artifacts and anchors the asset |
| Skill system | the `skills/` directory (21 skills), `agent/assembly.go`+`server/assembly.go` (wireAgentAugment + SkillIndexBlock injected into renderSystem), `db/db.go` builtinSkillVisibility | **A new skill must do three things**: (1) SKILL.md frontmatter (name/description; missing means it loads empty) (2) add it to builtinSkillVisibility's default bindings (otherwise the guard test goes red) (3) the release package/image must contain it (build.sh already `cp -R skills`). Guard tests: `db/skill_visibility_test.go` (every skill must be bound or have an optOut; src-hunting knowledge-base completeness) |
| Skill meta-tool call rate | `server/assembly.go` (SkillIndexBlock -> renderSystem injection of the quick-reference block) | **Lesson**: Skill is a meta-tool, and a model will almost never call one unless the system prompt explicitly reminds it (once 56k calls produced only 8). Anything "you hope the agent proactively uses" must go into the system prompt |
| MCP | `server/server_mgmt.go` (pgSaveMCP etc.), `mcphttp/client.go` (HTTP/SSE), the norma `mcp` package (stdio), frontend presets `web/src/app/(main)/system/mcp/page.tsx` mcpPresets | The built-in FOFA MCP lives in `mcp-servers/fofa/` (launched by uv; relative paths rely on the service cwd=/opt/pojun or /app); **9 presets**; to add a preset edit the mcpPresets array |
| js_audit (SPA source leak) | `agent/tools_jsaudit.go` | Detection chain: HTML -> script/chunk -> sourceMappingURL + `.map` fallback -> sourcesContent restored to disk -> secret/endpoint scanning; **SPA fallback 200 != a hit** (it must be JSON + sources) |
| http_probe / auth_request / diff_responses / api_contract | `agent/tools_probe.go` etc. | Unified pattern: **only drop scripts and assemble commands, never send requests itself** — traffic still goes through the MITM for evidence and approvals still apply. Write new domain tools the same way |
| Vulnerability intel | `vulnintel/`, `agent/tools_vulnintel.go` (search_vulns/get_vuln/get_poc/scan_with_nuclei) | NVD+KEV+GHSA+PoC sync; tri-state version-range judgment; "version match != vulnerability" |
| Three-layer interception gate | `intercept/`, `guard/`, `db/intercept_builtin_rules.go` | deny/judge/ask; rules seeded in batches (the batch is recorded in a settings flag; user deletions/edits are not resurrected) |
| Task Playbooks | `db/task_playbook_seed.go` | 4 built-in templates (full web flow / internal AD / APP+API / pure recon); settings flag `task_playbooks_v1` |
| Word reports | `report/` (hand-written OOXML, zero dependencies), `report/fonts/` official document fonts | Fonts embedded as odttf; the docx->PDF rendering verification recipe is in the memory file "docx rendering verification recipe" |
| Frontend | `web/src/` (Next.js static export), build with `NEXT_EXPORT=1 npx next build` -> copy `web/out` -> `server/webui/dist` | Image zoom ZoomableImageDialog; data viewer ArtifactDataViewerDialog; MCP presets in system/mcp/page.tsx |

## 4. Release process (standard steps, don't skip)

1. **Change code + test**: `go build ./... && go vet ./...`; refresh the test database (see §2); `go test ./... -count=1` (known parallel flakes in §6; single-run re-verification decides); for frontend changes run `cd web && npx tsc --noEmit && NEXT_EXPORT=1 npx next build`.
2. **Sync the frontend**: `rm -rf server/webui/dist && cp -r web/out/. server/webui/dist/` (**mandatory after any frontend change**, otherwise the binary embeds the old frontend).
3. **CHANGELOG.md** entry (use `assert` on the anchor to prevent a silent replace failure).
4. **commit + tag + push**: `git add -A && git commit && git tag v0.4.x && git push origin main v0.4.x`. Version numbers increment in small steps (the user explicitly requires not bumping major versions). The local network is unstable toward GitHub: retry a failed push first, then use the repo-level proxy (already configured `git config http.proxy http://127.0.0.1:7897`).
5. **CI (release.yml) automatic**: cross-compile linux amd64+arm64 -> zip + SHA256SUMS -> GitHub Release -> **multi-arch docker image pushed to ghcr**. WARNING: CI overwrites manually uploaded same-named assets with its own packaging (this is normal and ends up self-consistent); if CI's SHA256SUMS content is stale, overwrite it manually.
6. **Deploy to Kali** (paramiko recipe): sftp upload `dist/pojun-linux-amd64/pojun` -> `systemctl stop pojun` (hostd too) -> `install -m 0755 /tmp/pojun /opt/pojun/.pojun.new && mv -f ... /opt/pojun/pojun` (ETXTBSY-safe swap) -> `chown pojun:pojun` -> start -> `journalctl -u pojun | grep POJUN` to verify the version line -> `/api/health` 200. If skills/mcp-servers/frontend changed, sync those too (or just run install.sh from a file:// local source).

## 5. Testing discipline

- **Parallel flake list** (occasionally fails on a full run, always passes alone, not a code problem): `TestChatMentionWorkerReceivesServerDetails`, `TestConversationBatchDeleteReportsMissing`, `TestNotifyDeliveriesHistoryAndRetry`, `TestNotifyChannelAPICreateValidation`, `TestTaskTemplateHTTPCRUD` and others — decision method: re-verify with a single run. **New failures caused by new code must be fixed; flakes are not an excuse**.
- On Windows, `go test ./docpreview` occasionally gets its exe locked by Defender — compile and run it manually with `go test -c -o`.
- Git Bash mangles Chinese in curl into GBK: write the JSON body to a UTF-8 file and use `--data-binary @file`.
- paramiko's shell does not understand bash arrays; write multi-step scripts to stdin with `bash -s`.
- psql on Kali: `activity` uses `exploration_id`, `exploration_nodes` uses `payload->>'summary'`; for complex SQL write a file and deliver it base64-encoded to `psql -f`.

## 6. Known issues and open items (directions available after handover)

1. **Skill usage observation** (to be verified after the v0.4.60 quick-reference injection): run a task and check whether `Skill` tool_use appears in activity.
2. **Compactor cost reduction**: 9.4M tokens of compaction output is the most expensive single item (retrospective docs/retrospective-2026-11-06.md); candidates = lower compaction_max_tokens + earlier tool-output trimming.
3. **Metasploit RPC bridge** (PentAGI's idea): the HexStrike preset is already provided (v0.4.60); observe the integration result before deciding whether to build a native bridge.
4. **SecLists not installed on Kali** (2.5G; large GitHub downloads are blocked) — install it when the network is good.
5. **Docker Hub not published**: the maintainer must configure DOCKERHUB_USERNAME/TOKEN secrets; the README only advertises ghcr.
6. **Task 18 paused** (Weinan, 19 open intents): resume after the user signals; resuming goes through the full terminal-state revival flow (fixed in v0.4.57).
7. **Expectation management for low-yield targets**: the opening narrow-surface hint is done (<10 assets); a further "expected vs actual output" gap hint is possible.
8. **Parallel test flake hardening**: test isolation on the shared PG database (currently worked around by refreshing the database).

## 7. User preferences (violating them means rework; details in the memory file)

- **Small versions, small steps**; never bump the major version; release each batch independently.
- **Target data stays verbatim and unmasked** (first-party submissions go to the vendor unmasked); **the platform's own credentials stay masked**.
- **Retesting is purely manual**; automatic retesting/reminders are forbidden.
- **A SQL injection report must carry a sqlmap retest command that has actually been run successfully**.
- **A task should end when it should end**; unbounded scanning is forbidden (automatic settlement criteria are built in and tunable on the settings page).
- **GitHub facade**: publish Linux only, one-command install in the README, Contributors lists only the maintainer.
- **External asset integration**: whole-package migration + distribution path wired up + layered verification (unit/end-to-end/deployment side) all green before packaging.
- **Online bugs follow the standard flow**: empirical root cause from data -> code fix -> regression test -> release and deploy.
- Communicate in Chinese; Kali may be operated freely but **check for non-terminal tasks before upgrading/restarting**; do not re-run real scans on the user's behalf without explicit instruction.

## 8. Document index

- [CHANGELOG.md](../CHANGELOG.md) — detailed record of every version (authoritative)
- [retrospective-2026-11-06.md](retrospective-2026-11-06.md) — 12-task efficiency/cost/channel data baseline
- [similar-tools-comparison-2026-11-06.md](similar-tools-comparison-2026-11-06.md) — 14-project comparison and integration list
- [01-dual-graph-architecture.md](01-dual-graph-architecture.md) ~ [04-approval-and-interception.md](04-approval-and-interception.md) — architecture design
- [deployment-guide.md](deployment-guide.md) — complete record of deployment/upgrade/troubleshooting pitfalls
- [public-deployment-security-hardening-2026-10-29.md](public-deployment-security-hardening-2026-10-29.md) — public-internet baseline
- [model-routing-strategy.md](model-routing-strategy.md) — configuring models per role
