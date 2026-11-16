# AGENTS.md — AI Collaboration Rules (Agent Harness Guide)

> This file is for AI coding agents working in this repository (Claude Code / ZCode / Codex, etc.).
> Goal: be able to build, test and release correctly without reading chat history, and avoid known pitfalls.
> Human-facing docs live in [README.md](README.md) and [docs/](docs/).

## 0. The project in one line

Pojun (literally "the Breaker") = an AI-driven autonomous pentest platform (Go monolith backend + Next.js static-export frontend + PostgreSQL as the only store).
planner/worker dual-role multi-agent autonomous progression, dual-graph architecture (asset graph x exploration graph), three-layer interception rules, full evidence trail.
Forked from the original author's deleted repository (baseline v0.3.15), now an independently evolving project. **For authorized testing only** (see the README disclaimer).

## 1. Common commands

```bash
# Backend build (both must pass)
go build ./...

# Frontend: typecheck + static export (note: must run inside web/; NEXT_EXPORT=1
# is Git Bash syntax — do NOT use `npm run build:static`, the env-var syntax in
# that script breaks under Windows cmd)
cd web && npx tsc --noEmit
cd web && NEXT_EXPORT=1 npx next build

# Full tests: real PG (Docker); -p 1 is mandatory (cross-package deadlocks
# otherwise); use a fresh database (rerunning against a shared DB collides on
# fixed-name fixtures' unique keys, producing false failures)
docker run -d --name pojun-audit-pg -e POSTGRES_PASSWORD=pojuntest -e POSTGRES_USER=pojun \
  -e POSTGRES_DB=pojun -p 15432:5432 postgres:16-alpine
docker exec pojun-audit-pg psql -U pojun -d postgres -c "DROP DATABASE IF EXISTS pojun_ci; CREATE DATABASE pojun_ci OWNER pojun"
POJUN_PG_DSN="postgres://pojun:pojuntest@127.0.0.1:15432/pojun_ci?sslmode=disable" go test -p 1 ./... -count=1

# Release build (for local cross-compile verification; real releases run in CI)
POJUN_SKIP_FRONTEND=1 POJUN_SKIP_NPM_CI=1 POJUN_COMPRESS=0 POJUN_PACKAGE=0 \
  POJUN_OUTPUT=/abs/path/pojun ./build.sh --target linux/amd64

# English-only gate: the whole tree must stay free of CJK text. The scanner
# also lists the binary image/font assets explicitly (they carry no text layer;
# the README screenshots under screenshots/ are re-captured from the English UI
# with scripts/shoot.py). Must print "CLEAN - no CJK anywhere".
python3 scripts/scan_cjk.py .
```

## 2. Test baseline (how to tell whether a FAIL is your fault)

- **Known load-dependent flaky tests** (always pass alone, occasionally fail in full runs; do not treat as regressions):
  `TestChatMentionWorkerReceivesServerDetails`, `TestNotifyDigestSegmentsAndDefersRemainder` (dirty shared-DB data),
  `TestChatUnavailableReasonDistinguishesStates` (Windows TempDir cleanup race).
- **How to check**: run `go test ./server/ -run <name> -count=1` alone; a pass means it was environmental.
- **Windows-specific**: the `evidence` directory fsync already has a GOOS branch; do not introduce new code that relies on directory fsync.

## 3. Release flow (tag -> CI -> Release)

1. Add a section to `CHANGELOG.md` (**confirm the anchor exists before editing** — a mismatched str.replace anchor once silently swallowed an entire section).
2. commit -> push main -> `git tag v0.3.x` -> push tag -> GitHub Actions produces 5 platform zips + SHA256SUMS + Docker + Release automatically.
3. CI gates are equivalent to local: `go build ./...`, `go test -p 1` (real PG), frontend tsc + `NEXT_EXPORT=1 next build`.
4. **Prompt changes roll out automatically to deployed instances via `SeedPromptVersioned`** (user-modified ones are unaffected) — no migration needed when changing worker/planner default templates.
5. **New interception rules go through a seed batch** (v1...v5 precedent): besides `seedBuiltinInterceptRulesBatch` you **must** also wire up name-based backfill seeding + merge into the enabled toolset (v4/v5 taught us real upgrade-path lessons: early-return flags swallowed the new rules).
6. git push to github.com often fails due to local proxy flakiness — use `git -c http.proxy= -c https.proxy= push` for a direct connection + a retry loop (30-45s intervals) + `git ls-remote` to confirm it landed.

## 4. Key pitfalls (learned the hard way)

- **Default builds contain no frontend**: `go build ./cmd/pojun` produces a stub (pages report "frontend not embedded"). Embedding requires `-tags embedui` plus `cp -r web/out server/webui/dist` first. Do not deploy a tagless local build as a release.
- **Dev version strings disable one-click update**: `CompareVersions` only accepts a clean three-segment version; something like `0.3.95-dev` is judged incomparable.
  Watch what you pass as `POJUN_BUILD_VERSION` when cross-compiling locally.
- **`next build` must run with cwd = `web/`** — it was once mistakenly run under `web/src` and the resulting `.next` got committed via `git add -A`.
- **Never write tests that rely on short sleeps for timers**: `1ms timeout + sleep 2ms assert` flips under CI load (passes locally every time).
  Use bounded polling.
- **An implemented tool must be registered**: domain tools in `agent/tools_*.go` must go into the three lists
  `PlannerTools/WorkerTools/MainAgentTools` (tools.go / tools_insert.go),
  and consider `agent/toolcatalog.go`'s BuiltinToolSeeds. Both listener (v0.3.87)
  and list_worker_traces (v0.3.89) hit the "implemented but never registered" bug.
- **Static export does not support server-side redirect()**: it is silently dropped and the route exports to a 404 page. Use client-side
  `router.replace` (see the v0.3.88 root-route fix).
- **Use readTool/readExpTool for read-only tools**: writeTool drops the ReadOnly/Concurrent flags and gets serialized by the scheduler.
- **Never put into chat/reports**: FOFA key, LLM API key, any plaintext password — credentials live only in runtime config.

## 5. Directory map

```
cmd/            entry points (pojun / pojun-hostd privileged helper / pojun-maint maintenance tool)
agent/          multi-agent layer (planner/worker/mainagent prompts and tools; the three tool lists in tools.go/tools_insert.go)
db/             PostgreSQL sole store (schema.sql idempotent migrations; intercept-rule seed batches v1-v5)
server/         HTTP surface and engine scheduling (all routes registered around server.go:680-1000)
intercept/      three-layer interception (rules + LLM judge + ask approval; judge prompt in prompt.go)
listener/       reverse-connection receiver; guard/   approval gate (Attributions flow back into planner posture)
traffic/ vulnintel/ llmpool/ selfupdate/ report/(handwritten OOXML, do NOT add third-party doc libs) skills/
web/            Next.js frontend (src/app routes; lib/api.ts is the single API wrapper)
docs/           design docs + phase reports (date-named files are phase snapshots; newer is more authoritative)
```

## 6. Document authority order (newest wins on the same topic)

`docs/deep-optimization-plan-2026-10-31.md` (current roadmap) > `docs/product-health-checkup-2026-10-31.md` (defect baseline) >
`docs/model-routing-strategy.md` (model selection) > `docs/red-team-capability-building-2026-10-30.md` > `docs/product-improvement-list-2026-10-29.md`
(historical, 35%-complete snapshot). Deployment & troubleshooting: `docs/deployment-manual.md` (includes LAN-source install recipes).
Handover background: `docs/project-handover-document.md`.
