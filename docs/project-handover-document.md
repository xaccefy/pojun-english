# ARTEX Project Handover Document

> Updated: 2026-11-01 (corresponds to version v0.3.95; the v0.3.83 handover content is still largely valid; for the evolution history see "Since v0.3.84" at the end of this document).
> Purpose: to let the person taking over fully onboard without needing to read the chat history.
> Companion reading: `docs/01-dual-graph-architecture.md` (architecture), `docs/deployment-manual.md` (deployment and troubleshooting),
> `docs/vuln-hunting-capability-comparison.md` (current capabilities and roadmap).

---

## 0. Quick Facts Card

| Item | Value |
|---|---|
| Project | ARTEX — AI autonomous penetration testing system |
| Tech stack | Go 1.26 (backend) + Next.js 15/React (frontend, static export) + PostgreSQL (sole storage) |
| This repo | `github.com/chu0119/Pojun` (local `D:\xiangmu\aiai\ARTEX`) |
| Origin | Taken over from the original author `Autumn-27/ARTEX` (**the original repo was deleted by its author**), based on its final release **v0.3.15** (2026-10-10) |
| Current version | v0.3.95 (as of this document's update; see CHANGELOG for version-by-version details) |
| Positioning | **Independently evolving red-team operations platform** (README presents it as an independent project; aggressive features rolled out in batches per the roadmap) |
| Release process | Push a `v*` tag → GitHub Actions automatically produces 5-platform zips + SHA256SUMS + Docker image + GitHub Release |
| Key commands | `./install.sh` (deploy) / `./start.sh` (daemonized startup) / `./build.sh` (build) / `./reset-password.sh` |

---

## I. Project Details

### 1.1 What this system does

ARTEX is an **AI autonomous penetration testing platform**: a human gives a goal (one sentence), and the system automatically completes
the full pipeline of "goal decomposition → reconnaissance → vulnerability discovery → verification → reporting", with the human able to step in and course-correct at any time.

Core working model (see `docs/01-dual-graph-architecture.md`):

- **Dual-agent orchestration**: the planner reads the situation, decomposes intent, and dispatches tasks; the worker
  picks up one intent, executes it independently, and writes the result back; the human observes and intervenes through the main agent (mainagent).
- **Dual-graph architecture**: asset graph (globally shared, reusing hosts/domains/IPs/fingerprints across tasks) + exploration graph
  (independent per task, recording the exploration chain of intent→work→facts/findings/assets). The two graphs are bridged via "anchors".
- **Tool surface**: agents can invoke 60+ tools (host tools such as nmap/nuclei/sqlmap/ffuf +
  platform-built-in domain tools for vulnerability intelligence / traffic review / credential reuse / response diffing / contract enumeration),
  all passing through the interception control layer (rule matching → LLM adjudication → human approval).
- **Evidence chain**: the MITM recording proxy retains all HTTP traffic; findings can be bound to traffic evidence,
  and reports can be exported to Word.
- **Controls**: command interception rules are split into three tiers (10 explicitly forbidden / 12 referred to LLM adjudication / 1 requiring human confirmation),
  with rule-level timeout policies supported; high-risk commands can be configured to require manual clearance.

### 1.2 Takeover Background (Key Facts)

- The original author **Autumn-27**'s repo `Autumn-27/ARTEX` was **deleted** around 2026-10,
  invalidating all original links, Release downloads, and Docker image sources.
- This repo preserves the **original author's complete git history** (from initialization on 2026-07-26 to the v0.3.15 final release,
  462 commits in total), and continues maintenance on top of it.
- **Takeover baseline = tag `v0.3.15`** (the original author's final release, 2026-10-10). All changes since then
  were made by us (see Section III).
- Positioning decided after takeover (2026-10-17): **stable for personal use + light maintenance** — not pursuing feature completeness,
  prioritizing a stable deployment pipeline, practical usability in real engagements, and fast problem localization.

---

## II. Source Code Origins and Upstream

### 2.1 Overview of Code Sources

| Code / Dependency | Source | Status |
|---|---|---|
| ARTEX core | Original author `Autumn-27/ARTEX` (deleted) | **This repo = original author's complete history + our 158 commits**. Baseline tag `v0.3.15` |
| norma SDK (agent engine framework, `github.com/Autumn-27/norma`) | The original author's toolkit (not deleted, but to guard against going missing again) | **go.mod replace now points to the maintainer's fork: `github.com/chu0119/Norma v0.4.4`** (see the comment near line 66 of `go.mod`). To change SDK behavior, modify the fork repo and push a new version tag |
| Lightweight edition | `chu0119/pojun-skill` | Single-skill version of the ARTEX methodology (independent repo, no code dependency on this repo) |
| Docker image | `ghcr.io/chu0119/pojun` (amd64/arm64, auto-pushed by the release pipeline; Docker Hub requires DOCKERHUB_USERNAME/TOKEN secrets to push) |
| Third-party reference | Cairn (blackboard architecture, a Tencent Cloud hackathon project) | A snapshot commit exists in the repo history, for reference only |

### 2.2 How to distinguish "the original author's code" from "our changes"

The git history provides a natural dividing line:

```bash
git log v0.3.15..HEAD --oneline     # all 158 commits since we took over (all authored by xingchuan)
git diff --shortstat v0.3.15 HEAD   # total changes since takeover: 280 files, +34k / -1800 lines
git log --oneline v0.3.15           # the 462 commits before this are all the original author's
git diff v0.3.15 HEAD -- <path>     # line-by-line diff of any file against the original baseline
```

### 2.3 Backup Locations of the Original Baseline (verified 2026-10-29)

| Backup | Status |
|---|---|
| **Main repo tag `v0.3.15`** (the strongest evidence) | ✓ Intact. Points to commit `2e59e96`, whose 462 commits are authored by multiple people — Autumn-27 (338) / pphua (44) / Autumn (43) etc. — genuine upstream history, not rewritten. There is also a v0.3.15 Release on GitHub (5-platform zips + SHA256SUMS) |
| **Local directory `D:\xiangmu\ARTEX`** (the copy kept at takeover) | ✓ Clean. HEAD is at `a27b9ab` (= v0.3.15 + 1 README cross-link to the lightweight edition), differing from v0.3.15 content only by 2 lines in the README |
| `D:\xiangmu\aiai\ARTEX-upstream` | ⚠️ **Not an original backup** — it is a single-commit snapshot of the third-party `trhhubsd/ARTEX` (pre-takeover state, 140 files differ from v0.3.15); do not use it as a comparison baseline |
| `D:\xiangmu\norma` | Local source of the norma fork (corresponding to the go.mod replace target) |

> Conclusion: at any time you can use `git diff v0.3.15 HEAD` to compare with the original code line by line; the tag and
> the GitHub Release back each other up. For absolute safety, you can also make a read-only copy of the
> `git archive v0.3.15` output (burned to disc / saved to cloud drive).

Changes are concentrated in `vulnintel/` (new), `intercept/` (major overhaul), `agent/tools_*.go` (new tools),
`server/` (API and assembly), `web/src/app/` (frontend pages), `docs/` (documentation) — see Section III for details.

---

## III. Change Log (What We Did After Taking Over)

Organized by **feature batches** (each batch corresponds to several tags). Each entry notes "what was changed"; for line-precise
history, use the git commands above to check yourself.

### Batch 1: Structural Hardening (v0.3.16–v0.3.17, mid-Oct 2026)

The first thing after takeover — removing the structural risk that "the repo could go missing again at any time":

- **norma dependency decoupling**: `go.mod` replace points to the maintainer's fork `chu0119/Norma v0.4.4`
  (commit `1ee0ad7`). Reason for choosing replace over moving/changing import paths: minimal change surface, upgrades remain trackable.
- **CI gates** (`.github/workflows/ci.yml`): backend (build + vet + full PG test suite, with `-p 1`
  to serialize packages and prevent deadlocks) + frontend (tsc + static export). **Note: `-p 1` must be kept**, the reason is written in the
  ci.yml comments (cross-package PG deadlock, reliably reproduced twice).
- **Design document rebuild**: the four core design docs `docs/01-04` (the original author had deleted the docs directory).

### Batch 2: Personal-Use Enhancements (v0.3.18–v0.3.33)

- **Vulnerability intelligence library `vulnintel/` (new package)**: NVD CVE sync + CISA KEV exploited-in-the-wild list +
  GitHub PoC aggregation + nuclei template integration + asset fingerprint→CVE correlation + structured version-range matching +
  a UI page with configurable status and diagnostics (`/system/vulnintel`). Accompanied by agent tools
  `search_vulns` / `get_vuln` / `get_poc` / `scan_with_nuclei`.
- **Proxy pool `traffic/pool.go` + `/system/proxypool` page**: per-request egress rotation
  (four strategies: round-robin / sticky / sticky-random / random + failure circuit breaker + health checks + bulk import/verification).
- **Two must-haves for real engagements**: the `net_context` tool (Docker container callback IP) + duplicate vulnerability reporting governance
  (fingerprint deduplication at the write layer + merge with secondary confirmation).
- **Task wrap-up mechanism**: graph_overview injects stall status (consecutive rounds with zero output), and the planner
  prompt gains a "wrap up on diminishing returns" section — preventing tasks from spinning indefinitely and burning tokens.
- **Word report export** (`report/docx.go`): a hand-written minimal OOXML generator (zero dependencies);
  both task reports and individual findings can be exported; reports are collapsed and aggregated by vulnclass category.
- **vulnclass standard enumeration**: a 19-category whitelist + alias normalization table (normalized at the write layer, with aggregation and fingerprints using the same baseline).

### Batch 3: Capability Batch (v0.3.34–v0.3.35)

- **New `judge` action for interception rules**: a rule match can be referred to LLM adjudication (reusing the existing adjudication chain,
  skipping the global LLM toggle when a rule explicitly requests adjudication). The action CHECK in `db/schema.sql`,
  `intercept/`, `guard/`, and the frontend interception page were all changed.
- **Vulnerability intelligence page from read-only to configurable and diagnosable**: NVD Key / GitHub Token / proxy / PoC toggle / backfill days
  all configurable (masked on display), per-source errors with plain-language advice, manual sync and connectivity probing
  (`POST /api/vulnintel/sync|probe`).
- **Proxy pool bulk import + active verification + smart switching** (bulk/check endpoints, health-check goroutine,
  sticky_host_random strategy).

### Batch 4: Idle-Spin Governance and Deployment Hardening (v0.3.36–v0.3.76, scattered fixes)

- **Idle-spin criteria moved to PreToolUse** (v0.3.76, `779f1d4`) — a bug where the original implementation never took effect.
- Separate accounting of worker write-back counts, chat session list overflow, task-polling taskMissing, and
  a batch of other fixes from real-world feedback (see git log for each).

### Batch 5: Interception Rule Remediation (v0.3.77–v0.3.78)

- **Full review of built-in interception rules** (`db/intercept_builtin_rules.go` added, the single source of truth for rules):
  split into three tiers by "irreversibility × target object" — 10 explicitly forbidden (mkfs / dd / shred / fork bombs /
  iptables flush / shutdown / DROP DATABASE etc., hard deny) / 12 referred to LLM adjudication (rm -rf,
  DELETE requests, wipe-style paths etc., judged by context) / 1 requiring human confirmation (listener lifecycle).
- **Rule-level timeout actually takes effect** (the three `timeout_*` columns were previously dead fields);
  a one-time migration with fingerprint verification (only old databases are migrated; new databases are seeded directly with the new defaults).
- v0.3.78 fixed a migration parameter misalignment (only exposed by the real PG in CI; undetectable with local SQLite).

### Batch 6: Deployment Hardening + Middleware Tools (v0.3.79–v0.3.81)

- **`hosttools/` gained a "middleware protocol" category with 15 tools** (gmqtt / pika / pymongo / zeep /
  netmiko / napalm / confluent-kafka etc.; pure libraries installed via `pip --break-system-packages`).
- **NVD rate-limit gate** (`vulnintel/ratelimit.go`): the main sync and the fast lane share the quota,
  with the page interval derived from whether an API key is present — otherwise the anonymous tier's 5 requests/30s would starve each other.
- **install.sh triple hardening**: download retries on all error codes + mandatory SHA256SUMS verification +
  password synchronization when the DB role already exists (otherwise a fresh install would inevitably fail to start); `start.sh`
  gained a crash-loop cap (after 5 attempts systemd truthfully shows "failed", no more silent infinite restarts).
- **New `skills/vuln-hunting`**: a seven-dimension proactive vulnerability-hunting methodology
  (object transposition / flow decomposition / state machine / data boundaries / resource assumptions / error paths / composition) +
  reference.md command templates; fixed the frontmatter of the `scopesentry` skill
  (the old `## name:` format could not be parsed by norma, making the skill effectively invisible).
- **Recent high-severity fast lane** (`vulnintel/fastlane.go`): fetches the last 7 days by publishedDate,
  only accepting CVSS≥9.0 or KEV, with its own cursor and lock, one round every 30 minutes — "freshly disclosed high-severity" items
  enter the DB and get correlated with assets within tens of minutes.

### Batch 7: Hunting Capability Batch (v0.3.82, 2026-10-22)

The first batch delivered after a gap analysis benchmarking 11 open-source peers (`docs/vuln-hunting-capability-comparison.md`, the M1-M25 mechanism list):

- **`agent/tools_auth.go` `auth_request`**: turns credentials already registered on an asset into directly executable
  authenticated curl commands (a prerequisite for authorization-flaw verification; POSIX single-quote escaping verified with a real shell parsing test).
- **`agent/tools_diff.go` `diff_responses`**: structured diffing of two HTTP responses
  (shared across three dimensions: authorization flaws / enumerability / state machines). File mode is pure Go; URL mode writes a Python script
  executed via Bash (preserving traffic recording and the approval chain). The Go and Python implementations have a real-run comparison test.
- **`vulnintel/ghsa*.go` GitHub Advisory Database as a second data source**: fills the gap where NVD does not populate version ranges for newly disclosed
  CVEs (semver range parsing + conservative judgment: if parsing fails, always "potentially affected").
  Reuses `vuln_cves(source='ghsa')` without creating a new table — search_vulns picks it up automatically.
  Note the coverage boundary: **only components with a package ecosystem are covered; PHP core-class CVEs are not in GHSA**.
- **`agent/tools_contract.go` `api_contract`**: probes the target's OpenAPI/Swagger/Postman
  contracts and parses the endpoint list (endpoints requiring authentication are listed separately — the target list for authorization-flaw hunting).
- **`server/skill_tags.go` standardized skill tags**: SKILL.md frontmatter `tags:`
  (CWE / ATT&CK / class); the four built-in skills are tagged; norma ignores unknown fields,
  with a guard test ensuring compatibility. The UI skills page displays tag badges.

### Batch 8: Mobile Adaptation (v0.3.83, 2026-10-23)

- Playwright mobile viewport (390×844) page-by-page audit of 30 pages, fixing 7 issues:
  - **Overlay overflow, 4 spots**: tool edit `min-w-[480px]`, LLM edit `min-w-[420px]`,
    tool detail `w-[30vw]`, agent edit `w-[45vw]` — uniformly changed to the "full width on mobile,
    desktop width from `sm:` onward" pattern (desktop behavior unchanged).
  - **Header squeeze / vertical stacking, 3 spots**: proxy pool title, skill statistics (the w-64 list column squeezed the stats column
    → vertical stacking on mobile), traffic page recording badge — added `flex-wrap` / `min-w-0`.
- Table pages keep "horizontal scroll as the fallback" per the established decision; card-style layout is left for later.

---

## IV. Directory Structure (What Each Directory Does)

Backend (Go, module `github.com/chu0119/pojun`):

| Directory | Purpose |
|---|---|
| `cmd/` | Program entry points. `cmd/pojun` (main service) and `cmd/pojun-hostd` (privileged host helper) |
| `agent/` | AI agent layer: planner/worker/mainagent three-role orchestration, intent dispatch, context assembly, **all domain tools** (`tools_*.go`: intelligence / credentials / diffing / contracts etc.), idle-spin wrap-up (idlestop) |
| `db/` | PostgreSQL sole storage layer: `schema.sql` (all table schemas, idempotent migrations) + per-table Stores + built-in interception rule seeds + skill visibility |
| `server/` | HTTP service layer: all API routes, session/task management, agent assembly (tool injection), skill file management, LLM pool wiring, notification endpoints |
| `intercept/` | Command interception: rule matching → LLM adjudication (judge) → allow/ask/deny; audit traces; context for adjudication (working directory / user message background) |
| `guard/` | Tool-call control gate: plugs intercept's verdicts into the agent tool execution chain |
| `traffic/` | MITM traffic recording proxy + egress proxy pool (rotation / circuit breaking / health checks) |
| `vulnintel/` | Vulnerability intelligence: NVD/KEV/GHSA sync, PoC aggregation, nuclei template management, asset fingerprint→CVE correlation, fast lane, rate-limit gate |
| `hosttools/` | Host tool inventory and install recipes (apt / pip / github three source types), including the "middleware protocol" group |
| `hostd/` | Privileged host helper (runs as root, unix socket `/run/pojun/hostd.sock`): installs tools, runs actions requiring privileges; the main service runs as a normal user, all privileged operations go through here |
| `llmpool/` | LLM multi-config round-robin pool: priority-based failover, circuit breaking, health records (429/5xx trigger switching) |
| `llmrec/` | LLM request/response recording (for troubleshooting and auditing) |
| `report/` | Report generation: Word export of task reports / individual findings (built-in Chinese-language templates, hand-written OOXML with zero dependencies) |
| `notify/` | Notification push: DingTalk / Feishu / WeCom channels, filter rules, digest intervals, delivery retries |
| `evidence/` | Evidence retention and versioning for findings |
| `enrich/` | Automatic asset enrichment: new assets entering the DB trigger DNS resolution / HTTP probing |
| `selfupdate/` | One-click self-update: check GitHub Release → download and verify → replace and restart |
| `proxyprobe/` | Proxy availability probing |
| `listener/` | Built-in listener (callback form, for hybrid deployments) |
| `sidequestion/` | Side questions (lightweight Q&A that does not interrupt the main task) |
| `mcphttp/` | MCP (Model Context Protocol) HTTP service wrapper |
| `config/` | Configuration file loading |
| `skills/` | Built-in skill source files (`SKILL.md` + references / scripts), seeded at startup and manageable via the UI |
| `scripts/` | Auxiliary scripts (static checks of install scripts, etc.) |
| `docs/` | Design documents (`01-04` core designs, deployment manual, capability comparison, this document) |
| `dist/` | Local build artifacts |
| `screenshots/` | README screenshots |

Frontend (`web/`, Next.js App Router + Tailwind + shadcn/ui):

| Path | Purpose |
|---|---|
| `web/src/app/(main)/` | Main UI after login. `dashboard/` (overview), `chat/` (conversation), `function/` (business pages: tasks / findings / assets / traffic / workspace), `system/` (system management: LLM / Agent / tools / interception / intelligence / proxy pool / skills / MCP / notifications / host environment / logs / settings) |
| `web/src/app/(auth)/` | Login / first-time setup |
| `web/src/components/` | shadcn/ui base components |
| `web/src/lib/` | API client (`api.ts`) and type definitions (`types.ts`) |

Root scripts: `install.sh` (the sole deployment entry point, binary / Docker dual mode) ·
`start.sh` (daemonized startup, crash cap of 5) · `build.sh` (cross-compilation and packaging) ·
`reset-password.sh` · `.github/workflows/` (ci.yml gates + release.yml releases).

---

## V. How to Work After Taking Over

### 5.1 Daily Development

1. Backend changes must pass: `go build ./... && go vet ./...`; with PG connected, run `go test -p 1 ./...`
   (this is exactly what CI does; `-p 1` cannot be removed). Without local PG, 23 tests in the `server/` package will inevitably fail
   — treat CI as authoritative, and locally judge regressions by "comparing failure counts before and after the change".
2. Frontend changes must pass: `cd web && npx tsc --noEmit && NEXT_EXPORT=1 npx next build`.
3. Minimal-diff discipline: no opportunistic refactoring, do not touch lock files.

### 5.2 Releasing

```bash
git tag -a v0.3.x -m "..." && git push origin main --follow-tags
```

Pushing a tag automatically triggers the release workflow (frontend export → 5-platform cross-compilation → zip + SHA256SUMS +
Docker image + GitHub Release). Machines with the service installed can use the page "System Configuration → Update Now"
or wait for `start.sh`'s self-update chain. Upgrades are idempotent: config.json is carried over without overwrite, and all schema migrations are idempotent.

### 5.3 Real-Machine Verification

- Intranet test machine: **xingchuan (192.168.198.130, Kali, ARTEX installed, Web :8787)**.
  Upgrade method: download the release's `install.sh` → `sudo bash install.sh`; the test machine's connection to
  GitHub is flaky, so add `--install-proxy=http://127.0.0.1:7897` (local Clash).
- Production test machine 10.10.70.17 (ssh-remote profile `prod-artex`) — **SSH password not configured**
  (a placeholder in servers.json); ask the maintainer for the password before using it.
- Mobile adaptation verification: Playwright viewport 390×844, page-by-page screenshots (this is how it was verified this round).

### 5.4 Document Index

| Document | Contents |
|---|---|
| `docs/01-dual-graph-architecture.md` | Roles of the asset/exploration graphs, anchors, cold compression, schema migration design, invariant checklist before changing code |
| `docs/02-engine-and-scheduling-loop.md` | planner/worker orchestration and lifecycle |
| `docs/03-llm-access-layer.md` | provider/model configuration, round-robin pool, budgeting pitfalls of thinking models |
| `docs/04-approval-and-interception.md` | three-layer interception rules and the adjudication chain |
| `docs/deployment-manual.md` | deployment, upgrades, troubleshooting (including the "web page won't open but the service is fine" flow) |
| `docs/vuln-hunting-capability-comparison.md` | comparison with 11 open-source peers, M1-M25 mechanism list, done/to-do |
| `docs/command-intercept-rules-remediation-plan.md` | adjudication rationale for the three tiers of interception rules |

### 5.5 Known Issues and TODOs (Priority After Taking Over)

- **Occasional TLS failures reaching NVD**: in some network environments the handshake with `services.nvd.nist.gov` fails
  (reproduced in tests on the maintainer's Windows machine and the intranet test machine). Check this first when intelligence sync fails; configuring
  `vulnintel_proxy` or a system proxy resolves it.
- **The last missing link in GHSA intelligence**: GHSA's CWE field is parsed but not persisted; once persisted, we can implement
  "look up a CVE → automatically suggest the corresponding methodology skill" (requires schema changes, see capability comparison doc M1).
- **Second batch of mechanisms to do** (ranked by cost-effectiveness in Section V of `docs/vuln-hunting-capability-comparison.md`):
  tri-state closure (ruled_out must name the control point), fuzzing integration, LLM loop detection, coverage ledger,
  three-model separation.
- **Table pages on mobile**: currently horizontal scroll as the fallback; card-style layout for core list pages is left for later.
- **Unstable free LLM channel**: upstream rate limiting on opencode zen's `beam-free` is the norm;
  configuring multiple channels in model management + enabling the "LLM round-robin" toggle enables automatic failover (triggered by 429).


---

## Appendix: Evolution Summary Since v0.3.84 (2026-10-29 ~ 10-31, eight consecutive releases)

| Version | Theme | Key Points |
|---|---|---|
| v0.3.84 | Assessment remediation | Rate-limit gate rebuilt per key, GHSA CWE persisted + skill linkage, CHANGELOG gaps filled |
| v0.3.85 | Public-network hardening | Login brute-force protection / de-fingerprinting / session revocation on password change / security response headers (100% of the baseline document fulfilled) |
| v0.3.86 | Tool delivery | One-click install of all host tools (install-batch + hostd queue); dead-code cleanup of listener |
| v0.3.87 | Red-team special | Callback receiver, three C2 egress forms, redteam-ops skill, 9 post-exploitation tools, teardown wall-clock timing |
| v0.3.88 | Fixes | Root route static-export 404, listener tool registration completed, CHANGELOG backfilled |
| v0.3.89-92 | Comprehensive checkup | Four-track audit (frontend / API / agent / documentation reconciliation) → 11 P0 items, listener/C2 management pages, Guard attribution feedback, cold-start onboarding, 24 dead files removed |
| v0.3.93-94 | Report phase 1 | Word cover / TOC / headers & footers / severity coloring / rich Markdown rendering / retest section / traffic evidence / delivery sorting / methodology chapter / remediation roadmap / appendix assets |
| v0.3.95 | Agent phase 2 | stop_reason into posture, intent hypothesis/success_criteria, worker five-step framework + bypass checklist, continuation summary, prompt revision pack (planner/goals/judge/compaction), model routing strategy |

Current roadmap: `docs/deep-optimization-plan-2026-10-31.md` (approved; phase-3 attack-chain narrative + deferred big items from phase 2 still to do).
AI collaboration rules (build / test / release / pitfalls): repo root `AGENTS.md`.
