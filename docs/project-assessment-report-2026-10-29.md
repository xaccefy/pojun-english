# ARTEX Secondary Development Overall Assessment Report

> 2026-10-29. Scope: all changes since the takeover (`v0.3.15..HEAD`, 159 commits, 281 files, +34317/-1807 lines).
> Questions: (a) which features are good, which are bad, which have negative effects; (b) remove what should be removed, optimize what should be optimized; (c) what was planned but not done / not fully done.
>
> **Method** (four levels of evidence, not just reading documents):
> 1. **Static verification**: item-by-item "claim vs code" comparison across the handover document's 8 batches, with `file:line` evidence for each;
> 2. **Build and test**: `go build`/`go vet` all pass; PostgreSQL 16 in Docker running the full `go test -p 1 ./... -count=1`; frontend `tsc --noEmit` with zero errors; cross-checked against GitHub Actions CI (all green on Linux);
> 3. **Code reading**: three key modules (vulnintel / intercept rules / LLM access chain) read file by file;
> 4. **End-to-end simulation**: a real service on the local machine + GLM-4.7-Flash (open.bigmodel.cn) + a locally isolated lab range, running one task to verify the whole engine chain.

---

## 0. Overall conclusion

**The direction of change is correct, the delivery rate is high, and the quality is above expectations.** Of the 60+ specific claims across 8 batches, item-by-item verification **found not a single false claim of the "the document says it was done but it wasn't" kind**; every claimed new file, new mechanism and guard test really exists and behaves as described. Every problem found is a **minor one** (2 places where the docs lag, 1 place where a comment disagrees with behaviour, 1 dead parameter); none is a directional error, and **there is no feature we recommend removing**.

Top-level conclusion table:

| Dimension | Conclusion |
|---|---|
| Documentation credibility | **High**. The handover document matches code reality closely, and even "known defects" are marked honestly (v0.3.77 unusable for a fresh install, GHSA CWE not persisted, etc.) |
| Feature delivery rate | **High**. All five mechanisms claimed as "implemented" (M1/M2/M3/M10/M14) verified in place |
| Code quality | **High**. The design decisions, the measured evidence in the comments, and the defensive boundaries of the three deeply-read modules are all first rate |
| Test health | **Good**. 17 of 19 packages fully pass (including every new module); the 12 failures in 2 packages are all Windows local environment issues (CI on Linux is all green) |
| End-to-end usability | **Demonstrated**. Local simulation: goal decomposition → planner dispatches intents → two workers execute in parallel → graph write-back → rate-limit retry chain; the whole chain works in a live run |

---

## 1. Batch-by-batch verification detail ("claim vs code")

Verdict: ✅ in place / ⚠️ partially done / ❌ not done / 🐛 done but differs from the description.

### Batch 1: structural hardening (v0.3.16–17) — all ✅

| Claim | Evidence | Verdict |
|---|---|---|
| norma fork decoupled | `go.mod:66` `replace github.com/Autumn-27/norma => github.com/chu0119/Norma v0.4.4` | ✅ |
| CI gate includes `-p 1` | `.github/workflows/ci.yml:42-45`, the comment states the cross-package PG deadlock (SQLSTATE 40P01) reason | ✅ |
| Design documents rebuilt | all four `docs/01-04` exist and match the code (read one by one this round, with implementation spot checks) | ✅ |

### Batch 2: self-use enhancements (v0.3.18–33) — all ✅

| Claim | Evidence | Verdict |
|---|---|---|
| vulnintel intel store (NVD/KEV/PoC/nuclei/asset linkage) | `vulnintel/`: 13 files, ~4000 lines of product code + ~2000 lines of tests; KEV sync pulled **1760/1760 real records** in the simulation | ✅ |
| Proxy pool three strategies + circuit breaking + health checks | `traffic/pool.go:40` actually has **4 strategies** (round_robin/sticky_host/sticky_host_random/random), one more than the docs | ✅ (docs lag) |
| Zero-dependency Word export | `report/docx.go` imports only the standard library (archive/zip/bytes/fmt/io/strings/time) | ✅ |
| vulnclass 19-class allowlist + alias table | `db/vulnclass.go:11-31`, exactly 19 classes; alias table with 40+ groups | ✅ |
| Task wrap-up (stall posture) | commit `b825bd5` + the implementation inside `agent/` | ✅ |
| net_context tool (container/binary dual-form explanation) | from `agent/tools_vulnintel.go:294`, two descriptions depending on the `selfupdate.InDocker()` branch | ✅ |

### Batch 3: capability batch (v0.3.34–35) — all ✅

| Claim | Evidence | Verdict |
|---|---|---|
| Intercept rule `judge` action, explicitly skipping the global LLM switch when judgement is requested | `guard/guard.go:101-117` (the `dec.Action == "judge"` branch) + `intercept/intercept.go:545` (`JudgeRule` forced=true; only `!forced && !cfg.Enabled` is bound by the global switch) | ✅ |
| Intel page configurable and diagnosable + manual sync/probe | `server/server.go:835-836` `POST /api/vulnintel/sync|probe`; the full settings set in `server/vulnintel_sync.go` | ✅ |
| Proxy pool bulk import + active verification | `server/proxypool_api.go` (bulk/check endpoints, `checkOneProxy`) | ✅ |

### Batch 4: spin governance (v0.3.76) — ✅

| Claim | Evidence | Verdict |
|---|---|---|
| Spin criterion moved to PreToolUse (the original implementation never took effect) | `agent/idlestop.go:48-64` — the comments fully reconstruct why the original Stop-only implementation could never fire for a "worker that keeps working"; PreToolUse is the primary criterion, Stop kept as a fallback | ✅ |

### Batch 5: intercept rule overhaul (v0.3.77–78) — all ✅ (deep-dived)

| Claim | Evidence | Verdict |
|---|---|---|
| Single source of truth for built-in rules | `db/intercept_builtin_rules.go`: **23 rules = 10 hard-deny + 12 judge + 1 ask**, exactly matching the deployment handbook's expected values; each carries a `rationale` classification reason | ✅ |
| Rule-level timeout really takes effect (dead field fixed) | verified through the whole chain: `guard/guard.go:109-117` reads the rule declaration → `JudgeRuleWithTimeout` (`intercept/intercept.go:564`) → `judge():579-586` the rule values override the global TimeoutSeconds/FailAction → `context.WithTimeout` genuinely takes effect. The regression test `intercept/rule_timeout_test.go` and the end-to-end `guard/intercept_e2e_test.go` both exist | ✅ |
| Migration carries a fingerprint, user-modified rules untouched | `db/intercept_builtin_migration.go:20-31`: the old default fingerprint (action + timeout triple + pattern), updated only on an exact match | ✅ |
| v0.3.77 migration argument misalignment fixed | commit `0352acb`; the deployment handbook §8 has a real PG drill record | ✅ |

### Batch 6: deployment hardening (v0.3.79–81) — all ✅

| Claim | Evidence | Verdict |
|---|---|---|
| install.sh: SHA256 mandatory, no downgrade | `install.sh:377-382`: when SHA256SUMS can't be fetched it calls `die` outright ("refusing to install an unverified binary") | ✅ |
| install.sh: sync the password when the role already exists | `install.sh:449-461` `ALTER ROLE artex LOGIN PASSWORD` | ✅ |
| install.sh: download retries | retry/fallback logic in 6 places | ✅ |
| start.sh crash cap | `start.sh:26-39`: gives up self-relaunching after consecutive crashes; exit code 75 (one-click update) doesn't count — the semantics are finer than claimed | ✅ |
| 15 middleware-protocol tools, pip --break-system-packages | all 15 middleware tools are present in `hosttools/hosttools.go`; installation goes through `hostd/recipe.go:142` `python3 -m pip install --break-system-packages` (and a test asserts that flag is present) | ✅ |
| vuln-hunting seven dimensions | `skills/vuln-hunting/SKILL.md:37-121` has all seven dimensions section by section + `reference.md` | ✅ |
| scopesentry frontmatter fix | `skills/scopesentry/SKILL.md` frontmatter closes properly with `---` (line 6) | ✅ |
| Recent-critical fast lane | `vulnintel/fastlane.go`: its own cursor `nvd_fastlane`, a 7-day window floor (the comment carries the measured basis: a 1–3 day window makes NVD time out), 12h overlap, a 20-page cap per round, and the cursor kept on truncation | ✅ |
| NVD rate-limit gate shared by both lanes | `vulnintel/ratelimit.go` process-level token bucket + `nvd.go:163` `waitNvdSlot` before every request (⚠️ one comment disagrees with the behaviour, see §3-P2) | ✅ |

### Batch 7: hunting capability (v0.3.82) — all ✅ (deep-dived)

| Claim | Evidence | Verdict |
|---|---|---|
| `auth_request` credential reuse, POSIX escaping verified by a real shell | `agent/tools_auth_test.go:192-194`: "the criterion for correct escaping is that the value the shell restores equals the original" — a real shell parse test | ✅ |
| `diff_responses` Go/Python dual-implementation cross-check test | `agent/tools_diff_test.go:306-353`: "the two implementations must be equivalent — really run python and compare field by field" | ✅ |
| GHSA as a second source, reusing vuln_cves without a new table, conservative verdicts | `vulnintel/ghsa_store.go:14,71-76` (`source='ghsa'` writes the same table); `ghsa_range.go` judges a parse failure/dev version/empty range as "possibly affected" in every case (the asymmetric handling of the wrong direction is right); the two sources are merged by `HasVersionRange` (`fastlane.go:270`) | ✅ |
| `api_contract` contract enumeration | `agent/tools_contract.go:51` + `scripts/apicontract.py` (and commit `4c0a4a9` fixed the safety problem where "the sweep sent real requests to write endpoints") | ✅ |
| Standardized skill tags + norma compatibility guard test | all 4 skills carry `tags:` (cwe/attack/class); `server/skill_tags_test.go` includes `TestTaggedSkillsStillLoadWithNorma` | ✅ |

### Batch 8: mobile adaptation (v0.3.83) — 7/7 ✅

Verified place by place (including a git comparison against the pre-change state): the four modals (tool edit / LLM edit / tool detail / Agent edit) all became "full width on mobile + desktop width from `sm:`", and the three cramped spots (proxy pool title / Skill stats / traffic badge) all gained `flex-wrap`/`min-w-0`. A repo-wide grep finds no harmful leftovers of the same kind (the remaining `min-w-[60rem]` is the established "table horizontal-scroll floor" decision). **Nothing partially done, no side effects**.

---

## 2. Build and test verification

| Item | Result |
|---|---|
| `go build ./...` | ✅ passes |
| `go vet ./...` | ✅ passes |
| Frontend `tsc --noEmit` | ✅ zero errors |
| Full backend test suite (Docker PG16, `go test -p 1 ./...`) | **17 of 19 packages fully pass** — including every new module (vulnintel 21s / db 40s / agent 17s / intercept / guard / llmpool / the evidence-related agent packages, etc.) |
| The 2 failing packages (evidence 5 + server 7 = 12) | **all of them Windows local environment issues**: ① the root cause of the evidence failures is `evidence/store.go:115` calling `d.Sync()` on a directory handle — on Linux that flushes directory entries, on Windows it necessarily gives `Access is denied` (**upstream-inherited code, not introduced by us**); ② `TestSkillRelPath` expects forward slashes while Windows `filepath.Join` gives backslashes (the "Windows path separator" class already known from the handover document); ③ the first-round `TestTaskTemplateHTTPCRUD` was a Windows TempDir cleanup race and passed on the second round (flaky) |
| GitHub Actions CI (Linux + real PG) | ✅ the latest main commit is all green (2m33s) — none of the 12 failures exists on the CI platform |

**Judgement**: the code is healthy on the platform it actually deploys to (Linux); Windows local failures are not evidence of a regression.

---

## 3. List of found problems (everything that needs fixing is here)

### P1 · CHANGELOG gap (documentation debt, the most visible problem)
The last entry in `CHANGELOG.md` is **0.3.62 (2026-10-21)** while tags already reach **v0.3.83** — the 21 versions in between (including the four important batches: intercept rule overhaul, deployment hardening, hunting capability, mobile adaptation) have no changelog. The handover document covers this content, but CHANGELOG is the change record visible externally (on the Release page). **Recommendation**: add a batch-level set of summary entries (version-by-version isn't necessary) and adopt the rule that "tagging must come with a CHANGELOG entry".

### P2 · ratelimit.go comment disagrees with behaviour (small bug)
The comment at `vulnintel/ratelimit.go:63-65` says "if the key changes mid-way, it is enough to rebuild on the next sync round", but the implementation uses `sync.Once` — **the in-process rate-limit interval is fixed to the key used first and is not rebuilt after a key change**, until the service restarts. Impact: on an instance that first ran without a key (6.5s interval) and then had a key configured in the UI, sync still runs at the anonymous rate (9x slower but no errors). **Recommendation**: change the Once to rebuild when the key value changes (a change within 10 lines).

### P3 · `isRecentCritical` dead parameter (code hygiene)
The `severity` parameter at `vulnintel/nvd.go:205` is unused (the actual criterion is score≥9.0 or KEV; the behaviour is correct and matches the semantics of `selectRecentCritical` in `fastlane.go:91`). **Recommendation**: delete the dead parameter, or have both places share one function.

### P4 · Windows portability of the evidence directory fsync (inherited problem, on record)
`evidence/store.go:115` `d.Sync()` necessarily fails on Windows → the evidence subsystem is unusable on a Windows host. The project ships a windows/amd64 package with `start.bat`, but CI only tests Linux, so this gap is invisible. **Recommendation**: pick one — ① skip the directory fsync when `runtime.GOOS == "windows"` (within 10 lines); ② state explicitly in the README/deployment handbook that "the evidence subsystem supports Linux deployment only".

### P5 · One case where the commit message doesn't match the content (process, not code)
Commit `afdebc0`'s title is "remove incomplete listener feature", while the actual diff **rebuilt** the 52-line minimal `listener/listener.go` package (what was removed was the incomplete agent integration). It doesn't affect behaviour but misleads later archaeology. **Recommendation**: no need to rewrite history; just be aware.

### P6 · Two places where the docs lag slightly
① The proxy pool is documented as "three strategies" but actually has four (`sticky_host_random` was added later); ② the two helper-class skills playwright-cli/scopesentry have only a class tag and no cwe/attack (a reasonable design, but something to know when counting tag coverage).

---

## 4. Question (a): feature value grading

### Good — keep and keep investing (ordered by value)

1. **The vulnintel intel layer** (the core of batches 2/3/6): "continuous intel operations on a time stream" (the fast lane every 30 minutes, CVSS≥9 or KEV) is **a unique leading item** in surveys of comparable products; the implementation quality is high — page-level cursor resumption, a shared rate-limit gate, "two-source merge" decisions when the version is undetermined, an inverted index (which fixed a 28-second / 33k-line-log performance incident), and KEV stub rows. The simulation's full KEV sync succeeded.
2. **The intercept rule overhaul** (batch 5): the three-tier criterion "irreversibility × what it acts on" is clear and aligned with the verdict prompt; the rule-level timeout dead field was fixed through the whole chain; the migration fingerprint protects user changes; each rule's rationale makes the classification auditable. This is the key balance point between platform safety and usability, and the direction is entirely correct.
3. **The LLM stability family of fixes** (batch 4 + scattered): the Compactor self-deadlock (root cause located from a SIGQUIT stack, which also punctured "a 15-minute wall clock does nothing against a self-deadlock"), planner wall clock + an independent goroutine as a double safeguard, thinking downgrade by switching provider (fixing the previous version's dead code whose condition was always false), budget tuning. **In this simulation the 429 rate-limit paths "retry in the safe window before submit" and "intent-level model_error rerun (2/2)" fired for real and worked as designed** — this family of fixes directly determines whether the platform can run on a real (unstable) LLM channel.
4. **The hunting capability batch** (auth_request / diff_responses / api_contract / GHSA / skill tags): precisely closes the G2/G5 gaps (the capability comparison document confirms the waste of "the asset has auth data but it can only be read as text"); the dual-implementation cross-check tests and the real-shell escaping test are a rigour rarely seen in comparable tools.
5. **Evidence-chain fixes** (v0.3.62): traffic citation became "best effort" (fixing the net-loss defect where "one wrong ID guess threw away a confirmed vulnerability"), and duplicate reports also bind traffic — all of them pits you fall into the moment the switch is on.
6. **Deployment chain hardening** (batch 6): mandatory SHA256, role password sync, crash-loop cap, ETXTBSY handling — each one corresponds to a real incident (cross-verifiable between the handover document and the deployment handbook), and deployment reliability improved markedly.
7. **Structural de-risking** (batch 1): the norma fork, the CI gate, the documentation rebuild — with "the original author has deleted the repo" as the backdrop, these three are the precondition for the takeover being sustainable at all.

### So-so — valuable, mind the conditions

1. **Running tasks on a single free LLM channel gets stuck on rate limits** (proven in the simulation: the glm-4.7-flash free tier returns 429 often, and a single intent ended up blocked). This is not a platform defect — the platform's retry/wrap-up behaviour is all correct — but **a real deployment must have multiple channels + LLM rotation** (already known in the docs; worth stressing as a deployment precondition).
2. **Mobile**: all 7 fixes are in place, but table pages still use "horizontal scroll as the floor" (an established decision); the mobile experience is "usable", not "pleasant".
3. **hostd privileged helper**: the security boundary of allowlist + socket permissions + no free-form commands is genuine and cleanly implemented, but it is a resident root process after all — turning it off with `--no-installer` in environments that don't need web one-click install is the correct advice already in the docs.

### Negative / needs handling

See P1-P6 in §3. All six are minor problems; none of them suggests "remove a feature".

---

## 5. Question (b): removal and optimization recommendations

**Removals: none.** No feature was found that should be deleted. The closest is the minimal `listener/` package — it is only 52 lines and its companion `listener_start/stop` tools have an ask approval gate, so the cost of keeping it is tiny, and "callback listener" is a reasonable capability for a pentest platform; not recommended for removal.

**Optimizations (by priority)**:

| # | Recommendation | Cost |
|---|---|---|
| 1 | Fill in CHANGELOG 0.3.63–0.3.83 (batch-level summaries are enough) + adopt "a release always updates it" | half an hour |
| 2 | Fix ratelimit rebuild on key change (P2) | 10 lines |
| 3 | evidence `d.Sync()`: skip on Windows or declare Linux-only (P4) | 10 lines / one doc paragraph |
| 4 | Delete the `isRecentCritical` dead parameter (P3); unify it with `selectRecentCritical` while at it | 5 lines |
| 5 | Doc touch-up: proxy pool has four strategies (P6) | 5 minutes |
| 6 | Add a deployment precondition to the README: "configure ≥2 LLM channels with rotation enabled; a single free channel gets stuck on rate limits" (proven in the simulation) | 10 minutes |

---

## 6. Question (c): planned but not done / not fully done

**Verification conclusion: the handover document is honest about "not done"** — every item marked "to do / not done" was verified as indeed not done, with no false claims of completion. The list:

| Item | What the doc says | Verification | Recommendation |
|---|---|---|---|
| Persisting GHSA's CWE field | the capability comparison M1 says outright "parsed but not persisted; second-batch work (needs a schema change)" | indeed not done | **Do it first** — it is the last link in the "find a CVE → automatically surface the matching methodology skill" loop, and the GHSA parsing code is already there, only persistence and linkage are missing |
| The M-list second batch (tri-state closure / fuzzing integration / LLM loop detection / coverage ledger / three-model separation) | sections 5 and 6 list them explicitly as to-do | indeed not done | Proceed in the cost/benefit order the doc already laid out; tri-state closure (M11) is the highest priority — it addresses the credibility problem of "reaching a boundary is only the model's self-report" |
| The frontend lint gate in CI | the ci.yml:59-61 comment says outright "kept out of the gate for now: 75 existing errors… left as a separate governance task" | indeed outstanding | The debt is recorded; schedule one dedicated pass to pay it off |
| Card layout for table pages on mobile | handover document batch 8 "left for later" | indeed not done | Low priority |
| Windows platform test coverage | (not mentioned in the docs) | CI has no Windows job, which is why evidence's P4 problem is invisible | If we insist on shipping Windows packages, at least add a Windows smoke job that doesn't connect to PG |
| CHANGELOG maintenance | (no such convention) | gapped from 0.3.63 on (P1) | Establish a release-process convention |

---

## 7. End-to-end simulation record (2026-10-29)

**Environment**: a local Windows machine; an ARTEX `dev` build (`go build ./cmd/pojun`); PostgreSQL 16 (Docker, separate database `artex_sim`); LLM = GLM-4.7-Flash (open.bigmodel.cn, OpenAI-compatible endpoint, a reasoning model); the lab = a deliberately vulnerable small app isolated on 127.0.0.1:8099 (login / search reflection / unauthenticated API / robots.txt / backup files), with no real external target touched throughout.

**Platform mechanisms that passed in the live run**:

1. Service startup, built-in prompt/agent/reporter seeding, env LLM wiring (`openai / glm-4.7-flash`);
2. **KEV intel sync really worked end to end**: the full cisa.gov set, 1760/1760 records persisted;
3. Task creation → target asset seeding → (**graceful fallback** to a single target when task 1's LLM decomposition produced nothing);
4. **planner edge wake-up → `add_intent` dispatches intents → two workers claim them in parallel via CAS**;
5. Workers really executed Bash (curl probing API contract paths, Write writing wordlists, ffuf attempts), adapting to failures by switching paths;
6. **The rate-limit resilience chain worked live**: free-tier 429 (1302 rate limit / 1305 model overload) → stream-layer "safe window before submit" retry (1/2, 2/2) → intent-level model_error rerun (2/2) → blocked as designed, **no silent failure and no infinite loop**;
7. **Dual-graph write-back**: the exploration graph formed an origin fact → 2 goals (spawns) → 2 intents (derived_from) lineage structure, exactly as the design document describes.

**Not verified this round** (constrained by free-tier rate limits; the single task never reached findings/report output): the complete exploitation chain, the report_finding→reporter trigger, and Word export. These paths are covered by CI tests and their logic was verified upstream.

**Conclusion**: on a "real and unstable" free LLM channel the platform behaves as designed — graceful degradation under rate limits rather than breakdown. A single free-tier channel is only enough to verify mechanisms; real use needs multiple channels.

---

## 8. Notes on confidence

- Static verification is based on comparison against the git baseline `v0.3.15` plus file-by-file reading; key claims all carry `file:line`;
- Tests ran on a real PostgreSQL 16 (not a SQLite stand-in), and GitHub Actions (Linux+PG) cross-confirms that the Windows local failures are environmental;
- The simulation used a real third-party LLM service and a real isolated lab range, not mocks;
- Unverified items: a long-running task wrapping up completely (all goals met → done), the content of the Word report artifact, and a real root install of hostd (needs a real Linux machine; recommend verifying next time on the Kali test machine).
