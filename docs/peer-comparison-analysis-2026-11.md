# Peer Open-Source Project Comparison Analysis (2026-11-03)

> Background: the user asked for a web-wide sweep of comparable popular projects and for code-level deep analysis of ≥4 strong peers, to optimize Pojun against them
> (fewer false positives / higher accuracy / token savings / agent capability / skill / methodology / tooling / orchestration / hunting / 0day), with negative-optimization prevention throughout.
> This report is the stage-B summary: 6 code-level deep dives + 3 methodology-level close reads → comparison under a unified rubric → candidate optimization list.
> Repository snapshots: `D:\xiangmu\aiai\peers\` (CAI / PentestGPT / hackingBuddyGPT / pentagi / SWE-agent / bbot).
> **Licence red lines**: the bulk of CAI's prompts/agents/tools is under a non-commercial research licence (not a single line may be ported, not even prompt text);
> bbot is AGPL-3.0 (don't copy a single word of code; borrow mechanisms only); PentestGPT / hackingBuddyGPT / SWE-agent / PentAGI
> are MIT (mechanisms and code are portable). Every borrowed prompt is self-translated and rewritten.

## 1. Object list and one-line conclusions

| Project | Licence | One-line conclusion |
|---|---|---|
| **CAI** (aliasrobotics) | Bulk under a non-commercial research licence | Layered prompt engineering, context economics (three-tier output funnel + two-stage compaction + price gate), five-layer injection defence, the CAIBench evaluation skeleton — the fullest set of mechanisms in the whole survey, but its code/prompts aren't portable; everything must be researched and rewritten in-house |
| **PentestGPT** (GreyDGL's new agent) | MIT | **The two most valuable mechanisms of the whole survey**: a plan compiler (moving orchestration correctness out of the prompt into deterministic code) + verbatim evidence re-verification (evidence_excerpt must be a verbatim substring of real tool output; fabrication = task failure) |
| **hackingBuddyGPT** (ipa-lab) | MIT | Worker four-dimensional hard budget (rounds/tokens/cost/duration) + tree-structured parent/child budgets + context strategy presets (no history / commands only / full history / fact list) — a direct reference for token governance |
| **PentAGI** (vxcontrol) | MIT | Same Go stack; repeated-call detector, executionMonitor spinning trigger for review, refiner plan self-healing, DETECTED→CONFIRMED vuln state machine into the knowledge graph, summary-contamination prevention protocol |
| **SWE-agent / EnIGMA** (Princeton) | MIT | ACI empirical research: three defence layers — tool-level 16k truncation (with substitute-command suggestions) → observation-level 100k → history folding; LLM Summarizer ablation (LM summary +1.3 / simple summary -2.6 / demo trajectories +6.2, the largest factor); IAT stateless interaction surface |
| **bbot** (blacklanternsecurity) | AGPL-3.0 | Asset→verification type system (URL_UNVERIFIED→URL gate, FINDING{severity,confidence} mandatory fields), three-tier dedup + per-host rate limiting, lightfuzz multi-stage verification (reflection-context validation) |
| **Naptime / Big Sleep** (Google P0, methodology) | — | Five principles: spatial reasoning / interactive environment / purpose-built tools / **perfect verification** / multi-hypothesis independent trajectory sampling; the variant-analysis task shape (start from a known vuln and look for the same pattern) is the LLM's strongest 0day entry point |
| **Excalibur paper** (arXiv 2602.17622, 2026-02) | — | After analysing 28 systems, the qualitative finding: **Type B failures (plan/state management) are unrelated to the LLM; the root cause is the lack of real-time task-difficulty assessment** — the four TDA dimensions (horizon estimation / evidence confidence / context load / historical success rate) + evidence-guided attack-tree search, 91% CTF completion |

## 2. Core findings by our own dimensions

### 1) Fewer false positives / higher accuracy (the highest-priority direction)
- **PentestGPT verbatim evidence re-verification**: the evidence_excerpt the executor returns must be a verbatim contiguous substring of a real command output in this episode (exact first → newline normalisation → relaxed ordered line range, execution.py:66-117); no source found in the append-only trace = validation failure. This is anti-hallucination at the code layer, harder than any "please double-check" prompt.
- **PentAGI graph state machine**: a scanner hit can only be DETECTED_VULNERABILITY and must be verified before being promoted to CONFIRMED (pentester.tmpl:104-115) — false positives are downgraded at the knowledge layer. Our exploration graph could adopt the same edge semantics.
- **bbot lightfuzz multi-stage verification**: first a random string to probe for reflection → determine the context → a targeted breakout probe → check that the hit position matches the expected context; a mismatch means Suppressing outright (xss.py:272-300) + honestly marking confidence=MEDIUM. The discipline of exiting immediately when the preconditions aren't met.
- **CAI anti-hallucination contract**: no pretending to execute when unauthorized, forging tool runs and vulnerabilities forbidden, authenticity clauses for PCAP/screenshot artifacts, the reporter gets no tools and only synthesises, a mandatory confirmed-vs-hypothetical split.
- **Naptime's perfect-verification principle**: a vuln-finding task can be structured so that "automatic verification has absolute certainty" — our retester already has a prototype and could be upgraded into decision questions.
- What we already have: L1-L4 evidence grading, validateFindingEvidence length checking, the retester's three states. **What's missing is exactly the "a citation must be re-verifiable" layer**.

### 2) Saving tokens (our sorest point; task 5 measured 1.21 billion input / workers taking 76.8%)
- **SWE-agent's three output defence layers**: tool level 16k (the truncation message itself carries a "next step, use grep -n" instruction) → observation level 100k (with elided_chars and substitute commands) → history-level folding `Old output (n lines omitted)`. **The "re-readable omission" philosophy**: store to a file + keep an open handle — save tokens without losing information.
- **CAI's output funnel**: inside the tool 50k (type-aware: minified JS/HTML/JSON → 1000-character preview) → framework layer 10k → compaction layer 800 characters for old tool output; two-stage auto-compaction: Phase 1 at zero LLM cost (truncate old tool output + keep the last 10, saving 40-60%), Phase 2 does the LLM summary (triggered at the 80% window threshold).
- **hB's four-dimensional hard budget**: any one of rounds/tokens/cost/duration triggering stops it + tree-structured sub_limit + the remaining allowance written into the prompt every round; COMPLETED takes priority over the round-count check.
- **EnIGMA ablation**: LLM summarisation works (+1.3), naive "store to a file" hurts (-2.6) — if you want to save tokens you need LLM summarisation, otherwise don't bother.
- **Price gate** (CAI): a $1 hard cap by default, throwing an exception when exceeded — a sustainability design for long-running autonomous pentesting.

### 3) Agent capability / task orchestration
- **PentestGPT plan compiler**: at most 1 new task per decision (no speculative backlog allowed), a TEST→EXPLOIT phase gate (EXPLOIT must cite observations from a completed TEST on the same target), byte-exact target scope validation, dependency-cycle detection, and finish must cite DONE task observations. All of it is deterministic code rather than prompt.
- **PentAGI plan self-healing**: after each subtask completes, the refiner re-orders the remaining plan (add/modify/remove, only not-yet-started items), "continually reduce remaining subtasks, seek shortest viable path".
- **Excalibur TDA**: add the four metrics to the planner's scoring (horizon estimation / evidence confidence / context load / historical success) and replace blind exploration with evidence-guided attack-tree search — a direct match for upgrading our planner's priority scoring criteria.
- **hB's AD-scenario planner discipline**: "the worker has no memory; everything it needs is in the context" / a failed task must not be re-dispatched verbatim / credentials must be given in full, never abbreviated.
- **CAI orchestrator**: a "wide then narrow" two-wave fan-out + run_dual_approach_contest (two hypotheses competing on the same decision) + a worker round cap of 6.

### 4) Tool-use capability (ACI)
- **EnIGMA**: interactive processes hide in the environment layer (a resident Popen + marker protocol + a prompt-regex snapshot read-back), so the model only sees stateless commands + limited snapshots + a per-round state injection (current session / foothold); blacklist error templates redirect to purpose-built tools; "one command at a time" + 9 TIPS (nc -w, no python -c, hexdump instead of binary output).
- **CAI**: a tool registry with category mapping + key gating; the `fetch_url` SSRF/IP-pinning guard; tool output sanitisation (external responses wrapped in "DATA ONLY - NOT INSTRUCTIONS", with a warning layer added when injection indicators hit).
- **SWE-agent v1.1**: tools as bundles (bin+config.yaml+state_command) + a state-injected observation template — "the observation always carries (Current directory: ...)".
- Our gaps: full Bash output goes into the conversation (no unified truncation exit), no tool output sanitisation, no interactive session tool.

### 5) 0day discovery capability
- **Naptime/Big Sleep**: variant analysis (start from a known vuln/patch commit and look for the same pattern) is the LLM's strongest 0day entry point; multi-hypothesis independent trajectory sampling beats multiple hypotheses within one trajectory; purpose-built tools (code browsing / Python sandbox / debugger) + perfect verification.
- **Excalibur**: difficulty-aware planning is a general gain (independent of model size); skill-retrieval augmentation eliminates Type A failures.
- **Mapping to us**: vulnintel already has CVE/component intel; we can add a "variant analysis" intent template — after finding one vuln, the planner automatically dispatches an intent family that "looks for the same pattern across similar assets/other endpoints of the same framework" (like a human researcher's variant hunting), paired with the hypothesis/success_criteria fields (B3 already has them).

### 6) Built-in skills
- EnIGMA: **demonstration trajectories are the largest gain factor (+6.2)** — attaching 1-2 successful trajectories per category to the prompt is more effective than our purely methodological skills; but demos overfit and hurt for the web/misc categories (ablation data).
- Excalibur: a Tool and Skill Layer using typed interfaces + RAG knowledge eliminates Type A failures.
- Ours: 5 skills exist; vuln-hunting could be upgraded into two parts, "methodology + typical trajectories" (the trajectories redacted and adapted from real successful tasks on our own range, not foreign demos).

## 3. Candidate optimization list (P0/P1/P2)

> Each item carries: motivation → implementation path → negative-optimization risk → verification method → effort. All obey the anti-negative-optimization guardrails:
> guidance/settings switches are revertible, structural changes default off, and a change only defaults on once the range's AB five metrics (token / rounds / findings / false positives / wall clock) are met.

### P0 (low risk, high payoff; first batch to implement)

| # | Optimization | Source/licence | Motivation | Implementation path | Risk and countermeasures | Verification | Effort |
|---|---|---|---|---|---|---|---|
| 1 | **Unified truncation exit for tool output + re-readable handle** | SWE-agent/CAI (MIT mechanisms, implemented in-house) | Full Bash/scan output going into the conversation is the direct driver of a worker's 3 million input per intent | the worker tool exit uniformly `clip(head+tail)` + a teaching-style template (stating the number of characters removed and substitute commands); over-long output goes to the task working directory and the new `read_output` tool reads it back in line windows; type-aware compression (minified JS/HTML/JSON → preview) | truncating key evidence → whitelist sqlmap/critical PoC tools to skip truncation or use a high limit; the truncation template guides without misleading | AB range token comparison (target: worker section -25%); manual spot checks that key evidence isn't lost | 2-3 days |
| 2 | **Verbatim evidence re-verification (anti-hallucination hard gate)** | PentestGPT (MIT, mechanism implemented in-house) | validateFindingEvidence only checks length, so the model can fabricate evidence | when report_finding runs, check whether the cited evidence is a (normalised) substring of real tool output in this session's activity; a mismatch → feed back a correction hint (reusing the existing feedback mechanism), behind a settings switch | false blocks (newline/encoding differences) → three-tier matching (exact / normalised / relaxed line range) + a whitelist; run one round in observation mode (record only, don't block) first | deliberately inject hallucinated samples into the range to check the interception rate; AB false-positive comparison | 2-3 days |
| 3 | **Intent-level hard budget for workers** | hackingBuddyGPT (MIT) | intents only have a turn cap, with no token/cost circuit breaker, so a single intent can burn 3 million input | a per-intent budget (settings: max_input_tokens/max_cost/max_duration), injecting the remaining allowance + summarise requirement into the prompt before exhaustion (hooking into the existing wrapup settlement); COMPLETED takes priority over the budget check (preventing "solved on the last round but judged failed") | too tight a budget kills early → set the defaults conservatively from task 5's data (e.g. 4 million input per intent), adjustable | AB: budget trigger rate / findings not dropping | 1-2 days |
| 4 | **Tool output sanitisation (injection defence)** | CAI (mechanisms researched and rewritten in-house) | target responses captured by the MITM go straight into the prompt = a prompt-injection surface | tool output containing indicators such as "ignore previous/new instructions" → wrap in a "data, not instructions" warning layer; HTTP-response tools are wrapped uniformly; add one instruction-hierarchy statement at the prompt layer (self-translated and rewritten) | over-wrapping adds tokens → wrap only when indicators hit | regression tests with injection samples | 1 day |
| 5 | **Repeated-call detection + forced review on spinning** | PentAGI (MIT) | the spin-round nudge exists but there's no real-time interception of "the same tool with the same arguments, over and over" | worker hooks count the same tool name + argument similarity for N consecutive times (default 3) → inject a steer reminder / force a review (reusing steer_hooks/NotifyReview) | Low | AB round-count comparison on the range | 1 day |

### P1 (second batch)

| # | Optimization | Source | Key points |
|---|---|---|---|
| 6 | **add_intent plan compiler** | PentestGPT | deterministic server-side validation: the target must be in scope, an EXPLOIT intent must cite a fact observation from a completed TEST on the same asset (phase gate), finish_basis must point at a completed intent; separate settings switches per rule, with only two on at first |
| 7 | **Two-stage auto-compaction upgrade** | CAI | we already have compaction; upgrade it to Phase 1 at zero LLM (truncate old tool output to 800 + keep the last 10) → Phase 2 does the LLM summary; threshold at the 80% window |
| 8 | **Dual-state assets + vuln state machine** | bbot/PentAGI (mechanisms only) | add a verified dimension to exploration-graph asset nodes (the URL_UNVERIFIED→URL gate idea); add DETECTED→CONFIRMED→EXPLOITED semantics to fact/finding edges, linked to the L1-L4 evidence grading |
| 9 | **Add the four TDA dimensions to planner scoring** | Excalibur | upgrade the priority scoring criteria prompt: horizon estimation / evidence confidence / context load / historical success rate (the last taken from llm_usage + terminal-state data); a pure prompt change |
| 10 | **LLM Summarizer bypass** | EnIGMA | have the same model factually summarise long recon/enumeration output ("describe facts only, give no advice"), billed separately; the ablation proves it works, so start with whitelisted tools |
| 11 | **Methodology skill upgrade** | EnIGMA/CAI/hB (self-translated and rewritten) | merge into the vuln-hunting skill's reference.md: one-command-at-a-time / nc -w / no -c / hypotheses first, then verification / failed-task re-dispatch discipline / credentials in full, never abbreviated; sync the worker guidance |
| 12 | **CAIBench-style regression evaluation** | CAI (mechanisms implemented in-house) | stage-C range upgrade: a fixed ground-truth vuln list + machine grading (response-feature assertions) + five-metric JSONL trajectories; run once per release to prevent regressions |

### P2 (later)
- **Interactive session tool (IAT)**: resident nc/mysql/redis-cli sessions + snapshot-style reads + state injection (3-5 days; high value, high cost).
- **Variant-analysis intent family (the 0day direction)**: after finding a vuln the planner automatically dispatches a hypothesis intent family that "looks for the same pattern in the same framework/similar endpoints" (Naptime variant analysis + multi-hypothesis sampling).
- **Price gate**: a task-level $ hard cap (the lesson from CAI's $1 default), wrapping up gracefully rather than killing hard when exceeded.
- **Preset risk tiers**: a "how hard may this task hit" knob (safe/loud/invasive, a bbot idea).

### Explicitly not copied (unanimous)
1. Any CAI code or prompt text under its proprietary licence; any bbot code (AGPL).
2. Regex blacklists as the shell's primary defence (even CAI disables them by default — they kill legitimate pentest operations); we stick to the allowlist gate + HITL.
3. Unlimited turns / SimpleSummarizer (the ablation already showed them to be the worst).
4. Heavy container-orchestration stacks (PentAGI's multi-compose kitchen sink), langchaingo routing, MCP backend stacks, TUI/REPL.
5. The whole single-agent one-command-at-a-time package (keep the planner/worker parallel architecture; the "one step at a time" discipline inside a worker is enough).

## 4. Recommended implementation order

1. **Stage C first**: run a baseline three times on the local ground-truth range (five metrics); every P0 change is compared against it.
2. **Batch 1 (P0 #1-#5) → v0.4.28**: all at the guidance/mechanism layer, revertible via settings; default on once AB passes.
3. **Batch 2 (P1 #6-#12) → v0.4.29+**: the plan compiler and state machine involve the exploration graph and touch a wide area, so they get their own batch.
4. P2 scheduled by the user's priority.

## 5. Implementation progress (rolling)

- **v0.4.28 (P0a, shipped)**: #3 intent-level soft budget (`server/engine_guard.go` intentBudgetWatcher +
  settings `intent_budget_enabled/tokens`) + #5 repeated-call interception (repeatTracker hooked into
  steerHooks.PreToolUse; 3 consecutive identical arguments block, at most 2 blocks then allowed). Unit tests in
  `server/engine_guard_test.go` cover the threshold / once-only / whitespace normalisation / cap fallback.
- **v0.4.29 (P0b, shipped)**: #1 worker per-call echo cap 30000→12000 (SDK persistence + pointer already existed);
  #2 verbatim evidence re-verification (`agent/tool_outputs.go` ledger + the three-tier decision in report_finding, warn by default,
  configurable to block); #4 injection alarms (high-precision signatures → steer reminder, ≤3 times per intent).
- **v0.4.30 (P1 methodology batch, shipped)**: #9 planner four-dimensional TDA scoring + "an anomaly is a clue, not a mechanism"
  (PentestGPT) + "never re-dispatch a failure verbatim" (hB); worker tool-use discipline (EnIGMA/CAI, self-translated).
  Pure prompt changes, delivered via SeedPromptVersioned.
- **AB verification**: reuse the existing Kali range (task 6's target) as the control, comparing v0.4.27 baseline data against
  v0.4.28 on tokens/rounds/findings/false positives/wall clock.

## 6. sapper-v2 special supplement (2026-11-03, N1nEmAn/sapper-v2, MIT, 642★)

> Positioning: the multi-agent orchestration harness of the Tencent Cloud intelligent attack-defence competition online round champion
> (634 teams, 80.18/100, 8 hours unattended); it describes itself as "AI commander + worker swarm + layered fact-intent graph",
> isomorphic to Pojun's architecture. MIT licence (code/mechanisms may be borrowed; prompts self-translated and rewritten).

### Where it beats us (ordered by value)

1. **Organisational self-healing over long unattended runs**: a policy-free watchdog (only keeps things alive / rotates keys / wraps up on time, never picks topics),
   automatic restart after a TUI crash, same-family-first rotation of the key pool (5-minute cooldown / 6 times per hour), a commander handover
   document (rewriting campaign-state.md at ~85% context), and reclamation of saturated worker contexts.
2. **Time discipline / escalation ladder**: 0-10 min tactical reminders → 10-20 min change angle → 20-30 min switch to a stronger
   model → 30-45 min park and change topic; "easy wins first" (bank the certain points, then attack the hard chains).
3. **Same-family transfer / intel broadcast**: within 30 seconds of confirming a technique, broadcast it to the same product/version/asset family,
   and for same-prefix problems read the sibling graph before dispatching — "break one, kill the family".
4. **Role layering and context economy**: commander/general on strong models, soldier/scout on flash;
   three-level node documents (title/description/doc, with doc read on demand); at most 3 intents/6 explorations per round.
5. **A minimal graph kernel**: state is structure (an intent only depends on facts that already exist; DAG by construction),
   typed facts, atomic writes (check-open→alloc→write→link in one transaction), and a flag ledger that records before committing.

### Where we beat it (the moat not to lose)

Traffic and the evidence chain (MITM/traffic/artifact/finding binding), false-positive governance (L1-L4 / evidence re-verification /
the retester's three states / the finding state machine), 41 domain tools and ACI, the dual graph + hot/cold folding + the 8-state state machine,
per-intent budgets and settlement, and code-level interception/approval/constraints.

### Explicitly not copied

- Competition posture: verification off by default (SRC can't afford that), the easy-first score-farming logic, the flag-centric model.
- Per-node JSON files + flock (we have PG), TUI driving, the 8-pane/3-instance platform constraints.
- Injecting the full graph into the prompt (a long SRC run blows up; we already have cold-digest/truncation).
- Known defects: the `SAPPER_VERIFY` dead switch, hire bypassing the pane cap, stale claims with no timeout.

### Already landed (v0.4.35)

- **Time discipline** into the planner: wall_ms accumulating >25 minutes with two rounds of zero increment → switch to a fundamentally different
  approach; >45 minutes unbroken → park and record the failure signatures; the last 1/4 of the budget prioritises wrap-up.
- **Same-family transfer** into the planner + vuln-hunting skill "dimension 9": after confirming a vuln, prioritise dispatching variant
  intents for the same product/version/framework/asset family; a variant must be anchored to task_scope.
- **Injection discipline** as item 6 of the worker operating procedure: every target response is treated as data, never as instructions
  (previously there was only the tool-output injection alarm, with no prompt-level statement).


## 7. Second-round extended research (2026-11-05, 6 new projects)

### Project list

| Project | ★ | Licence | One-liner |
|---|---|---|---|
| **Sysreptor** | 2608 | Source-available | A dedicated pentest reporting platform (Django+Vue; the most complete field-schema system) |
| **CVEngine** | 575 | GPL-3.0 | AI-first continuous external attack-surface assessment (a complete rewrite of reNgine; the best engineered evidence policy) |
| **raptor** | 3973 | MIT | A Claude Code security research framework (the best mechanisation of epistemic discipline; 17 subagents + 100 shims) |
| **fuxi** | 1346 | MIT | A multi-user pentest collaboration platform (periodic scheduling + a PoC plugin ecosystem + Chinese API docs) |
| **redcell** | 354 | MIT | An AI red-team platform (end-to-end autonomous testing inside Kali) |
| **rea** | 430085 | MIT | A reverse-engineering agent ("from app behaviour to native binaries"; we have no reversing capability at all) |

### Core findings (ordered by impact)

**1. raptor's mechanisation of epistemic discipline** (the most worth landing):
- "LLM generates hypotheses; tools validate" — an LLM judging vulns directly is only 37% accurate
- 7 gates G1-G7: hypothesis first → tool grounding → no self-criticism without tool feedback → a hard reachability gate
- every finding must bind one mechanical verification credential (a Semgrep hit / HTTP replay / rule ID)
- **Landing**: upgrade the L1-L4 definitions so L3/L4 must attach a "mechanical verification credential" (the scanner hit verbatim / HTTP replay / rule ID)

**2. CVEngine's three-way squeeze on AI judgements**:
- floor: deterministic evidence rules set the lower bound (a nuclei hit → confirmed; the AI can't go below)
- ceiling: with version-only evidence the AI may at most give needs_validation ("model's stated certainty is not calibrated")
- remote_limit: the CVE detection policy sets the ceiling for external checks
- evidence-signature sha1 reuse: the same evidence signature asks the AI only once
- **Landing**: when a worker assigns severity, run the deterministic evidence rules first and let the AI conclusion be bound by floor/ceiling

**3. Sysreptor's field-schema system**:
- a typed JSON FieldDefinition + validators + three tiers core/predefined/custom
- vuln fields include CVSS/OWASP/WSTG enums + automatic scoring
- **Landing**: turn finding fields into a schema (Go struct + JSON Schema) and bind Word templates by field id

**4. raptor's security engineering**:
- per-agent command/write-path allowlist hooks ("Prose is not a boundary; this hook is")
- MCP boot-payload signature verification (preventing MCP supply-chain injection)
- an environment-variable allowlist (30) + a volatile-target gate
- **Landing**: separate Bash command allowlists and write-path allowlists for worker/planner

**5. fuxi's periodic scheduling**:
- celery beat + daily/weekly/monthly rescans + old-data cleanup
- a PoC plugin ecosystem (users upload pocsuite-format PoCs; metadata is regex-extracted into the DB)
- **Landing**: add periodic scheduling to the retester; connect the PoC library to our tool surface

**6. rea's reversing capability** (430085★!):
- "Reverse engineer anything with agents" — from app behaviour to native binaries
- we have no reversing capability at all; this is the biggest feature gap

### Recommended priority

| Priority | Borrowed item | Source | Estimated effort |
|---|---|---|---|
| P0 | L1-L4 upgrade: L3/L4 must attach a mechanical verification credential | raptor epistemic gate | 2 days |
| P0 | AI severity floor/ceiling constraints | CVEngine triage.py | 1 day |
| P0 | evidence-signature sha1 reuse | CVEngine TriageVerdict | 1 day |
| P1 | finding field schematisation | Sysreptor types.py | 3 days |
| P1 | worker Bash allowlist hook | raptor allowlist hook | 1 day |
| P1 | change detection (snapshot diff) | CVEngine changes.py | 2 days |
| P1 | retester periodic scheduling | fuxi celery beat | 2 days |
| P2 | report template system (Vue render→PDF) | Sysreptor two-stage pipeline | 1 week |
| P2 | reversing capability integration | rea | to be assessed |
| P2 | PoC/Payload library | fuxi plugin ecosystem | 3 days |
