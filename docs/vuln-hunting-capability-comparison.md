# Vulnerability Discovery Capabilities: Comparison with Open-Source Peer Products

> 2026-10-22 inventory. Goal: compare the "vulnerability discovery" capability line (methodology → intelligence → tools →
> evidence → orchestration → closed loop) with open-source peer products, to find out **what's still missing**.
>
> Every conclusion in this document is tagged with its **evidence source** — "definitely absent in the code" is more reliable than grep returning nothing
> (during this inventory, twice did empty grep output lead to a false conclusion that a capability was missing, when in fact it existed).

---

## I. ARTEX Current State (Self-Inventory, Six Layers)

| Layer | Existing Capabilities | Evidence |
|---|---|---|
| **Methodology** | `vuln-hunting` skill: seven dimensions (object substitution / process decomposition / state machine / data boundary / resource assumptions / error paths / composition), each giving core questions, techniques, verification points, and evidence forms; `reference.md` has ready-to-use commands and script templates | `skills/vuln-hunting/` |
| | `api-recon` skill: front-end API/parameter surface reconnaissance (with a full flow using mocks to expand SPAs) | `skills/api-recon/` |
| **Intelligence** | NVD + CISA KEV + PoC aggregation + nuclei template linkage | `vulnintel/` |
| | Asset fingerprint → CVE linkage (token-normalized loose matching between `technologies` and CPE product) | `vulnintel/link.go` |
| | **Recent high-risk fast lane**: pull the last 7 days by publishedDate, only accept CVSS≥9.0 or KEV, independent cursor + shared rate-limit gate | `vulnintel/fastlane.go` / `ratelimit.go` |
| | **Version-undetermined marking**: when the NVD version range is empty, mark "unconfirmed" rather than "unaffected" | `vulnintel/fastlane.go` `VersionRangeUndetermined` |
| **Tools** | 54: nmap/nuclei/httpx/katana/ffuf/sqlmap/hydra/impacket/netexec/msf/semgrep/pwntools + **15 middleware protocol libraries** (gmqtt/pika/pymongo/zeep/netmiko…) | `hosttools/hosttools.go` |
| **Evidence** | MITM traffic retention + `traffic_search`/`traffic_get`/`traffic_blob` (**bound to worker and reporter**) + finding four-purpose binding (baseline/proof/verification/supporting) + evidence versioning | `server/finding_workflow.go` `readers := ["worker","reporter"]` |
| **Orchestration** | planner dispatches intents / worker executes / `idlestop` ends idling / `wrapup` wraps up / `steer_work` manual correction / continuation generation limit 3 | `agent/planner.go` `worker.go` `idlestop.go` |
| **Quality** | Adversarial self-check (switch identity/parameter order/client to reproduce) + 8 triage states + retest closed loop + graph writeback (fact/asset/finding/hint) | `db/findings.go` `db/finding_retests.go` |
| **Control** | Built-in rules in three layers (explicitly forbidden 10 / handed to Agent for judgment 12 / manual confirmation 1) + rule-level timeout genuinely effective | `db/intercept_builtin_rules.go` |

**Two places confirmed "actually usable"** (once falsely judged nonexistent due to empty grep output):

- traffic trio **bound to worker** (not just reporter) → worker can review its own sent requests while discovering
- Asset DTO **contains an `auth` field** (`agent/tools_insert.go`) → discovered credentials can be retrieved via `list_assets`

---

## II. Confirmed Gaps (Definitely Absent in Code)

| # | Gap | Impact | Evidence |
|---|---|---|---|
| **G1** | **No fuzzing engine** | In vuln-hunting, the two dimensions "data boundary" and "resource assumptions" inherently rely on fuzzing to find boundaries. Currently the model can only hand-write scripts — coverage and efficiency are both uncontrolled | boofuzz/radamsa/atheris/hypothesis/schemathesis are all 0 in hosttools |
| **G2** | **No differential/baseline comparison tool** | "Compare two responses to find differences" is a core technique in the methodology (authorization bypass, enumeration, state machine all rely on it); currently the model can only hand-write python for diff | diff-type tools 0 in hosttools |
| **G3** | **No code asset / source repository concept** | semgrep is installed but only as a binary, **scan results cannot enter the graph**, and worker cannot get source context. **No bridge** between SAST and dynamic discovery | source_repo/code_asset-type concepts 0 in `db/assets.go` |
| **G4** | **No exploit-chain orchestration** | There is `steer_work` (manual correction), but no chaining mechanism where "after A succeeds, automatically dispatch B to use the result". Serial chains rely entirely on planner judging on the graph | The continuation discipline in `agent/planner.go` is a **text convention** (fill in the `continues` field), not a mechanism |
| **G5** | **No auth-state/multi-identity management** | The prerequisite for horizontal privilege escalation is "two identities". Assets have an `auth` field, but there is **no tool to "use this account to call this API"** — the model must hand-craft curl | No credential-reuse-type tools in hosttools/agent tools |

---

## III. Candidate Solutions to Fill Gaps (Package Names Verified to Exist)

| Gap | Candidate | Version | Verified |
|---|---|---|---|
| G1 | `boofuzz` — protocol fuzzing (Sulley successor) | 0.4.2 | PyPI ✓ |
| G1 | `atheris` — Python coverage-guided fuzzing | 3.1.0 | PyPI ✓ |
| G1 | `schemathesis` — OpenAPI/GraphQL adaptive API testing | 4.32.3 | PyPI ✓ |
| G1 | `hypothesis` — property-based testing (can serve as a base for differential/invariant testing) | 6.170.5 | PyPI ✓ |
| G2 | No new package needed — `hypothesis` + a "response diff" script suffice; but making it a tool is more robust | | |
| G3 | `bandit` — Python SAST (complement beyond semgrep) | 1.9.4 | PyPI ✓ |
| G5 | Middleware libraries like `netmiko`/`pika`/`pymongo` already exist; what's missing is a **platform-side credential-reuse tool**, not a new dependency | | |

> `radamsa` / `gitleaks` / `trivy` are not on PyPI (binary form in GitHub releases).
> gitleaks is already installed (present in hosttools).

---

## IV. Comparison with Open-Source Peer Products (Researched 2026-10-22)

Research subjects (all READMEs actually fetched and verified):

| Project | Stars | Positioning |
|---|---|---|
| **pentagi** | ★32k | Self-hosted multi-agent autonomous penetration system |
| **Anthropic-Cybersecurity-Skills** | ★35k | 818 structured security skills, 34 domains, mapped to 6 MITRE/NIST frameworks |
| **PentestGPT** | ★16k | LLM-driven penetration testing agentic framework |
| **hexstrike-ai** | ★13k | Collection of AI penetration tools in the form of an MCP server |
| **AutoPentest** (bhavsec) | — | **Methodology-driven**: 109 OWASP WSTG cases + 31 PortSwigger guides |
| **vulnhuntr** (protectai) | ★2.8k | **Zero-shot vulnerability discovery** (closest to ARTEX's scenario) |
| **OpenAnt** (knostic) | ★781 | LLM vulnerability research framework |
| **strix** | — | Autonomous AI penetration agent |
| **Shannon** (KeygraphHQ) | — | Dual track of **white-box source analysis + live exploitation** |
| **Nebula** (berylliumsec) | — | Human-in-the-loop desktop-style AI penetration workbench |
| **CAI** (aliasrobotics) | — | Multi-agent hacking framework (archived, but the mechanism is worth a look) |

### 4.0 Industry-Wide Consensus and ARTEX's Position

**Consensus (nearly all projects have these)**:

1. **Multi-agent orchestration**: the orchestrator doesn't touch the target, dedicated sub-agents execute
2. **"Must have a PoC to report"** — no exploit, no report, is the industry threshold
3. **Container/sandbox isolation** for executing against targets
4. **CI integration + SARIF/Markdown multi-format reports**
5. **HTTP interception proxy + browser automation** dual verification channels
6. **Scope and permission constraints** (out-of-bounds is the biggest risk)
7. **Multiple pluggable LLM providers**

**★ ARTEX's judgment here**:

- Consensus items 1/2/3/4/6 we **all have** (orchestration/adversarial self-check + evidence/hostd isolation + reports + triage/control rules)
- **"Continuous intelligence operations by time flow" is almost nobody's work in the industry** — only CAI explicitly uses NVD/MITRE/GHSA to pull the latest advisories;
  Strix does "match assets against known CVEs"; the rest are basically static knowledge bases.
  **Not one has built "what blew up in the last 7 days → match my assets → queue them up".**
  **This is exactly what ARTEX's fast lane does — this is our leading item, not a shortcoming.**

**★ A shortcoming where we don't have an edge, but which is underestimated** (from the research):

> "CVE intelligence matching commonly doesn't do reachability/affected-version determination, easily reporting unreachable dependencies as high-risk."

**We hit the same wall**: the NVD version ranges for those two PHP CVEs are **empty** (`cpe:2.3:a:php:php:*:*`).
Currently we can only mark "version undetermined" — **this is damage control, not a solution**. The solution is to **connect a second version-range source**
(GitHub Advisory Database's GHSA API / OSV.dev), see M10.

### 4.1 Key Mechanism Differences (ARTEX Has / Lacks / Can Learn From)

| Mechanism | pentagi | Anthropic-Skills | ARTEX Current State |
|---|---|---|---|
| **Execution monitoring + Mentor intervention** | Yes: Adviser agent automatically intervenes when execution patterns are abnormal; **Progress Analysis specifically detects loops and inefficiency** | — | Has `idlestop`, but **fixed rules** (3 consecutive rounds of zero writeback), not LLM judgment |
| **Task pre-decomposition** | Yes: Planner first breaks into 3-7 concrete steps then dispatches specialist agents; **Scope Management prevents scope creep** | — | planner dispatches ≤4 intents at a time, **no explicit pre-decomposition step** |
| **Standardized tags for skills** | — | Yes: each skill maps to the **relevant ones** among ATT&CK/CSF/ATLAS/D3FEND/AI RMF/F3, validated with official libraries | **No tags at all** — skills cannot be searched by ATT&CK/CWE, coverage cannot be measured |
| **Skill scale and domains** | — | 818 skills / 34 domains | **4 skills** (api-recon / playwright-cli / scopesentry / vuln-hunting) |
| **Vector memory** | Yes: pgvector remembers "what works" | — | No vector search; only the graph (facts/assets/findings/hints) |
| **Knowledge graph** | Yes: Neo4j tracks host/service/finding | — | Yes (PostgreSQL graph), **but no vector memory** |
| **Isolated tool execution** | Yes: Docker sandbox | — | Yes (hostd privileged helper + control rules) |
| **Behavior observability** | Yes: langfuse + grafana | — | Has journalctl + interception history, **no agent behavior tracing** |
| **Intelligence sources** | — | — | **NVD + CISA KEV + PoC + nuclei + asset linkage + recent high-risk fast lane** (this layer we're not weak) |
| **Protocol tool breadth** | 20+ | — | **54 (including 15 middleware protocol libraries)** (we're broader) |
| **Vulnerability verification** | Report + exploitation guide | — | Yes: adversarial self-check (switch identity/parameters/client to reproduce) + traffic evidence binding + 8 triage states |
| **Adjudication layer** | None (conclusion is model output) | None (relevance analysis) | **Adjudication is model self-report** — this is a shortcoming (M20) |
| **Model isolation** | Admits shortcoming: Challenger uses the same model as generation, shared blind spots | N/A | **judge and worker use different models/contexts** — structurally able to do "adversarial recheck with different models", but **currently not used** |

### 4.2 Mechanisms Worth Adding to ARTEX Seen from the Comparison (Ranked by Cost-Effectiveness)

| # | Mechanism | Source | Why It's Worth It | Cost |
|---|---|---|---|---|
| **M1** | **Standardized tags for skills** (CWE / ATT&CK / vulnerability type) | Anthropic-Skills | Currently skills are "islands": cannot be searched by CWE, cannot measure "do we have a methodology for this type of vulnerability", cannot build a capability matrix. With tags, **when a task arrives, a skill can be selected by tag** instead of relying on model memory | Low — add fields to frontmatter + a search API |
| **M2** | **Differential/baseline comparison tool** | General (ARTEX lacks internally) | The core technique of three vuln-hunting dimensions (authorization bypass/enumeration/state machine) is "compare two responses"; currently the model can only hand-write python | Low — one script + one tool |
| **M3** | **Credential-reuse tool** | General (ARTEX lacks internally) | Assets **already have** `auth` data, but it can only be read as text; the prerequisite for privilege-escalation discovery is "two identities" | Low — one tool (read asset auth → send authenticated request) |
| **M4** | **LLM version of loop/inefficiency detection** | pentagi (Progress Analysis) | Current `idlestop` is a fixed rule of "3 consecutive rounds of zero writeback", **cannot detect "writebacks happening but going in circles"** (repeating the same thing with different wording). Such idling is a real cost | Medium — requires an LLM call to analyze the execution trace |
| **M5** | **Planner's explicit pre-decomposition** | pentagi | Currently planner dispatches ≤4 intents at a time, but **lacks the layer of "first break into 3-7 concrete steps"**; with complex targets, dispatches tend to be scattered | Medium — change planner prompt + possibly new structures |
| **M6** | **Vector memory (what works/what doesn't)** | pentagi (pgvector) | Currently cross-intent experience transfer relies on fact text; negative experiences like "this path doesn't work" are easily lost | High — need to introduce a vector store + search |
| **M7** | **Fuzzing engine integration** | General (ARTEX lacks internally) | The two dimensions "data boundary" and "resource assumptions" inherently require fuzzing | Medium — install boofuzz/schemathesis/atheris + orchestration |
| **M8** | **Code asset/SAST linkage** | General (ARTEX lacks internally) | semgrep is installed but results can't enter the graph, and worker can't get source context — **no bridge between dynamic discovery and static auditing** | High — need to introduce a new concept "code asset" |
| **M9** | **Mechanized orchestration of exploit chains** | General (ARTEX lacks internally) | Currently serial chains rely on planner judging on the graph + `continues` text field convention, no mechanism for "automatically dispatch B after A succeeds" | High |
| **M10** | **Second data source for version ranges** (GHSA / OSV) | Common shortcoming from research | NVD **often leaves version ranges empty** for newly disclosed CVEs (those two PHP CVEs are `cpe:2.3:a:php:php:*:*`). We can only mark "version undetermined" — damage control but not a solution. Connecting GHSA/OSV gives affected ranges | Medium — another data source, structure similar to NVD |
| **M11** | **Three-state closure** (confirmed / ruled_out / open_proof_gap) | Strix (counterevidence) | Currently we're two-state: "report only if confirmed / don't report if not confirmed". Strix requires `ruled_out` to **name the control point** (which protection, where on the attack path, why it executes before the sink), `open_proof_gap` explicitly keeps a ledger. **Our "reached the boundary" judgment is currently model self-report, with no evidence requirement** | Medium — change field semantics of report/record_fact |
| **M12** | **Coverage ledger** (every surface has a conclusion) | Strix (SARIF coverage) / Shannon (WSTG checklist) / AutoPentest (coverage report) | "Checked and clean" ≠ "not checked". We have a coverage concept, but **don't produce a ledger of "which surfaces are done"** | Medium |
| **M13** | **PoC sandbox verification layer** | Strix (Exploit Runtime) | We stop at "retrieve PoC" + adversarial self-check (reproduce by switching paths). Strix marks verified only when "PoC **actually runs through** against the target in a sandbox" — completely separating "intelligence hit" from "vulnerability confirmed" | High — need an execution environment |
| **M14** | **API contract-driven enumeration** | Strix (reads OpenAPI/Swagger/Postman directly) | We rely on crawler (katana) and fuzzing to discover APIs. **Contract files are a more accurate source of API inventory** — they directly answer "what APIs, what parameters, what methods" | Low — read contract files + parse |
| **M15** | **Structured attack-surface graph + role permission lattice** | Shannon (trust zone / role dominance relations) | The prerequisite for privilege-escalation discovery is "what roles exist, who can access what". We have no **structured permission model** — can only have the model infer from traffic on the fly | High — need a new data model |
| **M16** | **Decision/generation/parsing three-model separation** | PentestGPT | **Directly hedges ARTEX's known thinking-model budget trap** (the memory note: minimax-m3.1 forced thinking eats all output quota, causing empty compression/adjudication replies). Only hand decision points to strong models; generation/parsing use cheap models | Medium — need to change provider layer |
| **M17** | **WAF bypass adaptation + scenario-specific payloads** | AutoPentest (payloads by sink context) | Currently we give generic payload dictionaries. Giving different forms by sink type (sql_string/command_shell/html_body) greatly improves success rate | Medium |
| **M18** | **Unauthorized prompt-injection defense** (input+output bidirectional) | CAI (guardrails, Base64/32-aware) / Nebula | We feed target content into the model (captured pages, errors, response bodies) — **this is an inevitable injection surface**. Currently relying on the model's own judgment | Medium — need output-side decoding/homoglyph detection |
| **M19** | **Cost and cost-per-finding visibility** | Nebula (token/cache) / PentestGPT (pricing) / AutoPentest (measured $96/run) | We have llm_usage statistics, but **no "cost per finding"** — don't know which intent/tool combination is poor value | Low — data already exists, missing an aggregation view |
| **M20** | **Deterministic adjudication layer forcibly separated from LLM judgment layer** | OpenAnt | OpenAnt's hard rule: the model only outputs "concrete facts with verbatim quotes", **code verifies whether the quotes actually appear in the evidence the model saw** before deriving the adjudication — "the model's self-judgment never counts". Currently we have **model directly outputs conclusion + triage state**, equivalent to letting the model vouch for itself | Medium — change field semantics of report/record_fact (require fact + quote, not just conclusion) |
| **M21** | **Unexecuted checks must report unverified, no silent pass** | OpenAnt | Verification that failed to run reports "unverified" rather than "passed". We're currently stepping on this line: findings that reached a boundary but weren't reproduced have ambiguous status | Medium — concrete implementation of three-state closure (M11) |
| **M22** | **Stage-level model routing** | OpenAnt | Seven stages each configured with provider/model: strong models for detection/verification/reachability, light models for context building and reports. **Directly hedges the memory note** (minimax-m3.1 forced thinking eats all output quota, causing empty compression/adjudication replies) — strong models only used at judgment points that truly need reasoning | Medium — need to change provider layer (finer than M16 three-model separation) |
| **M23** | **Incremental scanning by git diff hunk + pre-commit hook** | OpenAnt | Only scan units whose "function bodies overlap with diff hunks", reducing cost by an order of magnitude. Can serve as a **second gate before commit/merge**, no need for full rescans every time | Medium — need code asset concept (do G3/M8 first) |
| **M24** | **Attack chain/correlation escalation** | hexstrike (VulnerabilityCorrelator) | Chain multiple low-severity findings by reachability then evaluate value. Solves two things at once: suppress false-positive noise (noise can't form a chain), avoid "stop when one is found" | High — depends on G3/exploit-chain orchestration |
| **M25** | **MCP as bridge between AI Agent and attack tools** | hexstrike | hexstrike's 150+ tools all go through MCP, reusing Claude/Codex's existing agent loop instead of building its own LLM loop. **ARTEX's hostd privileged helper + tool table is essentially the same idea**, but has no MCP exit — external agents can't connect | Medium — hostd already has a privilege boundary, adding MCP adaptation is incremental |

### 4.2.1 Methodology Differences Between the Two Researches (Worth Noting Separately)

OpenAnt and hexstrike took **two opposite paths**; this comparison is more valuable than any single mechanism:

| | OpenAnt (source-level) | hexstrike (tool-level) | ARTEX (current position) |
|---|---|---|---|
| **Discovery method** | Pure LLM reasoning + adversarial verification, no reliance on CVE libraries | Tool-driven, LLM only does scheduling and parameter selection | Intelligence-driven + LLM reasoning (both in embryonic form) |
| **False-positive control** | Deterministic code verifies quotes, **model self-assessment doesn't count** | Correlation chaining, README claims 2.1% false positives (no third-party reproduction) | Adversarial self-check (switch identity/parameters/client to reproduce) |
| **Output contract** | CI exit-code contract (0 clean / 1 vulnerability found / 2 scan failed) | Vulnerability cards + real-time dashboard | finding + 8 triage states + evidence chain |
| **Deployment boundary** | Only modifies temporary copies, never automatically modifies target repos, leaves deployment decisions to humans | Requires isolated environment, warns agent has system-level privileges | hostd privileged helper + built-in control rules (three layers) |

**★ The most critical item for ARTEX**: OpenAnt explicitly writes "Challenger and generation use the **same model**, so it only narrows,
doesn't eliminate shared blind spots" — this points exactly to a **structural advantage** of ARTEX: our interception judgment (judge) and
discovery (worker) use **different models/contexts**. **Using different models for adversarial recheck** is something we can naturally do and
OpenAnt cannot — but currently we **haven't used this advantage** (worker's self-check is still in the same context).

**★ Another hard constraint** (worth copying directly): OpenAnt's "Everything that decides whether a
patch is applicable ... is deterministic code operating on that output" —
adjudication must be deterministic code. ARTEX's `record_fact` / `report_finding` currently accept model self-reported
conclusions, which is exactly the disease M20 aims to cure.

### 4.3 Where ARTEX Is Clearly Stronger (Don't Lose It)

- **Intelligence layer**: automatic asset fingerprint → CVE linkage + recent high-risk fast lane + version-undetermined marking. Most peers' intelligence is "query by component"; we also did "by time flow".
- **Evidence chain**: MITM traffic retention + four-purpose binding + versioning. Most projects only have "report text".
- **Control layer**: rules in three layers + rule-level timeout genuinely effective. Most projects have a single "approve or not" switch.
- **Protocol breadth**: 54 tools vs 20+.

---

## V. Priority Recommendations (Finalized After Comparison)

**First Batch (Low cost, high certainty, already in progress this round)**

1. **G5 credential-reuse tool** (`auth_request`) — prerequisite for privilege-escalation discovery, and the assets **already have the data** (pure waste).
   **Implemented this round** (`agent/tools_auth.go`): choose auth method by credential form (token→Bearer / cookie type→Cookie header /
   username-password→-u), POSIX single-quote escaping (verified with real shell parsing), **only assembles commands, doesn't send requests** (goes through unified traffic recording and approval control).
2. **G2 differential comparison tool** — lowest cost (one script), directly serves the core technique of three dimensions
   **Implemented this round** (`agent/tools_diff.go` + `agent/tools_diff_test.go`):
   - **File mode**: model uses `curl -i` to save two responses → tool **reads files and computes directly** (zero network, zero scripts);
   - **URL mode**: tool writes a Python diff script in the **current run's working directory** → returns a
     command to "fetch two responses + do the diff" for Bash to execute (**requests go through the recording proxy and approval control**, same pattern as
     `scan_with_nuclei`/`auth_request`);
   - Criteria: filter out fields whose **value shapes** look like noise (timestamps/UUID/trace ids/base64), **keep key additions/deletions**
     (extra fields are often exactly the data obtained via privilege escalation); **credential-type field values are automatically redacted**;
   - The two implementations (Go side and Python side) **must be equivalent** — there's a comparison test that actually runs python and compares field by field;
   - Integrated into three dimensions of the `vuln-hunting` skill (object substitution/state machine/existence enumeration),
     and replaced the old guidance in the skill that said "hand-write python for diff".
3. **M14 API contract-driven enumeration** — read OpenAPI/Swagger/Postman to get an API inventory, more accurate than a crawler
4. **M1 standardized skill tags** (CWE/ATT&CK) — make skills searchable and coverage measurable
   **Implemented this round** (`server/skill_tags.go` + four built-in skills tagged):
   - Tag format is in the `tags:` block of SKILL.md frontmatter (three types: cwe / attack / class);
     norma's yaml parsing ignores unknown fields — tagged skills are completely transparent to norma
     (there's a guard test `TestTaggedSkillsStillLoadWithNorma` watching this);
   - ARTEX-side parser (`LoadSkillTags`), keyed by **directory name** (consistent with the binding key of agent_skill_visibility);
     parse failure = no tags, not an error (third-party skills often have no tags);
   - `GET /api/skills` returns the tags field, skill management page shows tag badges
     (CWE/ATT&CK use outline, class uses secondary);
   - vuln-hunting tagged with 10 CWEs (covering the core IDs for privilege escalation/authentication/IDOR/race conditions/composite exploitation) +
     T1190 + 8 classes; api-recon tagged with CWE-200 + T1595.002 + recon class;
   - **Next step needed for closure**: CVE entries stored with CWE IDs (GHSA's cwes field is already
     parsed in `vulnintel/ghsa.go` but not persisted) — once persisted, the search loop of "find CVE → automatically suggest the corresponding
     methodology skill" works. This is second-batch work (requires schema changes).

**Second Batch (Requires changing the data model or orchestration)**

5. **M10 second data source for version ranges** (GHSA/OSV) — directly solves the "new CVEs have empty version ranges" **industry-wide common shortcoming**
   **GitHub Advisory Database implemented as second source this round** (`vulnintel/ghsa.go` / `ghsa_range.go` / `ghsa_store.go`):
   - **No new table** — reuse `vuln_cves` (`source='ghsa'`) + `vuln_cpe_products`,
     `search_vulns`' search and version determination **take effect automatically** (no second set of queries, avoiding inconsistent logic);
   - GHSA's version ranges are **required** (`vulnerable_version_range` + `first_patched_version`),
     after converting semver ranges to the existing start/end columns, `VersionInRange`'s three-state determination works directly;
   - **Conservative determination**: version can't be parsed (dev builds like `8.3.1-dev-build`), range operators unrecognized,
     empty range — all judged "possibly affected". The error direction is asymmetric: falsely judging "unaffected" makes the model skip the vulnerability outright;
   - **Coverage boundary (important, not overstated)**: GHSA covers **components with a package ecosystem** (composer/npm/pip/maven/…),
     **CVEs of PHP core itself are not in GHSA** (tested: CVE-2026-109618/109619 return empty arrays in the GHSA API).
     So GHSA is a **supplement, not a replacement** — it supplements "components with a package ecosystem" which make up the bulk of our assets,
     core-language CVEs still rely on NVD + vendor advisories;
   - End-to-end verification done on a test machine (192.168.198.130): real GHSA fetch → real persistence →
     correct version determination (3.9.0 affected / 3.10.0 unaffected / 3.10.1 unaffected) →
     `search_vulns`' product search path hit → verification data cleaned up.
6. **M11 three-state closure** (ruled_out must name the control point) — cures "reached the boundary" being only model self-report
7. **G1 fuzzing integration** — high payoff, but must be integrated into worker workflow (not just installing a binary)
8. **M4 LLM version of loop detection** — current idlestop can't detect "writebacks happening but going in circles"
9. **M12 coverage ledger** — "checked and clean" ≠ "not checked"
10. **M16 three-model separation** — directly hedges the known thinking-model budget trap

**Third Batch (Large scope of changes, proceed with caution)**

11. **G3 code asset/SAST linkage** (M8) — need to introduce the new concept "code asset"
12. **M13 PoC sandbox verification layer** — need an execution environment
13. **M15 structured permission model** — need a new data model
14. **G4 mechanized orchestration of exploit chains** (M9) — depends on planner mechanism changes
15. **M17 WAF bypass adaptation**, **M18 prompt-injection defense**, **M19 cost view** — each independent, can be slotted in anytime
