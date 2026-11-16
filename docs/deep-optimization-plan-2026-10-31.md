# ARTEX Deep Optimization Plan (reporting capability x agent cognition x frontend presentation)

> 2026-10-31. Backed by three lines of research: (1) a line-by-line audit of the reporting path (the report/ package + the four export paths + the data side);
> (2) an audit of the agent cognition architecture (the full planner/worker/judge prompts + context engineering + loop gaps);
> (3) competitor benchmarking (NodeZero/XBOW/PentAGI/CAI/PentestGPT/PentestAgent papers/domestic reporting tools, 15+ sources with URLs).
> **This plan is to be executed after approval.**

## 0. One-sentence diagnosis

- **Reports**: the skeleton is complete (report -> reporter writes the body -> evidence versioning -> multi-format export), but "deliverable polish" is stuck in
  three places — the Word rendering layer has only 6 element types **and bullet points are broken** (missing numbering.xml); data already in the database
  (retests/status triage/CVSS/asset names/traffic evidence) **never reaches the report**; and structurally there is no executive summary/methodology/**attack-chain narrative**.
  The current state is about the level of mainstream domestic tools; it is three generations behind the benchmarks (NodeZero's attack paths + proof points, XBOW's self-verifying loop).
- **Agent**: prompt engineering is clearly above average (the judge prompt is the best in the whole repo), but **"mechanisms complete, judgment by guessing"** —
  the planner prompt asks for blocked_reason while the situational summary carries no such field at all; exhausted attribution queries the trace every round;
  intents have no hypothesis/success criteria (a worker handed a vague direction can only improvise); intent-level token cost is invisible.
- **Frontend**: process observability has a foundation (SSE session stream/exploration graph), but **attack-chain visualization** (sharing the report's data source)
  and a **cross-task aggregate insight layer** are missing.

---

## 1. Phase 1: report deliverable polish (maps to v0.3.93 / v0.3.94)

> Principle: keep the hand-written OOXML backbone (the de facto standard for domestic Word delivery), fill in the rendering layer and the data side, no rewrite.

### 1.1 Rendering-layer fixes and upgrades (report/docx.go + docx_build.go)

| # | Item | Notes | Size |
|---|---|---|---|
| A1 | **Add word/numbering.xml** | Bullet points currently do not render in Word at all (docx.go:55 references numId=1 but the package has no such part) — an obvious bug | S |
| A2 | **Severity colouring** | critical red / high orange / medium yellow / low blue: coloured run prefix on headings + row background in the statistics table | S |
| A3 | **A real cover page** | Vertically centred title, client name (Task.CompanyIDs->companies, the logo field already exists in the DB), date, classification placeholder, section and page breaks | M |
| A4 | **TOC field + header/footer page numbers** | `<w:fldSimple TOC>` (updated on open) + a PAGE field, with the report title/client name in the header | M |
| A5 | **Rich Markdown rendering** | `writeMarkdownish` supports Markdown tables -> real tables, `**bold**`, and `##` no longer degraded/flattened — the 8-section template the reporter writes keeps its hierarchy in Word | M |
| A6 | **Embed statistics charts** | `wcharczuk/go-chart` (zero-dependency pure Go) produces severity/category distribution PNGs embedded as media parts — charts beside tables, the first-glance polish of a commercial report | M |

### 1.2 Wiring up the data side (bring in data already in the DB that the report ignores)

| # | Item | Notes | Size |
|---|---|---|---|
| A7 | **status triage** | Export excludes false_positive/duplicate/ignored by default (a parameter can include them) — right now false positives go into the deliverable verbatim | S |
| A8 | **Readable asset names** | "Affected asset id:1,2,3" -> domain/IP/URL (resolveAssetIDs already exists) | S |
| A9 | **Retest subsection** | Append the latest retest verdict/summary/time to each finding (finding_retests already exists; fixed auto-sets status) | S |
| A10 | **Traffic evidence into Word** | baseline/proof/verification/supporting four-role bindings -> request/response code blocks + note (the md export already has this logic; copy it into docx) — **the binding mechanism is well designed but disappears from Word delivery** | S-M |
| A11 | **vulnintel enrichment** | "Known vulnerability" findings automatically carry the CVSS score/vector/KEV flag/description (the intel store is already linked to assets; the report layer consumes none of it) | M |
| A12 | **Report metadata** | Add commissioning party/authorization period/tester fields to Task (set in settings or when creating the task), used on the cover and in the scope section | M |

### 1.3 Structural upgrade (chapter level)

| # | Item | Notes | Size |
|---|---|---|---|
| A13 | **Executive summary** | The LLM aggregates findings into a management-level risk conclusion (severity distribution + top risks + a one-sentence overall assessment), stored in the DB, human-editable before export | M |
| A14 | **Scope and methodology chapter** | goals/timeline (FirstRunAt->CompletedAt)/asset distribution/tooling techniques — all the data exists, just assemble the chapter | S-M |
| A15 | **Remediation priority roadmap** | Three tiers: immediate (critical/high) / planned (medium) / opportunistic (low) | S-M |
| A16 | **Appendix: asset inventory** | Itemized by type (currently only counts) | S |
| A17 | **Same source for the page report and the export** | Change GET /api/report to build from the findings table (including the reporter body) — frontend preview and Word delivery become one and the same | S |

**The report's table of contents after phase 1**: cover (client/classification/date) -> TOC -> executive summary -> 1. Assessment overview
(statistics table + charts) -> 2. Scope and methodology -> 3. Vulnerability details (colouring/asset names/retests/traffic evidence/CVSS) ->
4. Remediation priority roadmap -> appendix (asset inventory). **This version alone reaches parity with domestic delivery standards and leads locally.**

---

## 2. Phase 2: agent judgment (maps to v0.3.95)

> Diagnosis: "mechanisms complete, judgment by guessing". Once this seven-piece set (about 300 lines of code + 60 lines of prompt) is done,
> it moves from "judgment by guessing" to "judgment fed by data", supporting long-term unattended operation.

| # | Item | Content | Size |
|---|---|---|---|
| B1 | **stop_reason into the situational summary** | compactIntents adds stop_reason (the DB column exists, the summary does not carry it) + renderTriggers in sync — the planner's "continue vs change direction" goes from guessing to seeing, saving 1-3 graph reads per round | S |
| B2 | **exhausted retrospective trigger** | When an intent with zero write-backs reaches a terminal state, the engine packages the last 3 steps' summaries into a trigger event, forcing the next planner round to attribute it once and record a fact ("direction #N died of X, do not continue") | M |
| B3 | **Intent structure: hypothesis/success_criteria** | intentItem gains optional fields (this direction's hypothesis/expected output/how it counts as success), rendered structurally by the worker — ending the status quo where a vague planner note leaves the worker improvising | M |
| B4 | **worker five-step operating framework** (prompt) | Restate the hypothesis -> list 2-3 probe vectors with discriminating signals -> write back after each result -> adversarial self-check -> answer explicitly whether the hypothesis holds; with a minimal bypass checklist (encoding/case/parameter position/method/CT/segmentation) | S |
| B5 | **worker self-protection** (prompt) | When an intent is self-contradictory or missing prerequisites, record_fact immediately with an explanation and stop, rather than grinding on until idle-stop; add "never write back a guess" to the closing wording | S |
| B6 | **guard attribution sampling** | blocked counts carry the last 3 sample commands + hourly bucketing — the last mile of "which directions are being defended" | S-M |
| B7 | **Intent-level token cost** | llm_usage gains an intent dimension, each recent_done_intents entry carries tokens — curing the root of the "longer summary -> more re-dispatch" positive feedback | M |
| B8 | **Prompt revision pack** | planner: format the three situational field lists / priority scoring criteria (currently an equivalent dead field) / the done-with-zero-writeback branch / depth-breadth arbitration rules / negative examples x2 / hard-baseline deduplication; goals: vague-goal rewriting rules; judge: empty arguments -> ASK, criteria for repeated packet sending; compaction: preserve terminal-state semantics | S |
| B9 | **Resume context summary + blocked rate limiting** | resume injects "last N rounds ended because of X, what was written back"; refuse re-dispatch after >=2 blocks in the same direction | S-M |
| B10 | **Independent compactor profile** | Compaction is a pure summarization task yet used a thinking model burning a 65536 budget + 20 minutes wall clock — give Compactor its own cheap default model and all the tuning pain disappears; llm.Config gains a thinking_budget knob | M |
| B11 | **Model routing strategy** (doc + default recommendations) | planner=strong reasoning (judgment work/short rounds/cache-friendly), worker=strong execution with medium reasoning, judge=non-thinking, goals=cheap model — the config surface is ready; record the strategy and default recommendations | S |

**Explicitly not doing** (judged over-engineering after research): a standalone reflection agent (the planner's per-round wake-up already is a reflection
loop; what was missing was input data), an automatic skill-distillation pipeline (risk outweighs benefit; do "one-click save a successful intent as a skill"
instead), a cross-task global vector experience store (lessons should be anchored to assets and travel with them), dynamic model routing by error rate.

---

## 3. Phase 3: attack-chain narrative + visualization (v0.3.96+, the generational gap versus NodeZero)

| # | Item | Content |
|---|---|---|
| C1 | **finding chain fields** | findings gain chain links (derived_from / enables / chained_with), automatically derived from exploration-graph lineage when the worker reports |
| C2 | **Attack-chain chapter** | The report gains an "attack path" chapter: a narrative of the chain from initial access to final impact, each step carrying its proof point (which fact/traffic proves it) — a direct projection of exploration-graph lineage |
| C3 | **Attack-chain graph embedding** | `goccy/go-graphviz` renders a PNG from the "asset -> vulnerability -> credential" graph into Word; the frontend task detail uses the same data source for an interactive graph (G6 is already the foundation) |
| C4 | **Cross-task aggregate insight page** | Risk trends by company/time, severity distribution, cost per unit of discovery (the deferred N8 folds in here) — the management reporting layer |
| C5 | **Verification loop (decided after observation)** | XBOW-style self-verification before reporting (replay traffic, compare signatures -> confirmed flag); first observe the false-positive rate after A10 traffic evidence + the retest subsection ship, then decide how strong to make it |

---

## 4. Execution cadence

| Version | Content | Status |
|---|---|---|
| v0.3.93 | A1-A10 (rendering fixes + data-side wiring) | ✅ released 2026-10-31 |
| v0.3.94 | A3 cover / A4 TOC header footer / A14-A16 structural chapters (A6 charts, A11 enrichment, A13 executive summary, A17 same-source deferred to v0.3.96) | ✅ released 2026-10-31 |
| v0.3.95 | B1/B3/B4/B5/B8/B9/B11 (B2 retrospective, B6 attribution samples, B7 token cost, B10 compactor profile deferred to v0.3.96) | ✅ released 2026-10-31 |
| v0.3.96+ | Deferred items + C1-C4 (attack-chain narrative + graph + insight page); C5 decided after observation | Not started |

Each batch as usual: tsc + next build + go test (real PG) -> tag and release -> verify one-click update on Kali.

---

## 5. Key evidence (excerpts from the research conclusions)

- Of the report's four export paths, **only the md format carries traffic evidence** — the Word format clients actually want lacks it (`report/findings.go:178-200` has ready logic to copy into docx)
- Word bullet points not rendering is an obvious bug: `docx.go:55` references `numId=1` but the zip has no `word/numbering.xml`
- The planner prompt explicitly asks for blocked_reason (planner.go:333), but graph_overview's compactIntents does not carry it (tools.go:22-51; the data lives in the `exploration_nodes.blocked_reason` column) — **the prompt and the data are disconnected**
- add_intent's priority determines the order in which workers claim tasks, yet there is no scoring standard anywhere, making it an equivalent dead field (tools.go:499 / 1251-1261)
- The compactor was bound to the same model as planner, burning 65536 tokens + 20 minutes wall clock (compaction.go:107 / 74-103), while it is a pure summarization task
- Three generations behind competitors: NodeZero's attack paths + proof points + Executive Narratives; XBOW's validator self-verification loop; PentAGI's knowledge graph + trace observability. Domestic tools (SecReport/PAIStrike/360) are isomorphic to ARTEX's current state — **adding attack chains and self-verification is exactly what moves it from "isomorphic" to "leading"**
