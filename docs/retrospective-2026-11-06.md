# Platform Data Retrospective (2026-11-06)

> Data source: full export of the Kali instance's artex database (tasks 1-18, of which 12 are real pentest tasks).
> This retrospective covers: task efficiency, token cost, intent execution, vulnerability output quality, channel health, mechanism problems.

## 1. Task efficiency summary (core)

| Task | Wall clock (h) | Intents done | Vulns | Critical+high | Input tokens (M) | LLM time (min) | M/vuln |
|---|---|---|---|---|---|---|---|
| 5  | 20.8 | 305 | 66 | 51 | 1207 | 2526 | 18.3 |
| 6  | 13.5 | 74  | 9  | 6  | 137  | 265  | 15.2 |
| 7  | 11.1 | 319 | 50 | 24 | 846  | 1680 | 16.9 |
| 8  | 2.5  | 94  | 10 | 5  | 178  | 349  | 17.8 |
| 9  | 7.6  | 234 | 72 | 48 | 590  | 1096 | **8.2** |
| 10 | 1.8  | 53  | 4  | 1  | 91   | 194  | 22.9 |
| 12 | 9.3  | 224 | 32 | 16 | 504  | 1476 | 15.8 |
| 13 | 36.3 | 46  | 7  | 3  | 113  | 272  | 16.2 |
| 15 | 3.0  | 103 | 21 | 9  | 200  | 575  | **9.5** |
| 16 | 6.5  | 121 | 6  | 0  | 108  | 816  | 18.0 |
| 17 | 16.2 | 167 | 3  | 2  | 160  | **1981** | **53.5** |
| 18 | 4.2  | 163 | 15 | 3  | 134  | 787  | **8.9** |

- **Best**: tasks 9 / 18 / 15 (8.2-9.5M tokens/vuln) — newer versions (v0.4.55+) are clearly more efficient.
- **Worst**: task 17 (53.5M/vuln): 1981 minutes of LLM time for only 3 vulnerabilities. Causes compound:
  the LongCat compactor's 69 errors (the entire 11.4% error rate is concentrated in this task) + slow-channel retries.
- Task 13 had 36h wall clock but only 46 intents: idling across days (pause/resume cycles), not an execution problem.
- Task 16: all 8 objectives met, 121 intents completed, only 6 low-severity — the targets were thin-surface sites, so
  the limited output is the target's own doing, not spinning in place (the intent content was all genuine targeted testing).

## 2. Token cost structure (real llm_usage ledger)

| Role | Calls | Avg latency | Input (M) | Output (M) | cache hit | Errors |
|---|---|---|---|---|---|---|
| worker | 45,622 | 10.1s | 4049 | 37.8 | 48.3% | 221 |
| planner | 9,976 | 26.9s | 1087 | 24.8 | 47.8% | 132 |
| **compactor** | **3,338** | **29.0s** | 12 | **9.4** | **13.9%** | **80** |
| main | 439 | 10.1s | 78 | 0.3 | 49.2% | 6 |
| judge | 315 | 4.5s | 2 | 0.1 | 36.2% | 0 |

- Total ~56k calls, 6.1B input / 77.6M output tokens, ~15,000 minutes of LLM time.
- **The compactor is a cost black hole**: 6% of calls eat 12% of output tokens (the most expensive part),
  with a cache hit rate of only 13.9%, 29s average latency, and 80 errors (69 of them concentrated in task 17, all LongCat).
- Model distribution: DeepSeek-V4.1-Flash as the workhorse (56.6k calls, 0.3% errors); LongCat 7.7k calls (1.7%);
  GLM/nemotron/qiniu free channels 60-70% error rates, egg-alpha 42%.

## 3. Execution and output quality

- **Intents**: 1,903, avg 4.3-5.7 min each; 28 exhausted on timeout,
  11 blocked=context canceled (restart leftovers, root cause fixed in v0.4.51), 12 killed (manual stops).
- **Vulnerability output**: 295 total, critical 25 / high 155 / medium 81 / low 34;
  after the hard evidence threshold (v0.4.52 mechanical verification): **thin evidence (<120 characters for critical/high) = 0**,
  traffic binding rate 92%+, only 7 missing a detailed report.
- **Duplicate vulnerabilities**: 0 duplicates after fingerprint deduplication.
- **Skill usage**: only 8 calls under the old bindings (vuln-hunting 6 / api-recon 1 / redteam-ops 1)
  — confirming "written but nobody could see it"; to be observed after the v0.4.56 full binding.

## 4. Improvements implemented this time

1. **Name the report-missing vulnerabilities before final settlement** (engine): both the goalless-done and settle
   paths check for vulnerabilities that have evidence but no report and flag them in the activity stream, preventing
   "silent empty-report delivery".
2. **Task revival self-healing** (admission): reviving from a terminal state automatically reopens leftover intents
   blocked="context canceled" (the 11 such intents in tasks 6/8/9 will automatically resume execution under the new
   mechanism); intents the user blocked manually are unaffected; regression tests included.
3. **Channel governance (Kali config)**: egg-alpha (42% errors) and GLM/nemotron/qiniu (60-70%) moved out of the
   rotation pool; the compactor pinned to the workhorse DeepSeek-V4.1 channel (0.3% errors).
   Expected: lower error-retry cost, better compaction stability.
4. **Task 18 paused** (stopped on instruction); the full data-side inventory is complete.

## 5. Follow-up recommendations (not implemented, by priority)

1. **Compactor cost reduction**: compaction output of 9.4M tokens is the single most expensive item. Options to try:
   lower the compaction output cap (compaction_output_tokens) + earlier in-session trimming in worker sessions
   (tool-output truncation threshold).
2. **Fill in channel context_window_k**: the field is 0 for every channel, so the router cannot perceive each model's
   real context limit — compaction over-limit errors (LongCat 11.4%) are related to this.
3. **Expectation management for low-yield targets**: thin-surface sites like tasks 16/17 could be flagged in the opening
   situational summary (graph_overview) as "narrow asset surface, expect limited output", letting the operator adjust
   targets/budget in advance.
4. **planner cache hit rate** (47.8%) still has room: the system prompt is already stable, and the remaining misses come
   mainly from inter-round graph situational changes — worth evaluating compressing the volume of graph_overview beyond
   moving the large situational block into this round's user input (already done).
5. **Skill usage observation**: after the v0.4.56 binding, watch whether skill_usage picks up; if still low,
   consider referencing skills explicitly inside the worker's five-step operating framework.
