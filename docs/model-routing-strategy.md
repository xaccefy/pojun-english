# Model Routing Strategy (v0.3.95 B11)

> The configuration surface has long been ready: the six roles goals / planner / worker / mainagent / judge / compactor
> each have independent LLM resolution (agent binding -> task chain -> global activation; judge additionally has its own
> profile + prompt + timeout). What this document records is the **strategy and default recommendations** — which model
> tier each role should be configured with, and why.

## 1. Role x model tier recommendations

| Role | Recommended tier | Rationale |
|---|---|---|
| **planner** | **Strong reasoning (thinking)** | Judgment-heavy work: deduplication, continuation attribution (stop_reason), goal determination (quantified prove_goal checks), depth-vs-breadth arbitration. Rounds are short and the static system prompt caches well — a strong model's judgment goes where it matters most |
| **worker** | **Strong execution + medium reasoning** | A full tool loop every round; thinking lengthens each step's latency and eats into the idle-stop counting window (thinking-only turns neither write back nor get rescued by a nudge — nudges only hang off Stop). If you use a thinking model, run_timeout must have headroom |
| **judge (interception adjudication)** | **Non-thinking / low thinking** | The 180s timeout is a hard constraint: thinking models need a 32768->65536 budget bump and retry; adjudication quality comes from prompt structure (dual-axis criteria + contrastive examples), not model depth |
| **goals (goal decomposition)** | **Cheap model** | A MaxTurns=8 structured extraction task (set_goals/set_constraints); flagship models bring no benefit |
| **compactor (context compression)** | **Cheap, non-thinking** | A pure summarization task. It previously used the same model as planner, burning 65536 tokens + 20 minutes wall clock — every pain point of tuning compression traces back to this. Independent configuration has been supported since v0.3.95; the default should be downgraded |
| **mainagent (human-in-the-loop)** | **Strong reasoning** | Judgment on par with planner (evidence gathering before steer/kill, intent supplementation); interaction frequency is low, so quality comes first |

## 2. Division of labour between the three-channel pool and role routing

Three-channel round-robin (llm_pool) solves **availability**; role routing solves **quality and cost**. The two are orthogonal:

- Free channels (the `:free` tier / flash tier): suited to worker / goals / compactor — high volume, shallow per step.
- Paid/flagship channels: give them to planner and mainagent first — short rounds, high judgment density, tokens well spent.
- judge is best bound to one stable channel (`llm_judge_profile_id`); the adjudication path should not join pool
  round-robin — a mid-adjudication circuit break falls through to fail_action (default ask) and disturbs the approval experience.

## 3. Thinking budget

`MaxTokens` is the shared budget for thinking + output. Setting it too small on a thinking model makes "the model is
thinking" get misjudged as "empty output" and trigger a budget-bump retry. Before v0.3.95 there was **no** independent
thinking knob — when using a thinking model, give MaxTokens plenty of room (>=32768) and scale the timeout up in step.

## 4. What we deliberately don't do

- **Dynamically raising/lowering the model based on error rate**: complex state, poor explainability; the existing
  "binding + task chain + manual switch + audit events" already covers it.
- **Using thinking for judge**: see above, the timeout risk outweighs the benefit.
