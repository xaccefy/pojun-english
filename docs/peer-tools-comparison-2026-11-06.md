# In-depth Comparison with Peer AI Pentest Tools and Integration List (2026-11-06)

> Trigger: user feedback that "tasks barely call any skill these past two days" + a request to analyse what is
> worth taking from 14 peer projects. This document has two parts: (1) root-cause analysis of the skill call rate
> (with empirical data); (2) item-by-item conclusions for the 14 projects (adopt/skip).

## 1. Why the skill call rate is low (empirical data)

**Data** (Kali artex database, 2026-11-06):
- `skill_usage` over the whole lifetime: **8 calls** (vuln-hunting 6 / api-recon 1 / redteam-ops 1);
- Task 18 (a Vue site, ran for a day): **0 Skill calls**;
- The top-25 tool distribution over the past three days contains **no Skill**: Bash 25.7k, list_facts 4.5k, node_detail 3.5k...
- The default bindings for the 21 skills were only **seeded in v0.4.56 (11-05)** — so for most of tasks 15/16/17/18 they were not in the tool surface at all.

**Three layers of root cause**:
1. **Structural (already fixed)**: missing bindings -> the available skill list was essentially empty;
2. **Behavioural (fixed this time)**: Skill is a **meta-tool** — the model only saw available skills at the tail of the
   tool description, and the system prompt **said not a single word** about them. A DeepSeek-flash-class model will not
   proactively call an optional meta-tool. This is the same root cause as the old "host tools installed but nobody used
   them" problem (recorded in a worker.go comment), whose fix was "put the tool inventory in the system prompt"; skills
   must get the same treatment.
3. **Routing (observable)**: intent text carries no association with skills, and no mechanism hints "this intent should
   consult that skill first".

**Fix (v0.4.60)**: `renderSystem` uniformly injects a "skill quick-reference block" — a
`- skill name: when to use` list plus usage instructions generated from the agent's bindings, covering every
worker/planner/pentest/chat agent; the registry caches for 60s. Regression tests verify bound items appear in the block
and that no bindings means no block.

## 2. Item-by-item conclusions for the 14 projects

| Project | Core mechanism | Conclusion | Disposition |
|---|---|---|---|
| **Shannon** | White-box, reads source first to understand the architecture, "No exploit, no report" | **Already borrowed** (v0.4.7-12 evidence grading/report narrative/mechanical verification) | Maintain; the source-code-hunting skill already covers the white-box flow |
| **PentAGI** | Self-hosted multi-agent, Docker-orchestrated Nmap/MSF/sqlmap | Partial | We already ship the whole tool set (Kali/image); MSF is **not wired** — listed for later (RPC bridge, cost/benefit to be assessed) |
| **Decepticon** | 16 specialist agents dividing the work + **auto-generated RoE** + Kali tmux sandbox | Partial | RoE = our set_constraints (already present); specialist division = intent + skill routing (strengthened by this round's skill block); tmux persistent sessions don't apply (we have hostd/the toolchain) |
| **RedAmon** | Neo4j attack-surface graph (25 node types) + Wave Runner parallelism | Partial | The dual graph (asset graph/exploration graph) already covers the core value; graph-driven "PR fixes" don't apply (we are on the testing side) |
| **Pentest-Swarm-AI** | Recon/classification/**independent verification** split + mixed cloud/local models | **Adopt the verification split** | New planner rule: when a critical/high has no independently reproduced fact, dispatch a verification intent that "only reproduces, never escalates"; mixed models = our existing per-role routing |
| **LuaN1aoAgent** | Traceable reasoning, evidence first | Already covered | Activity stream + provenance dual graph + L-grade evidence gate |
| **HexStrike AI** | **MCP bridge to 150+ tools** | **Adopt (preset)** | New MCP preset "HexStrike tool bridge" (clone hexstrike-ai into mcp-servers/ and start the :5000 service to use it) |
| **CyberStrikeAI** | Go + Web UI + skill system | Already borrowed (v0.4.56 skill system) | Maintain |
| **Pentest Copilot** | Browser-driven Kali + Burp workflows | Partial | The Burp MCP preset (v0.4.56) is already integrated; an in-browser terminal doesn't apply |
| **PentestAgent** | **Preset Playbooks** + multi-agent collaboration | **Adopt (Playbooks)** | Seed 4 task templates: full web flow / internal-network AD pentest / app reverse engineering + API / pure recon inventory |
| **PentestGPT** | Task-decomposition reasoning (USENIX'24) | Already covered | planner/worker split + intent hypothesis/success criteria |
| **Pentest-AI** | **Independent verifier (machine oracle)** + replayable proof capsule | **Adopt the verification rule** | planner independent-reproduction rule (same as Swarm); proof capsule = evidence pack + traffic binding + reproduction commands (already present, reports embed the sqlmap retest command) |
| **AIRecon** | Docker Kali sandbox + Caido proxy | Already covered | MITM recording proxy + hostd toolchain |
| **METATRON** | Local LLM (Ollama) privacy | Already covered | Any OpenAI-compatible endpoint (Ollama works) |

### Implementation list for this batch (v0.4.60)

1. ✅ **Skill quick-reference injected into the system prompt** (root-cause fix, see §1)
2. ✅ **4 built-in task Playbooks** (PentestAgent's idea; target structures validated by the Ankang series)
3. ✅ **Independent reproduction planning rule** (Pentest-AI / Swarm idea)
4. ✅ **HexStrike MCP preset** (150+ tool bridge)
5. ⏭ Follow-up candidates: Metasploit RPC bridge (PentAGI's idea, relatively costly; observe the HexStrike integration first)

### Explicitly not doing

- Neo4j graph database (the dual graph already covers the semantics; a heavy dependency isn't worth it);
- tmux persistent-session sandbox (the platform already has hostd + a toolchain, low benefit);
- Introducing LangGraph/multi-framework orchestration (our planner/worker orchestration is already validated; don't swap the foundation).
