<div align="center">

<img src="screenshots/pojun-logo.png" width="96" alt="Pojun"/>

# Pojun (the Breaker)

**AI autonomous penetration testing platform · from a one-line objective to a deliverable vulnerability report**

> Pojun (the Breaker) is the seventh star of the Big Dipper — the star of conquest and turning tides.<br/>
> Find the breach in the defense, and prove it to you.

[![Release](https://img.shields.io/github/v/release/chu0119/Pojun?label=version&color=red)](https://github.com/chu0119/Pojun/releases)
[![CI](https://github.com/chu0119/Pojun/actions/workflows/ci.yml/badge.svg)](https://github.com/chu0119/Pojun/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-lightgrey)
![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker&logoColor=white)

**Go monolith backend** · **Next.js embedded frontend** · **PostgreSQL** · **multi-agent autonomous progression** · **full evidence trail**

📦 [One-command install](#quick-start) · 🧠 [Single-skill pojun-skill](https://github.com/chu0119/pojun-skill) — the platform's methodology distilled into one skill, drop-in for any AI Agent

</div>

---

## Quick start

> Requires **PostgreSQL** (handled by the install script/Compose); exploration needs an **LLM**
> configured in the UI (Anthropic / OpenAI / any compatible gateway, multi-channel round-robin).
> Detailed install options, OS choices, public deployment and upgrades → [Install guide](#install-guide).

**Linux (Debian / Ubuntu / RHEL / Kali, etc., run as root, fully automated interactive install):**

```bash
curl -fsSL https://github.com/chu0119/Pojun/releases/latest/download/install.sh | sudo bash
```

**macOS 13+ (Apple Silicon / Intel, one command, no sudo):**

```bash
curl -fsSL https://github.com/chu0119/Pojun/releases/latest/download/install.sh | bash
```

Fully automated: Homebrew check (installed if missing) → PostgreSQL 16 install and service registration → download and
verify the darwin package → generate config.json → register a launchd user service (start at boot +
auto-relaunch on crash) → health check. Pentest tools and LibreOffice etc. are installed on demand via
`brew install` (missing tools are shown honestly on the "Host Environment" page). See [Install guide](#install-guide).

**Windows / existing Docker (the toolchain lives entirely in the image, zero host installs):**

```bash
git clone --depth 1 https://github.com/chu0119/Pojun.git pojun && cd pojun
cp .env.example .env    # use `copy` on Windows; change at least POSTGRES_PASSWORD
# Windows (Docker Desktop, WSL2 backend):
docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d
# macOS (Docker Desktop / OrbStack):
docker compose -f docker-compose.yml -f docker-compose.macos.yml up -d
# Linux / others:
docker compose up -d
# → http://localhost:8787
```

**Once installed (3-minute onboarding):**

1. Open `http://<host>:8787` in a browser → initialize the admin password (≥8 chars)
2. Configure a model channel on the "LLM Config" page (≥2 channels + round-robin on = recommended for real work);
   for Anthropic/OpenAI/DeepSeek and other OpenAI-compatible endpoints fill base_url + key + model directly
   (e.g. DeepSeek: `https://api.deepseek.com` + `deepseek-chat`/`deepseek-reasoner`)
3. One-click install all tools on the "Host Environment" page (the Docker image already bundles all 66 — skippable)
4. Create a task, give it a one-line objective

---

## Contents

| | |
|---|---|
| **🚀 Deploy** | [Install guide](#install-guide) · [Config cheatsheet](#config-cheatsheet) |
| **📸 Product** | [UI tour](#ui-tour) · [Core capabilities](#core-capabilities) · [Architecture](#architecture) · [How it differs from peers](#how-it-differs-from-peers) |
| **🧰 Assets & discipline** | [Built-in inventory: skills / MCP / tools](#built-in-inventory-skills--mcp--tools) · [Field discipline & safety boundaries](#field-discipline--safety-boundaries) |
| **👥 Contribute** | [Development & contributing](#development--contributing) · [Doc index](#doc-index) · [Origin statement](#origin-statement) · [License & disclaimer](#license--disclaimer) |

---

## What is this

Pojun is an **LLM multi-agent autonomous pentest platform**: give it a one-line objective and it runs the
full "decompose → recon → vulnerability discovery → exploitation → post-exploitation → reporting" pipeline; you can step in and correct course at any time.

It is not "a scanner wrapped in an API". Pojun's core design is **making AI work like a disciplined pentest engineer**:

- **Goal gate** — every goal must carry verifiable acceptance criteria (e.g. "an unauthorized endpoint returns 200 with
  business data and no credentials", "a cross-tenant request reliably reads another object's full fields");
  a task may only close after every goal is proven met. If not, it is marked "unfinished" — the report says so honestly, it never pretends a run completed.
- **Evidence gate** — critical/high vulnerabilities must ship mechanically reproducible evidence (HTTP status codes,
  command output hits, traffic comparisons); version-match-only "possibly vulnerable" findings never make it into the deliverable report.
- **Autonomous chain-hopping** — a confirmed vulnerability ≠ a finished intent. When a high/critical is only proven to
  "exist", the platform automatically dispatches the next hop in the exploit chain (credentials → lateral movement,
  injection → dump → login, upload → webshell), pushing to the L4 data/financial impact layer.
- **Full trace** — all HTTP/S traffic is recorded request-by-request through the MITM proxy, findings bind traffic
  evidence, every activity step is replayable — "how this conclusion was reached" is always traceable.

Measured single-machine baseline (real authorized-project data, Kali deployment): 12 tasks, 56,000+ tool calls,
**295 confirmed vulnerabilities** (28 critical / 140 high), 2,752 asset nodes — fully unattended.

---

## UI tour

> All screenshots come from a real running instance; target domains, company names, IPs and vulnerability details are redacted.

**Global posture**

| Console login: first launch initializes the admin, anti-bruteforce lockout | Overview: task / finding / asset / token posture and trends |
| :---: | :---: |
| ![login](screenshots/pojun-login.png) | ![overview](screenshots/pojun-dashboard.png) |

**Task execution**

| Task list: goal progress and vulnerability distribution at a glance | Task detail: multi-agent sessions, planner posture analysis in real time |
| :---: | :---: |
| ![task list](screenshots/pojun-tasks.png) | ![task detail](screenshots/pojun-task-detail.png) |

| Task overview: goals listed one by one with acceptance criteria, completion status shown honestly |
| :---: |
| ![task overview](screenshots/pojun-task-overview.png) |

| Goal management and operation constraints: tick goals off one by one; allow/deny constraints directly bound planner dispatching |
| :---: |
| ![goals and constraints](screenshots/pojun-task-goals.png) |

**Findings & evidence**

| Findings: cross-task vulnerability roll-up, stats by severity | Vulnerability detail: summary + retest command + evidence PoC + status card |
| :---: | :---: |
| ![findings](screenshots/pojun-findings.png) | ![vulnerability detail](screenshots/pojun-finding-detail.png) |

| Asset ledger: enterprise → root domain/IP/subdomain/service/endpoint, fully registered | Asset coverage map: force-directed layout, tested nodes highlighted |
| :---: | :---: |
| ![assets](screenshots/pojun-assets.png) | ![asset map](screenshots/pojun-assets-graph.png) |

| Global traffic proxy: every HTTP/S exchange recorded request by request |
| :---: |
| ![traffic](screenshots/pojun-traffic.png) |

**Platform configuration**

| Vulnerability intel ops: 420k CVE / KEV in-the-wild / PoC repos continuously synced | Skill library: 22 built-in methodology skills, loaded on demand |
| :---: | :---: |
| ![vuln intel](screenshots/pojun-vulnintel.png) | ![skills](screenshots/pojun-skills.png) |

| MCP presets: FOFA mapping / Playwright / Burp, one-click attach | Agent roles: per-role model and visibility config |
| :---: | :---: |
| ![MCP](screenshots/pojun-mcp.png) | ![Agents](screenshots/pojun-agents.png) |

| LLM config: multi-channel round-robin / circuit breaking / failover | Host environment: 66-tool health check + one-click install |
| :---: | :---: |
| ![LLM](screenshots/pojun-llm.png) | ![host env](screenshots/pojun-hostenv.png) |

| Listeners / C2: reverse-shell callback reception and egress management | Chat workbench: cross-agent conversations and tool-trigger replays |
| :---: | :---: |
| ![C2](screenshots/pojun-c2.png) | ![chat](screenshots/pojun-chat.png) |

| System settings: goal wrap-up / writeback guards / cross-task dedup toggles | Domain tools: the platform tool list and toggles agents can call |
| :---: | :---: |
| ![settings](screenshots/pojun-settings.png) | ![tools](screenshots/pojun-tools.png) |

---

## Core capabilities

### 1. Multi-agent autonomous progression

```mermaid
sequenceDiagram
  autonumber
  participant EV as graph change (800ms debounce)
  participant P as planner (fresh session each round)
  participant FR as frontier intent queue
  participant W as worker xN
  EV-->>P: wake (edge/heartbeat)
  P->>FR: add_intent dispatches 0..4 intents (with anchored assets)
  W->>FR: CAS-claims intents
  W->>W: real tool execution (everything recorded via MITM)
  W->>EV: writeback fact/asset/finding + per-step activity
  EV-->>P: graph change -> next round (closed loop)
```

- **planner** is the sole intent producer and holds a todolist shared across wakes — serial exploit chains
  (injection point → credentials → lateral movement) are recorded once and dispatched step by step in dependency order, never duplicated or reordered.
- **worker** stops after finishing each intent; results write back to the dual graphs and wake the planner.
- **mainagent** handles conversations, report rewriting, and instant tool-triggered jobs (e.g. retest reminders).
- **Human in the loop**: conversational correction / intent pause-cancel / manual approval / `steer_work` live steering —
  every activity step is visible inline in the UI.
- Multi-layer resilience: idle wrap-up (3 nudge rounds + 5 prevent rounds + cancel reasons persisted) / decomposition wall-clock /
  planning-round timeout / automatic rerun on transient failure — even free rate-limited channels finish tasks reliably.

### 2. Goal management: completion cannot be bypassed

- `set_goals` lets each goal carry `criteria` (verifiable acceptance criteria); the goal-decomposition prompt is forced to
  produce criteria (e.g. "an unauthorized endpoint anonymously returns 200 with business fields", "a cross-tenant check
  reliably reads a foreign object"), and forbids writing "find/verify a vulnerability" process steps as end goals.
- **The `goal_met` gate**: while any goal is not `met`, overall wrap-up is rejected outright (with the unmet goal ids attached).
- **Honest terminal states**: only all goals met → `done`; when goals are unmet, regardless of timeout / auto idle /
  coverage wrap-up, the terminal state is `timeout` (unfinished), and list/detail/report all honestly show `x/y goals`.
- Word/Markdown reports gained a "goal attainment" section listing achieved/unmet goals with their acceptance criteria.

### 3. Execution surface: native executor + session reuse + background jobs

| Capability | Description |
|---|---|
| `http_request` | Native HTTP executor: method/headers/body/redirects/timeout controllable, recorded via MITM automatically |
| `session_login` | Five login shapes (form/JSON/Basic/Bearer/custom); task-level cookie jar interoperates with curl |
| session reuse | `http_request(session=<name>)` automatically carries login state; dual-identity contrast makes IDOR checks free |
| `poc_scaffold` | Generates runnable Python verification skeletons per category (sqli/ssti/lfi/ssrf/idor/jwt/upload/cmdi/race) |
| `job_start/status/output/stop` | Background jobs: long scans/brute-force run in the background, keep going after the run ends, results retrievable anytime |
| `save_script` / `run_script` | Task-level shared script directory: write once, reuse across the whole task |

### 4. Exploit-chain continuation: keep going after confirming a vulnerability

- `report_finding`'s receipt carries `chain_intent_id` — the platform dispatches follow-up intents by vulnerability class:
  - SQL injection → data exfiltration proof → session acquisition → lateral movement in the admin backend
  - File upload → landing verification → webshell capability-boundary check
  - Unauthorized endpoint → cross-tenant comparison → data-plane impact assessment
- Worker discipline (code-injected prompt, unaffected by frontend wordlist edits): a confirmed vulnerability ≠ a finished intent;
  push through the impact ladder L1 info → L2 auth/privilege → L3 control → L4 data/finance;
  ≥2 fundamentally different techniques must fail with logged output before judging "not exploitable".

### 5. Vulnerability dedup & merge: one bug, one truth

- **Multi-key dedup**: every finding carries strong keys (cve / root / endpoint / param) plus
  weak keys (asset_class / name); new reports hit their merge target automatically, `merge_count` counts,
  source findings fold into the `finding_updates` timeline, evidence and asset anchors are unioned.
- **Cross-task dedup**: when the same bug on the same asset was already reported by another task, it does not disturb you again by default (toggleable).

### 6. Writeback guards: the hard line against scope creep

- `record_fact` / `report_finding` anchored on assets outside the task's own scope are rejected outright
  (own / source / foreign classification; source-task scope is read-only shared).
- The planner carries a matching "verify-first" hard tail: cross-domain attribution conclusions must be
  double-checked with cross-domain evidence first; failing the check drops the chain immediately — one false
  correlation must not derail a whole chain.

### 7. Vulnerability intel ops (continuous, not a static knowledge base)

Most peers do "look up by component"; Pojun works "**by time stream**" —
**what broke in the last 7 days → match against my assets → queue it into tasks**:

- NVD full/incremental (measured DB 420k+) + **CISA KEV in-the-wild** + GitHub Advisory
  + GitHub PoC aggregation (measured DB 1,400+)
- **Recent-critical fast lane**: pulls CVSS≥9.0 or KEV every 30 minutes by publish time; entries land in minutes
- **Asset fingerprint → CVE reverse matching**: synced CVEs automatically match asset `technologies` fingerprints,
  attaching hints to tasks on hit
- **Precise version-range checks**: `search_vulns` returns a three-state `version_in_range`;
  when NVD leaves ranges empty, GHSA fills in (conservative: unparseable → "possibly affected")

### 8. Red-team capability

- **Reverse-connection receiver**: catches reverse shells / OOB callbacks, records source, time and captured content per session;
  both REST and agent-tool entry points; start/stop goes through manual approval.
- **Three C2 egress shapes**: direct (reachable from this host) / SSH-relay hosted (no public IP + a public relay host,
  auto-reconnect on drop) / manual (bring your own forwarding). `listener_start` returns the resolved
  callback address, so the agent fills payloads directly without guessing the network shape.
- **Post-exploitation methodology**: the redteam-ops skill's six phases (stabilize foothold → privilege escalation →
  persistence → credential access → lateral movement → data collection & exfil → wrap-up) + evidence discipline.
- **Post-exploitation tools**: impacket / netexec / evil-winrm / chisel / ligolo-ng /
  proxychains / socat / linpeas / pspy / responder / sqlmap / hydra / hashcat /
  nuclei / ffuf ... 66 items, one-click install on the "Host Environment" page (privileged helper pojun-hostd serializes the queue).

### 9. Approval & interception: three gates

| Layer | Semantics | Built-in rules |
|---|---|---|
| Hard `deny` | Irreversible in any context, no legitimate pentest use — rejected without calling a model | 10 |
| Agent `judge` | Target depends on context (dropping a test table vs a production table) — model adjudication on hit | 12 |
| Human `ask` | Platform capability boundary changes (e.g. opening a listener port) — escalates to manual approval | 1 |

- Rule-level timeouts actually work (judge class 90s/allow, hard-deny class 30s/deny);
- Model adjudication uses **strict JSON parsing** (parse failure falls back to the failure policy — never guessed);
- Anti-injection boundary: judge input is deliberately narrowed (tool name + args + cwd only); history never enters the judge's view;
- **Writeback scope guard** (see §6) is a final backstop at the data layer.

### 10. End-to-end evidence chain & delivery

- **MITM recording proxy**: every worker's HTTP/S traffic is recorded request by request (CA issuance logged);
- **Findings bind traffic**: findings bind four kinds of traffic evidence — baseline / proof / verification / supporting —
  versioned snapshots (sha256), verifiable when quoted in reports;
- **Evidence attachments**: screenshots + auto-converted image archives of Word/Excel/PPT/PDF samples, task-isolated and attributable to findings;
- **Report export**: professional-grade Word (cover · TOC · headers/footers · severity coloring · retest log · traffic evidence ·
  remediation roadmap, handwritten OOXML, zero dependencies) + Markdown + a zip of "one docx per vuln" batches;
- **Adversarial self-check**: reproduce with a different identity / different parameter order / different client — "confirmed before reporting".

### 11. Cost & model routing

- **Three-channel LLM round-robin**: circuit breaker + failover + usage attribution — even free rate-limited channels finish tasks
  (measured 2,725M tokens, 93% cache hit); per-role model config: strong reasoning for planner /
  medium for worker / cheap tier for judge.
- **Worker posture slimming**: planner-only fields never enter worker conversations; **untested assets are cluster-sorted**
  and parked statically; **batched http_probe liveness checks** replace per-host curl round-trips.

---

## Architecture

### Dual-graph: asset graph × exploration graph

All pentest state is split into two independent graphs stitched together by anchors:

- **Asset graph** (globally shared): the truth base of six node kinds — `root_domain / subdomain / ip / service / app / endpoint` —
  reused across tasks; corporate attribution + authorization boundaries (task_scope) hang here.
- **Exploration graph** (one per task): the `goal → intent → fact / finding` progression chain, five edge kinds
  (spawns / derived_from / yields / proves / covers) form the **lineage** — "which clue produced this
  finding" is always traceable, the foundation of **report credibility**.

```mermaid
flowchart LR
  subgraph EG["Exploration graph (per task · progression chain)"]
    direction TB
    G["goal"] -->|spawns| I1["intent A"]
    I1 -->|yields| F["fact"]
    F -->|derived_from| I2["intent B"]
    I2 -->|yields| FD["finding vulnerability"]
  end
  subgraph AG["Asset graph (global · truth base)"]
    direction TB
    RD["root_domain"] --> SD["subdomain"] --> SV["service"] --> EP["endpoint"]
  end
  I1 -.->|anchor| SD
  FD -.->|anchor| EP
```

### Full task lifecycle

```mermaid
flowchart TB
  T["new task (one-line objective + scope)"] --> GD["goal decomposition: LLM produces goals + criteria"]
  GD --> LOOP{engine loop}
  LOOP -->|"planner dispatches intents"| FR["frontier intent queue"]
  FR -->|"CAS claim"| W["worker xN executes"]
  W -->|"fact / asset / finding"| LOOP
  W -->|"high/critical confirmed"| CH["chain-hopping: auto-dispatch follow-up intents"]
  CH --> LOOP
  W -->|"same-class vuln hit"| DD["multi-key dedup: merged into existing finding"]
  DD --> LOOP
  LOOP -->|"all goals met"| DONE["done (deliverable)"]
  LOOP -->|"goals unmet + wrap-up triggered"| TO["timeout (unfinished, shown honestly)"]
  DONE --> REP["Word / Markdown report + goal attainment + retest entry"]
```

---

## Install guide

> The [Quick start](#quick-start) above is enough to get going; this section is the full reference for OS choices,
> the four install methods, public deployment and upgrades. Requires **PostgreSQL**; exploration needs an **LLM**
> (configured in the UI: Anthropic / OpenAI / any OpenAI-compatible gateway, multi-channel round-robin + failover).

### OS choice & requirements

| OS | Verdict |
|---|---|
| **Debian 12 (bookworm)** | ✅ **Preferred**: stable, systemd, PostgreSQL 15 in-repo, LibreOffice/poppler/uv all available |
| **Ubuntu 22.04 / 24.04 LTS** | ✅ **Preferred**: same family as Debian, long-term support |
| **Windows 10/11 (Docker Desktop)** | ✅ **Supported**: runs Linux containers on the WSL2 backend, toolchain lives in the image — see the Windows notes in [method 2](#method-2-docker-compose-against-the-published-ghcr-image) |
| **macOS 13+ (Apple Silicon / Intel)** | ✅ **Supported**: one-command install (install.sh uses brew + launchd automatically, no sudo) — see [Quick start](#quick-start); missing toolchain items are shown honestly on the "Host Environment" page |
| Kali | ⚠️ Usable (full toolset out of the box), but rolling updates carry upgrade risk — not recommended for production |
| RHEL / Rocky / CentOS Stream | ⚠️ Supported (dnf path), but coverage of newer tools like ffuf/sqlmap is thin — install on demand |
| Windows native (bare exe) | ❌ Not supported: the privileged helper/toolchain/watchdog scripts are all Linux-based — use Docker Desktop or WSL2 |

**Hardware**: minimum 2 cores / 4G RAM / 20G disk (without tools); **recommended 4 cores / 8G / 60G** (includes SecLists
~2.5G, nuclei templates, Playwright chromium, LibreOffice).
**Network**: install needs GitHub and the LLM gateway reachable; on restricted networks use `--install-proxy`.
**Python**: the bundled FOFA MCP needs Python ≥ 3.10 (does not affect the main service); `uv` is prepared by the install script.

### Method 1: one command, fully automated interactive install (recommended · Linux only)

Run as root on a **fresh Linux server** (Debian/Ubuntu/CentOS/RHEL/Kali, etc.):

```bash
curl -fsSL https://github.com/chu0119/Pojun/releases/latest/download/install.sh | sudo bash
```

The script asks interactively (press enter for defaults):

1. **Deployment mode**: binary (recommended, systemd + system PostgreSQL) or Docker;
2. **Outbound proxy** (optional): enter `http://host:port` if apt/GitHub access is restricted;
3. Then it automatically: installs dependencies (PostgreSQL / LibreOffice / poppler / ImageMagick / fonts, etc.)
   → creates the runtime user and directories → initializes the database → installs the systemd service
   → first start → prints the access URL and initial account.

Common non-interactive invocations:

```bash
# all defaults (binary, direct connection)
curl -fsSL https://github.com/chu0119/Pojun/releases/latest/download/install.sh | sudo bash -s -- -y
# with a proxy + common pentest tools
curl -fsSL .../install.sh | sudo bash -s -- --install-proxy=http://10.0.0.14:7897 --with-tools
# Docker mode
curl -fsSL .../install.sh | sudo bash -s -- --mode=docker
```

Idempotent: re-running = in-place upgrade; `config.json` / `jwt.key` / data / database are untouched.
Uninstall: `systemctl disable --now pojun pojun-hostd && rm -rf /opt/pojun`.

### Method 2: Docker Compose against the published ghcr image

If you already know Docker, you don't need install.sh:

```bash
git clone --depth 1 https://github.com/chu0119/Pojun.git pojun && cd pojun
cp .env.example .env      # change at least POSTGRES_PASSWORD; POJUN_TAG can pin a version (e.g. v0.4.64)
docker compose up -d      # → http://localhost:8787
```

**Windows (Docker Desktop, WSL2 backend)**:

```powershell
git clone --depth 1 https://github.com/chu0119/Pojun.git pojun; cd pojun
copy .env.example .env    # change at least POSTGRES_PASSWORD
docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d
# → http://localhost:8787
```

- Why Windows needs `-f docker-compose.windows.yml`: the data volume becomes a named volume
  (small-file I/O over an NTFS bind mount measures ~2 orders of magnitude slower; traffic/evidence writes
  become noticeably sluggish), and it pre-maps callback ports 4444-4450;
- **Reverse-connection receiver**: in `direct` mode inside the container the resolved LHOST is a container-subnet
  IP that external targets cannot reach — set the egress shape to **manual** on the "Listeners / C2" page,
  fill in the Windows host's LAN IP (check `ipconfig`), keep listen port and mapped port 1:1, and allow the
  ports through the Windows firewall;
- Data backup: `docker run --rm -v <project>_pojun-data:/data -v "%cd%:/backup" alpine tar czf /backup/pojun-data.tgz -C /data .`;
- Everything else matches Linux: the image bundles all pentest tools / LibreOffice / Playwright — nothing to
  install on the Windows host. Give Docker Desktop ≥8G of memory.

- Image `ghcr.io/chu0119/pojun`, dual-arch amd64/arm64, `POJUN_TAG` defaults to `latest`;
  the same pentest toolset as binary `--with-tools` ships inside the image: nmap / masscan /
  sqlmap / hydra / whatweb / nikto / ffuf / john / impacket / socat /
  proxychains / nuclei / httpx / subfinder / naabu / dnsx / katana / tlsx /
  notify / interactsh / gitleaks / chisel / amass / dalfox / feroxbuster /
  gobuster / wafw00f / semgrep / pwntools / SecLists wordlists /
  Playwright + chromium / LibreOffice / poppler / ImageMagick / official-document fonts;
- data lands in `./data` (inspect/backup directly on the host), the database lives in the `pgdata` volume;
- upgrade: `docker compose pull && docker compose up -d`; uninstall: `docker compose down -v`;
- callback port mapping examples live in the `docker-compose.yml` comments (open the ports a reverse shell needs).

### Method 3: download a prebuilt package (Linux / macOS, amd64 and arm64)

Download the matching `pojun-<version>-<os>-<arch>.zip` from
[Releases](https://github.com/chu0119/Pojun/releases) (SHA256SUMS included), then:

```bash
cp config.example.json config.json   # fill in the database connection
./start.sh                           # → http://localhost:8787
```

> Start via `start.sh` rather than running the binary directly — it is the watchdog script and "one-click update"
> relies on it to perform the binary swap (in-page one-click update works on macOS too; the release package is
> picked per platform automatically).

**macOS notes:**

macOS can also use the one-command install.sh (see [Quick start](#quick-start)) — the script goes through
Homebrew + launchd automatically, same experience as Linux; the manual route below suits users who don't
want Homebrew or want finer control over dependencies.

- Install dependencies yourself: `brew install postgresql@16 libheif poppler libreoffice` and start PostgreSQL;
  Node ≥ 20 (Playwright MCP) and `uv` (FOFA MCP) on demand;
- the pentest toolchain (nmap/sqlmap/nuclei etc.) via `brew install` on demand — missing tools are shown
  honestly on the "Host Environment" page, and agents route around missing tools to what's available;
- the privileged helper `pojun-hostd` and bulk tool install are Linux-only — unavailable on macOS (impact:
  the "install everything" button is unavailable; everything else is complete);
- `masscan`/`nmap -sS` and other privileged scans need root/sudo, same as Linux.

### Method 4: build from source

```bash
cd web && npm ci && npm run build:static && cd ..
cp -r web/out server/webui/dist
CGO_ENABLED=0 go build -tags embedui -o pojun ./cmd/pojun
CGO_ENABLED=0 go build -o pojun-hostd ./cmd/pojun-hostd   # optional: privileged install helper (Linux)
./start.sh
# cross-compile example (macOS Apple Silicon):
# CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -tags embedui -o pojun-darwin-arm64 ./cmd/pojun
```

### Public deployment

A built-in public-deployment security baseline ships (login anti-bruteforce, probe-response fingerprint
stripping, session revocation on password change, no product name on the auth surface).
Required: HTTPS reverse proxy + `X-Forwarded-For` pass-through. Full baseline in
[docs/public-deployment-security-hardening-2026-10-29.md](docs/public-deployment-security-hardening-2026-10-29.md).

### Upgrades

**In-page one-click update** (System config → Version & update): download → SHA256 verify → smoke test →
atomic binary swap → auto-rollback to the previous version on failure. Upgrades only swap the program —
data is untouched, schema migrations are idempotent.

---

## Config cheatsheet

**Database** (`config.json` or `POJUN_PG_DSN`):

```json
{ "database": { "host": "127.0.0.1", "port": 5432, "user": "pojun",
                "password": "…", "dbname": "pojun", "sslmode": "disable" } }
```

**LLM**: env vars `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` work as fallbacks; the UI "LLM Config" page
configures multiple channels + "LLM round-robin". Common args: `./start.sh -addr :8787 -proxy :8788`.

**C2 egress** (optional): `PUT /api/c2/config` with `mode=direct|ssh|manual` +
relay host/SSH credentials — `listener_start` returns the resolved callback address automatically.

**Reverse proxy (HTTPS)**: frontend and API/SSE share an origin; buffering must be off. Nginx example:

```nginx
server {
    listen 443 ssl;
    server_name your.domain.com;
    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # rate limiting relies on it
        proxy_buffering off; proxy_read_timeout 3600s;               # required for SSE
        proxy_http_version 1.1; proxy_set_header Connection "";
    }
}
```

---

## Built-in inventory: skills / MCP / tools

**22 built-in skills** (auto-routed by intent scenario, bound to the matching role by default):

| Domain | Skills |
|---|---|
| General methodology | vuln-hunting (unknown-surface discovery) / attack-surface-recon / pentest-output-standards (report spec) |
| Web & API | web-attack-methods / api-security-testing / api-recon |
| Specialized | cloud-security / windows-ad / source-code-audit / llm-security / mobile-reverse / apk-reverse / contract-audit / wireless |
| Red-team post-exploitation | redteam-ops (six-phase methodology) / opsec |
| SRC knowledge base | src-hunting (48 test-knowledge pieces + 11 process rules, loaded on demand) |

**10 MCP presets** (one-click config fill): FOFA asset mapping (incl. the one-fox channel) / Playwright
browser / Chrome DevTools / Burp Suite / Fetch web scraping / Sequential Thinking /
Memory knowledge base / Filesystem / HexStrike tool bridge (150+ security tools bridged) / Context7 docs retrieval.

**66 host tools** (health check + one-click install): network & host (nmap/masscan/naabu/tlsx…),
subdomain & DNS (subfinder/dig/amass…), Web & API (httpx/katana/ffuf/dalfox…),
injection & exploitation (sqlmap/hydra/hashcat/john…), post-exploitation (impacket/netexec/evil-winrm/
chisel/ligolo-ng/socat/proxychains/linpeas/pspy/responder…),
corpus (SecLists wordlists / nuclei templates).

---

## How it differs from peers

| Dimension | Typical peers | Pojun |
|---|---|---|
| Completion check | LLM self-declares "task complete" | Goals + acceptance criteria + the `goal_met` gate; unmet goals force an unfinished record |
| Vulnerability trust | Scanner output goes straight into the DB | Mechanical-verification evidence gate + L1-L4 evidence tiers + adversarial self-check; critical/high require L3+ |
| Vulnerability dedup | naive title/URL dedup | multi-key dedup (cve/root/endpoint/param strong keys) + merge timeline + cross-task dedup |
| Exploitation depth | ends at vulnerability confirmation | automatic exploit-chain hops (dimension → next hop), L1→L4 impact-ladder discipline |
| Long tasks | dropped at single-run timeout | background jobs + task-level shared scripts + session reuse — jobs keep running after a run ends |
| Traffic evidence | none or screenshots | MITM per-request retention + four-kind evidence binding + sha256 versioning + report quoting |
| Intel | static knowledge base | NVD/KEV/GHSA/PoC time stream + asset-fingerprint reverse matching + critical fast lane |
| Deliverable | Markdown | official-grade Word (cover/TOC/retest/traffic evidence/remediation roadmap) + one docx per vuln |
| Cost | single channel | multi-channel round-robin + breaker + per-role routing + cache hits (measured 93%) |

---

## Field discipline & safety boundaries

- **Authorization first**: task creation declares the scope (domains/IPs/legal entity); the asset graph registers
  by scope, and the writeback guard intercepts overreach at the data layer.
- **Minimal-harm verification**: SQL injection probing defaults to level 2 / risk 1 (read-only); file uploads verify
  capability without planting a backdoor; login surfaces stop after ≤5 default-credential failures; no big-wordlist
  brute-forcing of production systems.
- **Approval gates**: destructive commands pass three gate layers (deny/judge/ask); platform-capability changes escalate to humans.
- **Retests stay manual**: the platform never triggers retest actions automatically.
- **Credential hygiene**: LLM keys / FOFA keys live only in runtime config — never in the repo or in reports.

## Development & contributing

```bash
./dev.sh    # backend(:8787) + traffic proxy(:8788) + frontend next dev(:5173)
go test ./...   # full suite against a real PG (CI uses -p 1 serial to avoid cross-package deadlocks)
cd web && npx tsc --noEmit && NEXT_EXPORT=1 npx next build
```

- Backend: `go run ./cmd/pojun` (`-tags embedui` embeds the frontend)
- Frontend: `cd web && npm run dev` (`/api` proxied for hot reload)
- Mock preview: `cd web && NEXT_PUBLIC_MOCK=1 npm run dev`

Project layout:

```
cmd/            program entry points (pojun main service / pojun-hostd privileged helper)
agent/          multi-agent layer: planner / worker / mainagent / domain tools (tools_*.go)
db/             PostgreSQL sole store: schema.sql (idempotent migrations) + all table Stores
server/         HTTP surface: routes / engine scheduling / Manager / sessions / reports / updates
intercept/      interception engine: rule match → LLM judge → allow/ask/deny
guard/          tool-call approval gate (wires adjudication into the agent execution chain)
listener/       reverse-connection receiver: catches reverse shells / OOB callbacks with evidence
traffic/        MITM traffic-recording proxy + egress proxy pool
vulnintel/      vulnerability intel: NVD/KEV/GHSA/PoC/fast lane/asset linkage/rate gates
hosttools/      host tool catalog (66 items, grouped by attack surface)
hostd/          privileged helper: root-resident unix socket, tool installs/privileged ops
llmpool/        LLM multi-channel round-robin pool: breaker/failover
llmrec/         LLM request recording & token metering
report/         report generation: Word export (handwritten OOXML, zero deps)
notify/         notification push: DingTalk/Feishu/WeCom etc.
evidence/       finding evidence retention and versioning
enrich/         asset auto-enrichment: DNS / HTTP probing
selfupdate/     one-click self-update: check Release → verify → swap
skills/         builtin skills: vuln-hunting / redteam-ops / api-recon / …
web/            Next.js frontend (static-exported, embedded via go:embed)
docs/           design docs / deployment manual / capability comparisons
```

Issues and PRs welcome: file bugs and docs fixes directly; for new features please open an issue first
to discuss scenarios and boundaries.

## Doc index

| Doc | Contents |
|---|---|
| [docs/ai-handover-guide.md](docs/ai-handover-guide.md) | mechanism→code-location map, release process, test discipline, known issues and open directions |
| [docs/01-dual-graph-architecture.md](docs/01-dual-graph-architecture.md) | asset/exploration graphs, anchors, schema migration design, invariant list |
| [docs/02-engine-and-scheduling-loop.md](docs/02-engine-and-scheduling-loop.md) | planner/worker orchestration and lifecycle |
| [docs/03-llm-access-layer.md](docs/03-llm-access-layer.md) | channel routing, round-robin pool, breakers, recording & metering |
| [docs/04-approval-and-interception.md](docs/04-approval-and-interception.md) | three-layer rules and adjudication chain, anti-injection boundary |
| [docs/deployment-manual.md](docs/deployment-manual.md) | deploy / upgrade / troubleshooting (full field-lessons record) |
| [docs/public-deployment-security-hardening-2026-10-29.md](docs/public-deployment-security-hardening-2026-10-29.md) | public-deployment security baseline |
| [docs/red-team-capability-building-2026-10-30.md](docs/red-team-capability-building-2026-10-30.md) | kill-chain capability matrix / competitor comparison / roadmap |
| [docs/vuln-hunting-capability-comparison.md](docs/vuln-hunting-capability-comparison.md) | feature-by-feature comparison with open-source peers |
| [docs/deep-optimization-plan-2026-10-31.md](docs/deep-optimization-plan-2026-10-31.md) | report polish × agent cognition × exploit chain |
| [docs/model-routing-strategy.md](docs/model-routing-strategy.md) | per-role model routing: strong planner / mid worker / cheap judge |
| [docs/peer-comparison-analysis-2026-11.md](docs/peer-comparison-analysis-2026-11.md) | code-level research of 12+ peer projects, with the adopted-borrowings list |
| [CHANGELOG.md](CHANGELOG.md) | per-version feature changelog |

## Origin statement

This project originally forked the final release v0.3.15 of the now-deleted original project
[Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX) (champion of Baidu's "Agent+" offense/defense
challenge); the original code remains in git history as the starting point.

- **Kept**: dual-graph architecture, planner/worker orchestration, MITM traffic proxy, approval-gate framework, base
  toolset — the original architectural design is excellent, and git history honors it;
- **Rebuilt**: all design docs, CI gates, dependency decoupling (norma SDK fork), Docker sources;
- **Independent evolution**: since v0.3.16, 700+ commits and ~50k new lines by this repo's maintainer,
  spanning intel ops / goal gates / exploit chains / execution surface / dedup-merge / evidence chain / skill system —
  no code-level ties to the original project remain.

## License & disclaimer

### License

**AGPL-3.0** — derivative works (including network services) must be open-sourced likewise. Full terms in [LICENSE](LICENSE).

### Usage restrictions

**This tool is for personal study, code research and local technical verification only; it must not be used to run
real tests against any online system or website.** Permitted: reading and studying the source, verification in
isolated local environments. Forbidden: scanning/probing/exploiting any online system (authorized or not), real
offensive engagements, production use, illegal intrusion and data theft.

Users must comply with all applicable laws and regulations in their jurisdiction (including the Cybersecurity Law,
Data Security Law, Personal Information Protection Law, etc.). **All legal liability arising from use of this tool
rests solely with the user.**

This project is provided "as is" without warranty of any kind. Downloading, installing or using it means you have
read and agreed to all of the above terms.

---

## References

- [norma](https://github.com/Autumn-27/norma) — agent harness SDK (the multi-agent engine behind this platform)
- [SecLists](https://github.com/danielmiessler/SecLists) / [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — corpus & templates
- [FOFA](https://fofa.info) — asset mapping (built-in MCP preset)

<div align="center">

**Pojun (the Breaker)** — find the breach in the defense, and prove it to you.

</div>
