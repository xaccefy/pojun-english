# Red Team Capability Build-out: Kill-Chain Audit, Peer Comparison and Roadmap

> 2026-10-30. Background: upgrading ARTEX from a "vulnerability discovery agent" into a **complete red team
> operations platform** — focused on the four directions of attack progression, privilege retention, post-exploitation
> and data collection. This document is the audit conclusion + peer comparison + roadmap for this special effort,
> replacing verbal planning.

## 1. Kill-chain capability matrix (current-state audit)

Inventoried stage by stage along the classic kill chain (tool = hosttools host tool, agent = platform domain tool,
skill = methodology pack):

| Kill-chain stage | Existing capability | Gap (this round's additions marked ✅new) |
|---|---|---|
| Recon | nmap/masscan/httpx/subfinder/dnsx/katana/whatweb + api-recon skill + asset graph | Sufficient |
| Weaponization | search_vulns/get_poc (NVD+KEV+GHSA+PoC) / scan_with_nuclei + nuclei template library | Sufficient (the intel layer is a unique advantage) |
| Initial Access | sqlmap/dalfox/hydra/weak passwords + vuln-hunting's seven dimensions + vulnerability verification loop | Sufficient |
| **Execution and foothold** | Bash/nc/ssh + **reverse-connection listener listener_start/sessions ✅new** (catches reverse shells/OOB and preserves evidence) | ✅ Closed (the old stub is deleted) |
| **Privilege Escalation** | linpeas ✅new / pspy ✅new / search_vulns kernel CVEs | ✅ Essentially closed (GTFOBins database referenced in the skill) |
| **Persistence** | Methodology guidance (redteam-ops ✅new: ssh key/cron/systemd/webshell/credential types) | ✅ Methodology closed; execution relies on Bash (the correct boundary — persistence actions should be ordinary commands anyway) |
| **Credential Access** | impacket(secretsdump)/john/hashcat/gitleaks + auth_request (credential reuse) + asset auth field | responder ✅new; in-memory credential extraction relies on Bash + tools |
| **Lateral Movement** | netexec/evil-winrm ✅new/impacket/ssh + chisel/ligolo-ng ✅new/sshuttle ✅new/proxychains4 ✅new + net_context (callback address) | ✅ Core pieces closed |
| **Collection** | find/tar-style Bash commands + workspace | Methodology guidance added to the skill ✅ |
| **Exfiltration** | MITM proxy full trail + notify (OOB) + listener ✅ + C2 egress config ✅new (direct/ssh relay/manual) | ✅ Closed |
| C2/session management | listener session records ✅ | **Interactive C2 deliberately not built** (see below) |

Conclusion: after this round's additions, **every kill-chain stage has platform-level support**. What remains is
short on "depth", not "presence" — solved by skill methodology and field iteration.

## 2. C2 egress architecture (new this round, optional feature)

The first practical question for a red team callback: **what should the target connect to**. Three network shapes:

| Shape | Config | Behaviour |
|---|---|---|
| This host has a public IP / is on the same internal network as the target | `mode=direct` (default, zero config) | LHOST automatically takes the local NIC address (default-route source address, or a specified NIC) |
| No public IP here + a public relay host (hosted tunnel) | `mode=ssh` + `c2_relay_ssh=user@host:22` (+ password or private key path) | The platform automatically builds an SSH reverse tunnel (`ssh -R relay-same-port -> local listening port`), reconnects with exponential backoff on disconnect, and tears it down when the listener stops; LHOST = the relay's public address |
| No public IP here + forwarding already configured by hand | `mode=manual` + `c2_relay_host=<relay public address>` | The platform only displays the relay address in the callback info |

- Configuration entry point: settings API `GET/PUT /api/c2/config` (passwords masked on read-back).
- **Transparent to the agent**: `listener_start` returns `connect_back={lhost,lport,via}` — the callback address in the
  payload **is authoritative**; the agent need not judge the network shape itself.
- 1:1 port mapping (relay port = local listening port): the rule is simple and manual troubleshooting needs no lookup table.
- Entirely optional: unconfigured = direct, behaviour identical to older versions.

**Security boundaries**: listening ports restricted to 1024-65535 (binding a low port needs privileges — use hostd or
external forwarding); start/stop goes through the interception rule ask (manual confirmation); session capture capped
at 64KB per session (flood protection); no interactive shell (use Bash nc/socat — **we do not build our own C2
framework**; Sliver/Mythic are integration targets).

## 3. Peer comparison and borrowing

Researched: NodeZero (commercial benchmark), PentAGI, CAI, HexStrike, hackingbuddygpt,
Sliver/Mythic/Havoc (C2 framework reference points).

| Peer | Core shape | Lesson for ARTEX | Adoption |
|---|---|---|---|
| **NodeZero** (Horizon3) | Autonomous pentest as a service; focused on internal lateral movement and **proof-style attack chains** (exploit -> privesc -> lateral -> prove impact) | Our dual graph + lineage naturally supports "attack-chain proof" — after each post-exploitation step records a fact, the report automatically threads into a complete chain. This is an architectural advantage; keep feeding it live-fire scenarios | Red team range live-fire validation (§5) |
| **PentAGI** | Multi-agent sandboxed fully automated pentest | Architecturally isomorphic (planner/worker + graph); ARTEX differs in intel operations and the evidence chain — keep the differentiation | — |
| **CAI** | 300+ pluggable models, CTF benchmark | Model pluggability is already met (three-channel round-robin measured); CTF scenarios can be a skill extension direction | — |
| **HexStrike** | MCP tool layer (150+ tools) | The same idea as our hostd + tool catalog; an **MCP egress** (PM list M25) is worth doing — external agents could drive ARTEX | On the roadmap |
| **Sliver/Mythic** | Multi-protocol C2, persistence modules, multi-operator session collaboration | **Do not build our own C2**: red-flag-grade frameworks are their territory, and building one only creates a security hazard. The platform does "catch + preserve evidence" (listener); deep interaction goes through integration | listener boundaries defined (§2) |
| **hackingbuddygpt** | Minimalist research agent | — | — |

## 4. What landed this round (v0.3.87)

1. **Reverse-connection listener properly implemented**: the `listener/` package (TCP accept loop, bounded capture per
   connection, graceful stop), REST `GET/POST /api/listeners` + `GET/.../{name}` + `.../stop`,
   agent tools `listener_start/stop/sessions`, ask rule restored (matching the real tools),
   interception whitelist restored. Real-machine tests: callback banner capture, duplicate-name rejection, port closed after stop.
2. **C2 egress configuration** (§2): the direct/ssh/manual three shapes + SSH reverse-tunnel hosting
   (reconnect on disconnect) + callback address resolution injected into the agent tools.
3. **hosttools red-team additions**: socat/proxychains4/sshuttle/tcpdump (apt),
   evil-winrm/responder (Kali apt), ligolo-ng (nicocha30, asset names measured) /
   pspy/linpeas (peass-ng, asset names measured) — 9 core post-exploitation pieces.
4. **redteam-ops skill**: a six-stage post-exploitation methodology (foothold stabilization -> privesc -> persistence ->
   credentials -> lateral movement -> collection -> wrap-up) + evidence discipline, wired point by point to the platform tools.
5. **Decomposition wall-clock fix** (goalsDecomposeTimeout, a bug found by real Kali measurement, see CHANGELOG).

## 5. Follow-up roadmap (ordered by red team value)

1. **Automatic attack-chain threading** (benchmarked against NodeZero): the planner todolist already supports serial
   chains — add a "post-exploitation chain" intent template (get a shell -> privesc enumeration -> credentials -> lateral),
   letting serial chains unfold semi-automatically.
2. **Windows post-exploitation pack**: impacket-suite usage into the skill (secretsdump/ntlmrelay),
   SharpHound-class collector integration (AD graph into the asset graph).
3. **C2 integration** (not self-built): a sliver client install recipe + agent tool bridge (`sliver <cmd>` through Bash,
   session state into the exploration graph).
4. **MCP egress** (M25): expose the hostd tool catalog as an MCP server — external AI agents drive ARTEX directly.
5. **Report templates**: a red team report template (attack-chain narrative + persistence-item cleanup checklist + data
   collection inventory), wired into the docx export.
