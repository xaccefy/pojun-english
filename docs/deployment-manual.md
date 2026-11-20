# Deployment Manual (Common for Linux Test / Production Machines)

This document records **tested and working** deployment procedures and the pitfalls encountered. Paths are written for the test machine `/opt/pojun`;
the production machine has the same structure, just change the paths.

## 0a. Intranet Machine Installation: LAN Local Source Recipe (Kali, tested 2026-10, two full runs)

Directly downloading large files from GitHub will inevitably hang on intranet test machines (Kali VM, etc.). Recipe: **use Windows as the source, Kali pulls locally**.

```bash
# ── Windows side (Git Bash) ──
mkdir -p /c/Users/<you>/AppData/Local/Temp/r419 && cd /c/Users/<you>/AppData/Local/Temp/r419
gh release download v0.4.19 --repo chu0119/Pojun --pattern "pojun-0.4.19-linux-amd64.zip" --pattern "install.sh" --pattern "SHA256SUMS" --clobber
# Compare SHA256 locally (only continue if it matches the linux-amd64 line in SHA256SUMS)
sha256sum pojun-0.4.19-linux-amd64.zip

# Patch install.sh for a local source (⚠️ $REPO is a variable; after sed/replace you must confirm the number of replacements)
python - <<'PY'
import io
s = io.open("install.sh", encoding="utf-8").read()
old = 'https://github.com/$REPO/releases/download'
assert old in s, "anchor missing"
s = s.replace(old, 'http://<windows-lan-ip>:8124/v0.4.19')   # remember to append the version path
io.open("install.sh", "w", encoding="utf-8").write(s)
PY

# ⚠️ Double-layer directory pitfall: the original URL is .../download/$VERSION/$zip; after the patch replaces the first half, $VERSION
# will expand one more level → actual request <root>/v0.4.19/v0.4.19/<zip>. The local source must create a double layer of same-named directories:
mkdir -p v0.4.19/v0.4.19 && cp pojun-0.4.19-linux-amd64.zip SHA256SUMS v0.4.19/v0.4.19/

# Start the source (if the port is occupied by a leftover old session: netstat -ano | grep 8124, kill all by PID, then restart)
python -m http.server 8124 --bind 0.0.0.0 &
# Self-check (all three must return 200): zip / install.sh / v0.4.19/v0.4.19/zip

# ── Kali side ──
curl -sS -O http://<windows-lan-ip>:8124/install.sh && chmod +x install.sh
sudo ./install.sh --mode=binary
# For the Windows-side LAN IP see `ipconfig` (VMware NAT subnet is usually x.x.x.1)
```

Pitfall list: ① the install.sh replacement anchor must be asserted present (there have been silent no-op cases historically); ② double-layer $VERSION directory;
③ leftover 8124 processes across sessions; ④ Windows-side curl self-check 200 ≠ reachable from Kali — also curl once on the Kali machine;
⑤ after install, double-check with `curl 127.0.0.1:8787/api/health` + `/api/version`.

## 0. Prerequisites

- Binaries come from GitHub Release (CI-built, 7 assets):
  `pojun-<version>-linux-amd64.zip` + `SHA256SUMS`.
- **SHA256 verification is mandatory**; the corresponding line in the official `SHA256SUMS` must be OK before deploying.
- Download via the GitHub API asset URL (`Accept: application/octet-stream`),
  or follow the 302 on `browser_download_url`. **Asset names do not have a `v` prefix**:
  the tag is `v0.4.19`, the asset is `pojun-0.4.19-linux-amd64.zip`.

```bash
sha256sum pojun-0.4.19-linux-amd64.zip
grep 'linux-amd64' SHA256SUMS | sed 's/  */  /' | sha256sum -c -
# → pojun-0.4.19-linux-amd64.zip: OK
```

## 0b. Upgrading from Old-Name Versions (ARTEX ≤ v0.4.18) to Pojun

Starting with v0.4.19, release assets were renamed to `pojun-<version>-<os>-<arch>.zip` (older versions used `artex-...`).
**The built-in updater in old versions looks for the old asset name and cannot one-click update to v0.4.19+**; you must first
reinstall once with the new installer (idempotent: keeps `config.json` / `jwt.key` / `data/` / database, only replaces the program):

```bash
curl -fsSL https://raw.githubusercontent.com/chu0119/Pojun/main/install.sh -o install.sh
sudo bash install.sh --mode=binary --version=v0.4.19
```

After install, confirm only the new service is running (on old machines, stop `artex.service` if still present, to avoid two instances competing for the same database):

```bash
systemctl disable --now artex 2>/dev/null || true
systemctl status pojun --no-pager
```

After upgrading to v0.4.19, later versions can continue to use the page's "one-click update". If the download fails: first confirm
the proxy pointed to by `settings.install_proxy` is available (only affects downloads; the GitHub API check can be direct);
if unavailable, clear it or replace it with a working proxy and retry.

## 0c. Windows Deployment (Docker Desktop, Tested on a Real Machine 2026-11-12)

On Windows **no native exe is provided** (the privileged helper hostd / apt toolchain / start.sh daemon are all Linux
based), the recommended path is Docker Desktop (WSL2 backend) running Linux containers; installing Debian 12 inside WSL2
and then running install.sh is an alternative (equivalent to the Linux server experience, requires enabling systemd in WSL2).

### Items Verified in Testing (v0.4.64, Docker Desktop 29.x / WSL2)

- `docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d`:
  both containers healthy, `/api/health` 200, version line `POJUN 0.4.64`;
- Toolchain inside the container: nmap 7.93 / sqlmap 1.7 / nuclei 3.11 / ffuf / SecLists;
- Report pipeline: docx → LibreOffice → PDF → pdftoppm → PNG all working;
- FOFA MCP: uv auto-creates a venv and installs dependencies on first run, then the stdio handshake succeeds;
- auth/init initializes the administrator → login 200.

### Why the Windows Override Is Mandatory (Measured I/O Data)

The main compose's `./data:/app/data` bind mount on Windows goes through the NTFS ↔ WSL2 I/O channel;
benchmark of 500 4KB small files: **writes ~108x slower, reads ~328x slower**. Pojun's traffic records (written to disk
per request), evidence attachments, and task workspaces are all small-file intensive, so you must use the override to switch to a named volume
(which lands on WSL2 ext4, with performance equal to the container layer; measured write 0.01s vs NTFS 1.05s).

### Windows Configuration for the Reverse-Connection Receiver (reverse shell / OOB)

- In direct mode inside the container, resolving LHOST via a UDP dial to the default route yields the **container subnet IP**
  (172.x), which external targets cannot reach — this is the nature of container networking, not a bug;
- Correct configuration: on the "Listener / C2" page set the exit form to **manual** and fill in the Windows host's LAN
  IP (`ipconfig`); the override pre-maps 4444-4450, listener ports correspond 1:1 (listen 4444 →
  host 4444); add/remove more ports in the override's `ports:`; allow the corresponding ports through the Windows firewall;
- When other machines on the LAN are targets, also use the host IP; only targets within the same container network can use direct.

### Operations Notes

- Backup: `docker run --rm -v <project-name>_pojun-data:/data -v "%cd%:/backup" alpine tar czf /backup/pojun-data.tgz -C /data .`
- Docker Desktop resources: Settings → Resources ≥ 8G memory; after Windows reboots, Docker Desktop
  and containers auto-start (restart: unless-stopped);
- Upgrade: change `POJUN_TAG` in `.env`, then `docker compose -f ... -f ... pull && up -d`;
- skills/ keeps the bind mount (a few read-only files, NTFS read overhead is acceptable) — editing a skill avoids rebuilding the image.

## 0e. macOS Docker deployment (Docker Desktop / OrbStack, from v0.4.72)

Running the Docker container form on macOS: a plain `up -d` of the official `docker-compose.yml` starts the main
service, but there are three macOS-specific gaps (bind-mount I/O, callback ports, directory permissions), so the macOS
override is recommended:

```bash
docker compose -f docker-compose.yml -f docker-compose.macos.yml up -d
```

- `docker-compose.macos.yml`: the data volume becomes a named volume (macOS bind mounts go through
  VirtioFS/gRPC-FUSE and small-file I/O is likewise an order of magnitude slower — traffic/evidence are small-file
  heavy), and callback ports 4444-4450 are pre-mapped;
- callback receiver: in the container's direct mode LHOST is the container subnet IP, unreachable from external
  targets — on the "Listener / C2" page set the exit form to **manual** and fill in the host's LAN IP from
  `ipconfig getifaddr en0`, with listen ports corresponding 1:1 to the mapped ports;
- for the macOS **native binary** form (not Docker) see §0d.

## 0d. macOS Deployment (Run Prebuilt Package Directly, from v0.4.66)

macOS and Linux are both unix, so the main service (a pure-Go single binary) and the `start.sh` daemon script work directly;
the differences are in peripheral dependencies and the toolchain, install as needed:

- **Dependencies**: `brew install postgresql@16 poppler libreoffice` (document rendering and evidence preview),
  `brew services start postgresql@16`; install Node ≥ 20 and `uv` (for the two MCPs) as needed.
- **Penetration tools**: install `brew install nmap sqlmap nuclei ffuf` etc. as needed. Missing tools are
  shown truthfully as missing on the "Host Environment" page, and the agent works around missing tools using available ones; privileged scans
  (`masscan`/`nmap -sS`) require root/sudo, same as Linux.
- **Unavailable**: `pojun-hostd` batch tool installation (apt-based) and the "install all in one click" button;
  all other features (engine / intelligence / report / MCP / one-click update) are complete.
- **Startup**: extract the Release's `pojun-<version>-darwin-<arch>.zip` →
  `cp config.example.json config.json` fill in the database connection → `./start.sh`.
  The page's one-click update also works on macOS (automatically matches the darwin package by platform).
- Note Gatekeeper: binaries extracted directly from the browser may carry the quarantine attribute and be blocked;
  clear it with `xattr -d com.apple.quarantine pojun`; downloading and extracting with `curl`/`git` avoids this issue.

## 1. Backup (Cannot Be Skipped)

```bash
TS=$(date +%Y%m%d-%H%M%S)
BK=/root/artex-backup/pre-deploy-$TS
sudo -n mkdir -p "$BK"
sudo -n -u postgres pg_dump artex | gzip -1 > "$BK/artex.sql.gz"

# pigz multithreaded; **-p 8 gets OOM-killed on a 3.3G sqlite**, use -p 2
sudo -n tar --use-compress-program="pigz -p 2 -1" -cf "$BK/data-traffic.tar.gz" -C /opt/pojun/data traffic
sudo -n tar --use-compress-program="pigz -p 2 -1" -cf "$BK/data-tasks.tar.gz"   -C /opt/pojun/data tasks
```

**Verification** (`tar -tzf` lists entries one by one to confirm they are really readable):

```bash
for f in "$BK"/*.tar.gz; do echo "$(basename $f): $(sudo -n tar -tzf "$f" | wc -l) entries"; done
sudo -n zcat "$BK/artex.sql.gz" | grep -c 'CREATE TABLE'
```

## 2. Stop Service → Replace Binary → Start Service

### ⚠️ Deploying While Tasks Are Running = Cutting Off In-Flight Intents

`systemctl stop artex` cancels all running worker runs; they are written as
`blocked: context canceled`, and **all content is lost** (facts already written back remain, but that step's
probes are gone). In a test on 2026-10-21 deploying two versions in a row, all 8 intents of task 4 were cut off.

**Before deploying, check whether any tasks are running**:

```bash
sudo -n -u postgres psql -d artex -tA -F'|' -c \
  "SELECT id, status, left(name,30) FROM tasks WHERE status NOT IN ('done','failed','timeout');"
```

When tasks are running, two options:

- **Wait for it to finish** (recommended when the change is not urgent)
- **Gracefully pause first** (let the worker write back its results, then stop):
  ```bash
  curl -s -X POST "$API/api/tasks/<id>/control" -H "Authorization: Bearer $TOKEN" \
       -H 'Content-Type: application/json' -d '{"paused":true}'
  ```
  Wait until it enters paused, then stop.

**In case it has already been cut off**, use the official API to restore blocked intents to open (the worker will pick them up again):

```bash
curl -s -X POST "$API/api/tasks/<id>/intents/rerun-blocked" \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
# → {"id":"4","queued":false,"reopened":8}
```

### Actual Replacement Steps

```bash
sudo -n systemctl stop pojun

SRC=/tmp/pojun-upload/unpack/pojun-<version>-linux-amd64
D=/opt/pojun

# Binary: write .new first, then mv -f, to avoid ETXTBSY (a running binary cannot be written to)
sudo -n cp "$SRC/pojun" "$D/.pojun.new"
sudo -n chmod +x "$D/.pojun.new"
sudo -n mv -f "$D/.pojun.new" "$D/pojun"

sudo -n cp "$SRC/pojun-hostd" /usr/local/bin/.pojun-hostd.new
sudo -n chmod +x /usr/local/bin/.pojun-hostd.new
sudo -n mv -f /usr/local/bin/.pojun-hostd.new /usr/local/bin/pojun-hostd

# Maintenance tool (distributed with the package from v0.4.13+):
sudo -n install -m 0755 "$SRC/pojun-maint" "$D/pojun-maint"

# ★ skills must use the "merge" form: cp -r "$SRC"/skills/. "$D"/skills/
#   When written as cp -r "$SRC"/skills "$D"/, the target skills already exists, and GNU cp's behavior
#   does not guarantee filling in every sub-skill — in testing api-recon was once missed, while all three agents in the DB
#   were bound to it, so worker/auto/pentest silently lacked this capability.
sudo -n mkdir -p "$D/skills"
sudo -n cp -r "$SRC"/skills/. "$D"/skills/

sudo -n cp "$SRC/start.sh" "$D/start.sh"
sudo -n chmod +x "$D/start.sh"
echo "<version>" | sudo -n tee "$D/.version" >/dev/null
sudo -n chown -R pojun:pojun "$D"

sudo -n systemctl start artex
sleep 7
sudo -n journalctl -u artex --since '30 seconds ago' --no-pager | grep -Ei 'listening|panic'
```

**Must-check after deployment**:

```bash
sudo -n ls /opt/pojun/skills/          # the number of skills should match the release
sudo -n cat /opt/pojun/.version
```

## 3. Known Environment Facts

- **The service process carries `HTTP_PROXY` / `HTTPS_PROXY`** (systemd `Environment=`).
  In Go, `http.DefaultTransport.Clone()` inherits this proxy — to get a "direct connection" you must
  **explicitly set `transport.Proxy = nil`**. This project already follows this convention in three places:
  `agent/provider.go` (LLM), `traffic/traffic.go` (target traffic),
  `server/proxypool_api.go`.
- **The outbound proxy `10.10.70.14:7897` cannot reach some sites** (in testing cisa.gov /
  services.nvd.nist.gov give "TLS handshake EOF after CONNECT 200", while github works fine).
  Direct connection to these two sources works.
- The test machine intermittently fails to reach GitHub; the local machine needs the Clash proxy for GitHub
  (`socks5h://127.0.0.1:7897`).

## 4. Login Credentials

- The username is fixed as `ARTEX`; the password is a bcrypt hash stored in `settings` under
  `auth.password_hash`.
- **Reset password**: delete that row → `POST /api/auth/init` (body `{"password":"..."}`)
  → returns a token. `init` uses `InsertSettingIfAbsent` to ensure it can only be set once.
- To change the password use `POST /api/auth/change-password` (requires the **old password** + a valid token).

## 5. Full Reset (When You Want to Start from Scratch)

After backing up:

```bash
sudo -n systemctl stop artex
sudo -n -u postgres psql -d artex -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
-- ★ DELETE table by table, **do NOT use TRUNCATE ... CASCADE**
--   CASCADE follows foreign keys backward and clears "preserved tables": in testing task_scope references companies,
--   and CASCADE cleared companies/company_scope; agent_triggers was also wiped
--   ——after the reporter's report_finding trigger was lost, vulnerability reports no longer automatically triggered
--   the reporting Agent, so no one verified the traffic evidence.
--   Order: delete the referenced tables first, then the referencing ones.
DELETE FROM finding_traffic_bindings;
DELETE FROM traffic_evidence_snapshots;
DELETE FROM finding_retests;
DELETE FROM findings;
DELETE FROM activity;
DELETE FROM server_logs;
DELETE FROM llm_records;
DELETE FROM llm_usage;
DELETE FROM tool_usage;
DELETE FROM skill_usage;
DELETE FROM conversation_activities;
DELETE FROM side_question_requests;
DELETE FROM side_question_sessions;
DELETE FROM conversations;
DELETE FROM main_sessions;
DELETE FROM notification_events;
DELETE FROM notification_deliveries;
DELETE FROM intercept_pending;
DELETE FROM task_archives;
DELETE FROM scheduler_state;
DELETE FROM task_relations;
DELETE FROM task_asset_links;
DELETE FROM task_scope;
DELETE FROM task_constraints;
DELETE FROM task_intercept_rules;
DELETE FROM task_llm_profiles;
DELETE FROM exploration_anchors;
DELETE FROM exploration_edges;
DELETE FROM exploration_nodes;
DELETE FROM explorations;
DELETE FROM tasks;
DELETE FROM assets;
DELETE FROM settings WHERE key = 'auth.password_hash';
COMMIT;
SQL

for d in tasks sessions transcripts traffic evidence; do
  sudo -n rm -rf "/opt/pojun/data/$d"/* 2>/dev/null || true
  sudo -n mkdir -p "/opt/pojun/data/$d"
  sudo -n chown artex:artex "/opt/pojun/data/$d"
done
sudo -n systemctl start artex
```

**Must-check preserved tables after reset** (means of detecting CASCADE incidents):

```bash
sudo -n -u postgres psql -d artex -tA -c "
SELECT 'companies',count(*) FROM companies
UNION ALL SELECT 'company_scope',count(*) FROM company_scope
UNION ALL SELECT 'agent_triggers',count(*) FROM agent_triggers
UNION ALL SELECT 'agents',count(*) FROM agents
UNION ALL SELECT 'tools',count(*) FROM tools
UNION ALL SELECT 'settings',count(*) FROM settings"
```

`agent_triggers` must be **≥1** (the reporter's report_finding trigger).
If `companies` / `company_scope` had values before, restore them after reset (available from the backup).

**Preserve** (the system cannot function without them): `agents` / `agent_prompts` / `agent_triggers` /
`agent_visibility` / `agent_skill_visibility` / `agent_prompt_vars` / `tools` /
`settings` / `llm_profiles` / `llm_profile_health` / `intercept_rules` /
`asset_intercept_rules` / `mcp_servers` / `notification_channels` /
`task_templates` / `task_categories` / `companies` / `company_scope` /
`vuln_*`.

`nuclei-templates` (934M) — keep it, re-downloading is slow.

## 6. Post-Deployment Self-Check List

```bash
TOK=$(curl -s -X POST http://127.0.0.1:8787/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ARTEX","password":"<password>"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")

curl -s http://127.0.0.1:8787/api/health
curl -s http://127.0.0.1:8787/api/settings -H "Authorization: Bearer $TOK" | head -c 200
```

- `agent_traffic_binding` should be `true` (automatic binding of traffic evidence).
- `compaction_max_tokens` / `compaction_max_members` showing 0 is **normal**
  — 0 means "use the code default" (65536 tokens / 6 members), not that it is unconfigured.
- Opening `/function/tasks` in a browser should show "No tasks yet".

## 7. Intercept Rule Self-Check (After the 2026-10-22 Remediation)

Intercept rules were re-tiered in **v0.3.78**: built-in rules are no longer "deny everything", but are split into
**explicitly forbidden** (reject directly, no model call) / **handed to Agent for judgment** (model decides) / **manual confirmation**
(routed to approval). A fresh install should be in this state.

```bash
TOK=$(curl -s -X POST http://127.0.0.1:8787/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ARTEX","password":"<password>"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")

# Total number of rules and the distribution of the three actions
curl -s http://127.0.0.1:8787/api/intercept/rules -H "Authorization: Bearer $TOK" \
  | python3 -c "
import json,sys
rs=json.load(sys.stdin)['rules']
from collections import Counter
c=Counter(r['action'] for r in rs if r['name'].startswith('[Builtin]'))
print('Total built-in rules:', sum(c.values()))
print('Action distribution:', dict(c))
for r in sorted(rs, key=lambda x: -x['priority']):
    if r['name'].startswith('[Builtin]'):
        print(f\"  {r['action']:>5} | {r['name']}\")
"
```

**Expected values** (fresh install):

| Action | Count | Meaning |
|---|---|---|
| `deny` | 10 | Explicitly forbidden: irreversible in any context and with no legitimate penetration use |
| `judge` | 12 | Handed to Agent for judgment: the affected target depends on context |
| `ask` | 0 | Manual confirmation (from v0.3.86: listener start/stop rule removed, target tool was never implemented; the leftover rule on deployed instances is harmless and can be deleted manually) |

**Point-by-point verification checklist**

- Each rule's `timeout_enabled` should be `true`, and `timeout_seconds` / `timeout_action`
  should be **that rule's own values** (judgment type 90s/allow, hard-forbidden type 30s/deny). Before v0.3.78 this
  was a dead field — the UI showed 60s/deny while the global 180s/ask actually took effect.
- The "Data Exfiltration Pipeline" rule should be **enabled** (`enabled=true`). It was previously disabled by default because
  the old pattern would falsely flag legitimate reverse connections like `curl target | nc own reverse shell`; the new pattern
  only blocks "@file upload".
- "SQL DROP DATABASE / SCHEMA" and "SQL DROP TABLE / INDEX / VIEW" should be
  **two separate rules** (older versions had a single merged DROP rule).

**Runtime behavior verification** (requires a configured LLM profile, otherwise judgment rules follow the failure policy):

Send a task that triggers the rules, then look at the records in "System → Intercept Approval → History":

- A command triggering **explicitly forbidden** (e.g. `mkfs.ext4 /dev/sda`) → in the record `decision_source`
  is `rule`, the reason is the rule's own message, with **no `[Model]` prefix** (indicating no model call).
- A command triggering **judgment** (e.g. `rm -rf /var/www/html`) → the reason carries a **`[Model]` prefix**
  (indicating a model decision was made), and `rule_id` points to the matched built-in rule.

The platform has no "test match" API (rules only take effect on real tool calls), so this is the only way to observe.

> ⚠️ **Back up the database before upgrading an existing instance**. Rule migration (`intercept_builtin_rule_actions_v1`)
> rewrites the action/timeout/pattern fields of the `intercept_rules` table. It only changes rows that are "still at built-in
> defaults" (determined by action + timeout triplet + pattern); **rules modified by the user are left untouched**
> — but the backup must still be done.

## 8. v0.3.78 Fresh Install Verification Record (2026-10-22)

Before release, a fresh-install rehearsal was performed on **real PostgreSQL 16** using the v0.3.78 release binary
(empty DB → schema → seed → all migrations → start), results:

```
ARTEX 0.3.78 backend listening on 127.0.0.1:18787 (data=data, workers=3)

Built-in rules written to DB:
  deny  | 10    timeout_enabled=t  timeout=30s   action=deny
  judge | 12    timeout_enabled=t  timeout=90s   action=allow
  ask   |  1    timeout_enabled=t  timeout=180s  action=allow
```

Release package integrity was also checked: `SHA256SUMS` verification passed (linux-amd64 OK), after extraction
`artex` / `pojun-hostd` / `skills/` / `start.sh` / `config.example.json` are all present,
and `artex -h` works normally on Linux.

> ⚠️ **v0.3.77 has a known defect, do not use it for a fresh install**: that version's rule migration has
> a parameter misalignment (the `timeout_seconds` position receives a bool), so on a fresh install the seed phase
> errors out directly, preventing the service from starting. Use **v0.3.78 or later**.

## 9. Self-Check for v0.3.80+: Skills and Middleware Tools

v0.3.80 added the `vuln-hunting` skill (proactive vulnerability hunting methodology) and the "Middleware Protocol" tool
category. After installation you can confirm they actually took effect as follows.

### 9.1 Whether Skills Are Actually Seen by the Model

Skill files are in `<install-dir>/skills/`, and **visibility is bound in the DB**. If either is wrong,
the model cannot see the skill — while the page's skill list comes from the DB, so **file parsing failures are not visible**.

```bash
# 1) Are the files present
ls -la /opt/pojun/skills/

# 2) Can the frontmatter be parsed (both name + description must have values)
#    A skill without a description is effectively nonexistent to the model
for f in /opt/pojun/skills/*/SKILL.md; do
  echo "=== $f"
  sed -n '1,5p' "$f"
done
```

**A pitfall before v0.3.80**: the frontmatter terminator of `skills/scopesentry/SKILL.md` was
written as `## name:` (instead of `---`), so norma could not find the frontmatter boundary → the whole YAML block
was not parsed → that skill never appeared to the model. Fixed in v0.3.80.

### 9.2 Middleware Protocol Tools

The page "System → Host Environment" should have an additional "**Middleware Protocol**" group with 15 tools:

MQTT gmqtt / paho-mqtt; message queues pika / amqpstorm / confluent-kafka / kombu;
databases pymongo / pymysql / psycopg2-binary / redis; SOAP zeep;
GitLab python-gitlab; network devices netmiko / napalm; SIEM splunk-sdk.

**Note when installing**: these are **pure libraries** (no command-line entry point), installed by the platform with
`python3 -m pip install --break-system-packages` (not pipx — pipx cannot install
pure libraries, it reports "No apps associated with package ..."). After installation, verify:

```bash
python3 -c "import gmqtt, pika, pymongo, zeep, netmiko; print('ok')"
```

### 9.3 Recent High-Severity Fast Lane

Vulnerability intelligence sync now has two tracks: **main sync** (full catalog) and **fast lane** (pull by publication date for
the last 7 days, only CVSS≥9.0 or CISA KEV). The fast lane has an independent cursor, with a default interval of 30 minutes.

```bash
# The fast lane's cursor and number of records ingested
sudo -u postgres psql -d artex -tAc "
SELECT source, total_synced, left(coalesce(cursor,''),30), coalesce(last_error,'')
  FROM vuln_sync_state"
```

Seeing the `nvd_fastlane` row with a growing `total_synced` means the fast lane is running.
If you see `nvd rate limited`, that is NVD rate limiting — both tracks share the quota, and the platform coordinates with a gate;
if it still exceeds the limit, configure `NVD_API_KEY` (raises the limit from 5 requests/30s to 50 requests/30s).

## 10. Troubleshooting: Web Page Won't Open but "Service Status Normal"

**Symptom**: `systemctl status artex` shows `active (running)`, but the web page won't open.

**This was a real problem before v0.3.81** (now fixed, but the troubleshooting approach still applies):

- systemd sees the **`start.sh` wrapper script** still alive (it is waiting for the artex child process),
  while what actually crashed is artex itself. So the status is running, but **in reality everything is down**.
- Typical triggers: database password inconsistent with `config.json`, schema migration failure, port occupied.
  These are all **permanent** failures, crashing in an infinite retry loop, with the root cause drowned out in the logs.

**From v0.3.81**: start.sh gives up on auto-restart after 5 consecutive abnormal exits, and systemd's
StartLimit also puts the unit into `failed (start-limit-hit)`. So now the **status truthfully
shows the failure**.

**Troubleshooting steps**:

```bash
# 1) Look at the real logs (don't just look at status)
sudo journalctl -u artex --no-pager -n 50 | grep -vE "collation|warning|description|hint"

# 2) Look at the crash count and the "gave up on auto-restart" hint
sudo journalctl -u artex --no-pager | grep -E "abnormal exit|gave up on auto-restart" | tail -10

# 3) Is the database password consistent with config.json (★ the most common cause)
sudo -u postgres psql -tAc "select rolpassword is not null from pg_authid where rolname='artex'"
sudo python3 - <<'PY'
import json, subprocess
c = json.load(open('/opt/pojun/config.json'))['database']
env = {'PGPASSWORD': c['password'], 'PGHOST': c.get('host','127.0.0.1'),
       'PGPORT': str(c.get('port',5432)), 'PGUSER': c['user'],
       'PGDATABASE': c['dbname']}
r = subprocess.run(['psql','-tAc','select 1'], env=env, capture_output=True, text=True)
print('rc=', r.returncode, 'err=', r.stderr.strip()[:120])
PY

# 4) Is the port occupied
ss -tlnp | grep -E ":8787|:8788"
```

**The correct way to change the password** (don't only change the role but not config.json, or vice versa):

```bash
# Change the role password → change config.json in sync (the two must be consistent)
sudo -u postgres psql -c "ALTER ROLE artex LOGIN PASSWORD '<new-password>'"
sudo python3 - <<'PY'
import json
p='/opt/pojun/config.json'
c=json.load(open(p)); c['database']['password']='<new-password>'
json.dump(c, open(p,'w'), indent=2)
PY
sudo chmod 600 /opt/pojun/config.json
sudo systemctl restart pojun
```

> When the **role already exists**, install.sh uses the newly generated password to sync `ALTER ROLE` (from v0.3.79),
> and writes the same password into config.json — the two are naturally consistent.

## Document Evidence to Image Preview (from v0.4.21)

Word/Excel/PPT/PDF files captured in tasks are automatically sampled and converted to images for direct viewing
in the task overview's "Evidence Attachments" and in reports (no longer just download links).

- **Dependencies**: `libreoffice-writer libreoffice-calc libreoffice-impress`
  (Office→PDF) + `poppler-utils` (`pdftoppm` PDF→JPEG) + `imagemagick`
  (thumbnail fallback). `install.sh --with-tools` installs all by default; the Docker image has them built in;
  existing instances can install `libreoffice` / `poppler` additionally on the "System → Host Environment" page.
- **Sampling rules**: at most the **first 3 pages** per document, JPEG (long edge 1600, quality 82); PDF
  is rendered directly, Office is first converted to PDF via LibreOffice then rendered. Previews are sidecar files:
  `data/tasks/<id>/artifacts/previews/<artifact_id>/page-N.jpg`, not counted against
  the 100-attachment limit, protected by a 100MB per-task preview total.
- **Status**: the attachment list's `preview_state` is `pending/ready/failed/skipped`,
  with the failure reason in `preview_error` (missing dependencies prompt installation). The frontend can "regenerate" individual items.
- **Backfill previews for historical tasks**:

```bash
sudo -u pojun /opt/pojun/pojun-maint previews --config /opt/pojun/config.json --task 5
# Or all tasks (--force regenerates those already ready)
sudo -u pojun /opt/pojun/pojun-maint previews --config /opt/pojun/config.json --all
```

- **Troubleshooting**: `soffice --headless --convert-to pdf` has a 120s per-call timeout; LibreOffice
  conversions are globally serialized (to avoid profile lock conflicts), so seeing `pending` when large documents queue up is normal.

## Report Official-Document Fonts (from v0.4.4, Zero Configuration)

Word reports are exported in the GB/T 9704-2012 official-document format (FangSong_GB2312 body at size 3 / FZXiaoBiaoSong_GBK
document title at size 2 / KaiTi_GB2312 second-level headings / SimHei first-level headings, 28-point fixed line spacing, first-line indent of 2 characters,
22-line grid per page). The three official-document fonts are embedded into the binary via go:embed and embedded into the .docx on export
(ECMA-376 odttf) — **the recipient's machine renders them identically even without these fonts installed**, zero configuration on the server side.

Note two points:

1. The binary grows by about 21MB due to the embedded fonts (after zip compression, the docx increment is about 10MB each).
2. Export to PDF (optional): after installing LibreOffice on the server, convert offline —
   `soffice --headless --convert-to pdf report.docx`. For correct fonts in the PDF on a Linux machine,
   it is still recommended to install the fonts into the system (/usr/share/fonts/gongwen + fc-cache), because
   LibreOffice's support for fonts embedded in docx is incomplete:

   ```bash
   sudo mkdir -p /usr/share/fonts/gongwen
   # Take them from the repo's report/fonts/ (or a user-provided official-document font package), ASCII filenames are fine
   sudo cp report/fonts/*.ttf /usr/share/fonts/gongwen/
   sudo fc-cache -fv /usr/share/fonts/gongwen
   fc-list | grep -E "FangSong_GB2312|KaiTi_GB2312|FZXiaoBiaoSong"
   ```

## Historical Data Repair (pojun-maint, from v0.4.13)

`pojun-maint` is an offline maintenance tool distributed with the installer (`/opt/pojun/pojun-maint`),
which does not go through web login and is used to backfill old data after upgrades:

```bash
# 1) Register all historical images in task working directories (photos captured before the attachment feature existed) as
#    evidence attachments: deduplicate, at most 60 per task, skip artifacts themselves.
sudo /opt/pojun/pojun-maint scan-artifacts --config /opt/pojun/config.json

# 2) Update built-in agent prompts to the current binary version (reporter/retester etc. are seeded by
#    first-insert and are not overwritten automatically on upgrade). By default only reports the diff:
sudo /opt/pojun/pojun-maint reset-prompts --config /opt/pojun/config.json
#    After confirming the diff, write back (overwrites that agent's custom edits):
sudo /opt/pojun/pojun-maint reset-prompts --config /opt/pojun/config.json --force
```

> Images from old tasks have no finding_id, so the vulnerability detail page and single-vulnerability Word report
> fall back to showing task-level images with a note when there is "no dedicated image" (may include images from other materials in the same task, requiring manual review).

## Dependencies Covered by One-Click Install (--with-tools, from v0.4.13)

System repositories: nmap/masscan/sqlmap/hydra/whatweb/nikto/gobuster/ffuf/john/netcat/
dnsutils/whois/impacket/gitleaks, **imagemagick (evidence collage/watermark)**,
**libreoffice-writer (docx→PDF)**, nodejs/npm;
GitHub Release: nuclei/httpx/subfinder/naabu/dnsx/katana/tlsx/notify/
interactsh/gitleaks/chisel/amass/dalfox/feroxbuster;
Also installs SecLists, pip tools, Playwright MCP + chromium, and **official-document fonts**
(`/usr/share/fonts/gongwen`, pulled from the repo raw, failure only warns).

### Host tool install sources

Under "System → Host environment → Install sources" choose the system default, the Tencent Cloud mirror or the
Tsinghua TUNA mirror for APT and PyPI. Once saved, new single installs and "install all" jobs use the chosen sources.
With a mirror in use, the install proxy can still be set separately per network environment.

- **APT** recognizes supported Debian, Ubuntu and Kali official sources in `/etc/apt/sources.list` and
  `/etc/apt/sources.list.d/`. Only this APT job's mirror addresses are substituted; existing signature checks,
  distribution, architecture and third-party repo entries keep working as before. Self-built sources, DNF or tools
  bundled in the Docker image keep their deployment's package-management path.
- A **PyPI** mirror becomes the primary index for `pip` and `pipx` install jobs. Choosing "system default" restores
  the host helper's original configuration.
- The **Git** manual-download option converts a public GitHub repository address into a `gh-proxy.cn` clone address.
  Verify the commit against upstream after a manual clone. Program updates and GitHub downloads inside install-all
  keep using the install proxy.

## Data Disk Expansion and Migration (Tested on Kali 2026-11-02)

When the root disk is tight, migrate `data/` to a separate disk (the following uses a new `/dev/sdb` 100G disk as an example, about 2–3 minutes of downtime):

```bash
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT            # confirm the new disk has no partitions and no mounts
sudo parted -s /dev/sdb mklabel gpt mkpart primary ext4 0% 100%
sudo mkfs.ext4 -L <name>-data /dev/sdb1
sudo systemctl stop artex
sudo mkdir -p /mnt/newdata && sudo mount /dev/sdb1 /mnt/newdata
sudo rsync -aHAX /opt/pojun/data/ /mnt/newdata/
sudo mv /opt/pojun/data /opt/pojun/data.old && sudo mkdir -p /opt/pojun/data
sudo umount /mnt/newdata && sudo mount /dev/sdb1 /opt/pojun/data
sudo chown artex:artex /opt/pojun/data
UUID=$(sudo blkid -s UUID -o value /dev/sdb1)
echo "UUID=$UUID /opt/pojun/data ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab
sudo systemctl start artex && df -h /opt/pojun/data
# Only delete the backup after verifying the file count matches the pre-migration count: sudo rm -rf /opt/pojun/data.old
```

`nofail` must be added: a disk failure must not drag the system into emergency mode.

## Attachment 403 / Images Won't Open (from v0.4.18)

Attachment files must be readable by the service user (default `artex`). Historically, when `pojun-maint`
backfilled as root it wrote files with 0600 owned by root, and `http.ServeFile` returns 403 directly.
Fix:

```bash
sudo /opt/pojun/pojun-maint fix-permissions --config /opt/pojun/config.json
```

Normal permissions: directories 0750, files 0644 (the directory itself is under the task directory and is not exposed externally).
