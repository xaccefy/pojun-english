# Proxy and egress chain

> Applies to v0.4.83+. Target traffic = the worker's requests to an authorized target; platform traffic = LLM/intel sync/installs and the like.

## 1. The three egress paths

| Scenario | Egress | Notes |
|---|---|---|
| Traffic capture **on** | Local MITM (`traffic`) | All target traffic goes into the recording store; the MITM upstream then picks "proxy pool → global proxy → direct" |
| Traffic capture **off**, pool has a usable entry | One upstream from the pool | One exit is pinned per Agent at build time (`ProxyAddr()`); Bash/native tools inside the task agree |
| Traffic capture **off**, pool empty/all tripped | Global proxy → direct | Old behavior; with strict egress it becomes a failure (sentinel `127.0.0.1:1`) instead of a direct fallback |

**Strict egress** (`egress_strict_proxy`, off by default, a switch on the proxy-pool page): with a pool configured but fully tripped, target requests fail outright and never expose the real IP. A separate `traffic_direct_record_fallback` (off by default) allows "direct but still recording" — trading IP hiding for evidence continuity, operator-enabled only.

## 2. Proxy coverage per execution surface (after the v0.4.83 fixes)

| Surface | Proxy source | Status |
|---|---|---|
| Bash subprocess (curl/python/git/feroxbuster…) | `proxyEnv()`: `HTTP(S)_PROXY` / `ALL_PROXY` / `CA` + `EGRESS_PROXY` | ✅ |
| Native `http_request` / `session_login` | `ToolSet.SetEgressProxy` (injected when worker/planner/mainagent are built) | ✅ fixed in v0.4.83 (was dead code, went direct) |
| `job_start` background jobs | `mergeProxyEnv(os.Environ(), egressProxy, CA)` | ✅ fixed in v0.4.83 (took os.Environ only) |
| `run_script` / `poc_scaffold` / custom tools | Run through Bash, inheriting `proxyEnv` | ✅ |
| sqlmap / ffuf / httpx / dalfox (hand-written) | Unstable env support, **must be passed explicitly**: the worker prompt requires `$EGRESS_PROXY` | ⚠️ prompt-enforced, not mandatory |
| `scan_with_nuclei` (group commands) | `ToolSet.SetEgressProxy` → `ScanArgs.Proxy` → the command carries `-proxy` (no empty proxy added) | ✅ enforced in code (from this version; the server-level registry excepted, see below) |
| nuclei (hand-written) | The worker prompt requires `-proxy "$EGRESS_PROXY"`; the server-level domainReg instance has no `egressProxy`, see troubleshooting 4 | ⚠️ prompt-enforced, not mandatory |
| Monitor (SDK background tool) | The SDK SpawnSpec carries no Env | ❌ known gap — use `job_start` or Bash background for target traffic |
| enrich HTTP completion | `m.ProxyAddr()` | ✅ (DNS/UDP can't go through an HTTP proxy) |
| browser MCP | With capture on, `--proxy-server=MITM` + CA | ✅ |
| notify / vulnintel / selfupdate / hostd | Maintenance proxy or direct (platform traffic, deliberately outside target capture) | ✅ |

> Known gap (not fixed in this version): `buildDomainReg` in `server/assembly.go` (around L480-491) builds its instance with `NewToolSet(nil,"")` and never calls `SetEgressProxy`. That registry only serves Auto/custom agents that hold no per-task ToolSet (see the `AllDomainTools` comment), and when bound to those agents `scan_with_nuclei` carries no `-proxy`. The chat/mainagent ToolSets do get `egressProxy` injected and are unaffected.

When merging environment variables, same-named parent keys are stripped first: under POSIX a duplicate env var resolves to the first entry, so a plain append leaves the child reading the host's old proxy. Windows env names are case-insensitive, so uppercase keys are kept uniformly.

## 3. Clash / mihomo core

- Page: System → Clash node management (`/system/proxypool/clash`)
- Install: official GitHub source + mirror acceleration (`gh-proxy.com` and the like, overridable via `proxypool_mihomo_mirrors`) + custom URL/local file/PATH — four routes; SHA256 verification, resumable downloads
- Start: subscription YAML or URL → rewrite the config (random mixed-port only, loopback-bound, rules collapsed to a single `MATCH,<exit>`, geo download off) → wait for the port + a real HTTP liveness check → the entry address is written into the proxy pool as `mihomo-local`
- Exit modes: fixed group / fixed node / load balance / url-test / fallback; `external-controller` is loopback-bound with a random secret per start, used for node delay tests
- Health checks: when every local mihomo upstream fails it is restarted from the config on disk; trip state persists across restarts (`proxy_pool_break_state`)

## 4. Proxy pool

- Entries: `http/https/socks5://[user:pass@]host:port`, with name/weight/enable
- Strategies: `round_robin` / `sticky_host` / `sticky_host_random` / `random`
- Tripping: 5 consecutive failures cool down for 10 minutes; the active health check runs every 10 minutes by default and trips for 30; an agent can query and report via `proxy_status` / `proxy_report`
- Import: parses host:port / URL / host:port:user:pass per line; verifies before import by default, bad lines are not imported
- With capture off: `ProxyPoolPick("")` pins one exit per Agent build; a pool change rebuilds the Agents automatically (`refreshAgentsForEgressChange`)

## 5. SSH jump hosts

- Page: System → SSH jump hosts (`/system/egress`)
- Passwords/private keys are encrypted in the credential vault (XChaCha20-Poly1305, master key `data/vault.key` or `POJUN_VAULT_KEY`) and the API returns only a `credential_id`
- After start a random local SOCKS5 listener is opened and `use` adds `socks5://127.0.0.1:<port>` to the pool in one click (an `ssh-jump` entry)
- Coexists with Clash nodes; stopping removes it from the pool

## 6. Troubleshooting

1. Target requests fail: `proxy_status` first for available count/trip state/strict egress; then decide whether it is a local egress problem or an unreachable target
2. A native tool ignores the proxy: confirm `http_request` is called inside worker/planner/mainagent (injected automatically from v0.4.83); check whether `EGRESS_PROXY` is in the Bash environment
3. A background job ignores the proxy: `job_start` inherits it; Monitor does not — use job_start
4. sqlmap / ffuf / httpx / dalfox / hand-written nuclei go direct: these tools have unstable env support, so the proxy is prompt-enforced as an explicit argument (sqlmap `--proxy="$EGRESS_PROXY"`, ffuf `-proxy "$EGRESS_PROXY"`, httpx `-http-proxy "$EGRESS_PROXY"`, dalfox `--proxy "$EGRESS_PROXY"`, hand-written nuclei `-proxy "$EGRESS_PROXY"`); if it still goes direct with a proxy configured, check the command first. For `scan_with_nuclei` look for `-proxy` in `run_with_bash` (it is added automatically from this version, so its absence isn't a misconfiguration — if it really is missing, the call went through the server-level direct instance, see the known gap above).
5. Everything fails after enabling strict egress: expected (fail-closed); restore an upstream or switch strict egress off for now.
