# ONE-FOX FOFA Proxy Channel Implementation Notes

> Integrated on 2026-09-20. This document records the findings from crawling analysis of the fofa.one-fox.cn proxy interface, as well as
> the implementation approach of the get_alerts_onefox tool in fofa.py, for future maintenance or reuse.

## 1. What Is the Target Site

`https://fofa.one-fox.cn/` (ONE-FOX security team's "Planet" membership lookup tool) is **NOT a FOFA mirror site**,
it's a pure front-end shell + PHP server-side proxy:

- The page has only 4 static assets, all core logic is in `js.js` (under 5KB);
- The real FOFA API key lives on the site owner's server (PHP environment variable) and is never visible in browser traffic;
- The front-end `getApiKey()` returns a hardcoded constant `"onefox"` — that's a **site token**, not a FOFA key
  (the comment even solemnly says "get the server-generated API key", but it's actually a decoy).

## 2. Proxy Interface Specification

```
POST https://fofa.one-fox.cn/function.php
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Referer: https://fofa.one-fox.cn/

action=fofa_cx&fofa_yf=<URL-encoded fofa query syntax>&fofa_ts=<result count>&api_key=onefox
```

- Returns **native JSON from FOFA official API v1** (`error / consumed_fpoint / required_fpoints /
  size / page / mode / results` completely isomorphic with `fofa.info/api/v1/search/all`),
  `mode:"extended"` indicates the site owner is using a registered-user API;
- `results` row format is fixed as `[host, ip, title, port]` (fields hardcoded on the site's server, not selectable);
- The site token `api_key=onefox` is public in `js.js`, visible to everyone.

## 3. Session Mechanism (three-step call chain)

```bash
# 1. GET the homepage to obtain WAF challenge cookies (server_session_* / X_CACHE_KEY / md5-named cookies)
#    Skipping this step and directly submitting the password results in 403
curl -c jar.txt https://fofa.one-fox.cn/

# 2. POST the password to establish a PHP session (form posts back to the homepage itself)
curl -b jar.txt -c jar.txt -d "pagepwd=<Planet password>" https://fofa.one-fox.cn/

# 3. Query with the session
curl -b jar.txt -X POST https://fofa.one-fox.cn/function.php \
  -H "X-Requested-With: XMLHttpRequest" -e "https://fofa.one-fox.cn/" \
  --data 'action=fofa_cx&fofa_yf=header%3D%22ThinkPHP%22&fofa_ts=10&api_key=onefox'
```

Observed details:

- The first password POST is often blocked by WAF 403; back off a few seconds and retry to pass (pure cookie challenge, no JS challenge);
- In the session cookie, `PHPSESSID=onefox` is a hardcoded fixed value, but server-side session state still requires a real login;
  querying function.php with an invalid session returns `{"error":true,"errmsg":"session is exists."}`
  (js.js also has a `session is not exists.` branch; both may appear on the site, treat them equally);
- After successful password verification, an additional `mk_encrypt_*` cookie is issued.

## 4. Site-Side Limits

| Signal | Meaning | Handling |
|------|------|------|
| `Too frequent access. Please wait a moment.` | 60s rate limit | client throttles to 65s |
| HTTP 500 | trial result count exceeded (site-side limit, not an official API error) | reduce `fofa_ts` |
| `FOFA coin is not enough!` | **site owner's FOFA account F-points exhausted** | stop, wait for the site owner to top up |
| `Query invalid!` | empty syntax | check input parameters |

**Red line: this channel consumes the site owner's account F-points. As of 2026-09-20 it's designated as the primary independent query channel (user-specified),
but primary ≠ abuse: heavy tasks like full exports and bulk scans still go through the official channel; if the site owner's F-points are drained, this channel is dead.**

## 5. fofa.py Integration Implementation

Added a new tool `get_alerts_onefox(query, size=10)`, running alongside the official channel `get_alerts` (three-account rotation),
without interfering with each other. Implementation key points:

1. **Configuration**: `ONEFOX_PASSWORD` is in `fofa_MCP/.env` (never write in chat/reports); `ONEFOX_BASE_URL`
   can be overridden, default `https://fofa.one-fox.cn`; site token `ONEFOX_SITE_TOKEN="onefox"` hardcoded.
2. **Request client**: `httpx.AsyncClient(trust_env=False)` — bypasses any stale invalid proxy left on the machine
   (the 127.0.0.1:59112 trap); UA uses a browser string to avoid UA fingerprint blocking.
3. **Session management**: cookies persisted to `.onefox_session.json` (already in `.gitignore`), reused across MCP
   restarts, eliminating login each time. When a query returns `session is*` or 403, automatically run the login chain once and retry.
4. **Rate limiting**: record `last_query` timestamp in the state file; before each query, if the delta is under 65s,
   pad with `asyncio.sleep` — serialized within one MCP process via `asyncio.Lock`, across processes via the file.
5. **size tiers**: only accepts 10/100/1000/10000; other values snap to the nearest tier.
6. **Error mapping**: site errors are translated into Chinese messages and returned as-is, with a response structure isomorphic to `get_alerts`
   (`query/size/page/mode/count/data/raw_results/account_used`),
   `account_used="onefox-proxy"` marks the source.
7. **Login success determination**: password POST returns 200 and HTML contains `function.php` or "Search Mini-Tool"
   (i.e., query page markers), otherwise back off and retry up to 3 times.

## 6. Deployment Locations

| Location | Content |
|------|------|
| `src-6k/mcp-servers/fofa_MCP/fofa.py` | tool implementation (this directory) |
| `src-6k/mcp-servers/fofa_MCP/.env` | `ONEFOX_PASSWORD` + FOFA three-account keys |
| `src-6k/mcp-servers/fofa_MCP/.onefox_session.json` | session cookie + last_query (generated at runtime) |
| Claude Code: `~/.claude.json` mcpServers.fofa | existing registration, FOFA_KEY inlined in env |
| ZCode: `~/.zcode/cli/config.json` mcp.servers.fofa | registration added 2026-09-20, key not inlined, relies on .env |
| `src-6k/SKILL.md` line 53 | primary channel as of 2026-09-20 (user-specified); official three accounts demoted to fallback |

**Changes require restarting the corresponding harness session to take effect** (the MCP server starts with the session).

## 7. Test Records (2026-09-20)

- `header="ThinkPHP"`: `size=427293`, returned 10 rows of host/ip/title/port ✓
- First query with no session → automatic GET + password submission (one WAF 403 → passed after backoff retry) → re-query succeeded ✓
- cookies written to disk ✓; three-step chain reproduced with plain curl ✓

## 8. Limitations

- Return fields hardcoded to host, ip, title, port; for fields like body/icon_hash use the official channel;
- At most 1 query per minute, and it consumes the site owner's quota, so large-scale mapping is impractical;
- The site is a community public-welfare project, the interface has no contract guarantee and may change at any time — after a change, just re-check
  the data template of `run_form()` in `js.js` (the specification in section 2 of this document was scraped from there).
