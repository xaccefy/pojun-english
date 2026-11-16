"""FOFA asset search MCP server (stdio).

Three accounts: prefer the primary FOFA_EMAIL/FOFA_KEY; on 429/rate-limit/820041
switch to FOFA_EMAIL_BACKUP/FOFA_KEY_BACKUP, then FOFA_EMAIL_BACKUP2/FOFA_KEY_BACKUP2.
Fourth channel: get_alerts_onefox goes through the ONE-FOX community proxy
(fofa.one-fox.cn) — consumes none of your own key/F-points, site-side 60s rate limit;
password in .env ONEFOX_PASSWORD.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

mcp = FastMCP("fofasearch")

FOFA_API_BASE = "https://fofa.info/api/v1/search/all"
USER_AGENT = "fofa-mcp/1.0"

# Prefer env (Grok config.toml env=...); fall back to .env file.
FOFA_EMAIL = os.getenv("FOFA_EMAIL", "").strip()
FOFA_KEY = os.getenv("FOFA_KEY", "").strip() or os.getenv("FOFA_API_KEY", "").strip()
FOFA_EMAIL_BACKUP = os.getenv("FOFA_EMAIL_BACKUP", "").strip()
FOFA_KEY_BACKUP = (
    os.getenv("FOFA_KEY_BACKUP", "").strip()
    or os.getenv("FOFA_API_KEY_BACKUP", "").strip()
)
FOFA_EMAIL_BACKUP2 = os.getenv("FOFA_EMAIL_BACKUP2", "").strip()
FOFA_KEY_BACKUP2 = (
    os.getenv("FOFA_KEY_BACKUP2", "").strip()
    or os.getenv("FOFA_API_KEY_BACKUP2", "").strip()
)

# remember rate-limited accounts within a session; later requests prefer unthrottled ones
_exhausted: set[str] = set()


def _account_list() -> list[tuple[str, str, str]]:
    """Returns [(label, email, key), ...]: primary -> backup1 -> backup2; throttled ones last."""
    accs = [
        ("primary", FOFA_EMAIL or os.getenv("FOFA_EMAIL", "").strip(), FOFA_KEY),
        (
            "backup",
            FOFA_EMAIL_BACKUP or os.getenv("FOFA_EMAIL_BACKUP", "").strip(),
            FOFA_KEY_BACKUP or os.getenv("FOFA_KEY_BACKUP", "").strip(),
        ),
        (
            "backup2",
            FOFA_EMAIL_BACKUP2 or os.getenv("FOFA_EMAIL_BACKUP2", "").strip(),
            FOFA_KEY_BACKUP2 or os.getenv("FOFA_KEY_BACKUP2", "").strip(),
        ),
    ]
    valid = [a for a in accs if a[2]]
    live = [a for a in valid if a[0] not in _exhausted]
    dead = [a for a in valid if a[0] in _exhausted]
    return live + dead


def _is_rate_limited(result: dict[str, Any] | None, status_code: int | None = None) -> bool:
    if status_code in (429, 403):
        return True
    if not result:
        return False
    msg = str(result.get("message") or result.get("errmsg") or result.get("error") or "")
    low = msg.lower()
    if "429" in low or "too many" in low or "rate" in low:
        return True
    # FOFA business rate-limit codes
    if "820041" in msg or "today" in msg or "limit" in msg or "F points" in msg or "fpoint" in low:
        return True
    if result.get("error") and ("[-4]" in msg or "frequent requests" in msg or "access frequency" in msg):
        return True
    return False


async def make_fofa_request(url: str) -> dict[str, Any]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            try:
                data = response.json()
            except Exception:
                data = {"error": True, "message": response.text[:500], "http_status": response.status_code}
            if not isinstance(data, dict):
                data = {"error": True, "message": str(data), "http_status": response.status_code}
            data.setdefault("http_status", response.status_code)
            if response.status_code >= 400 and "error" not in data:
                data["error"] = True
                data["message"] = data.get("errmsg") or data.get("message") or f"HTTP {response.status_code}"
            return data
        except Exception as e:
            return {"error": True, "message": str(e)}


def format_alerts(alerts: list[list[Any]]) -> str:
    """Format FOFA rows (fields=host,ip,port) into readable text."""
    if not alerts:
        return ""

    lines: list[str] = []
    for result in alerts:
        if not isinstance(result, (list, tuple)):
            lines.append(str(result))
            continue
        # Default request uses host,ip,port
        if len(result) >= 3:
            host, ip, port = result[0], result[1], result[2]
            lines.append(f"hostname: {host}\nIP: {ip}\nport: {port}\n")
        else:
            lines.append(" | ".join(str(x) for x in result) + "\n")
    return "\n".join(lines)


def _build_url(email: str, key: str, query_str: str) -> str:
    params: dict[str, Any] = {
        "key": key,
        "qbase64": base64.b64encode(query_str.encode()).decode(),
        "size": 100,
        "fields": "host,ip,port",
    }
    # FOFA official API email+key; some key forms allow key alone
    if email:
        params["email"] = email
    return f"{FOFA_API_BASE}?{httpx.QueryParams(params)}"


@mcp.prompt()
async def search_prompt(query_params: str, assets_data: str) -> str:
    """Builds a security-analysis prompt carrying the asset context."""
    return (
        f"You are a senior network security analyst. Based on these query conditions: {query_params}\n"
        f"and the discovered asset information:\n{assets_data}\n\n"
        "analyze the potential security risks and provide:\n"
        "1. Asset exposure analysis\n2. Potential vulnerability assessment\n3. Hardening recommendations"
    )


@mcp.tool()
async def get_alerts(
    domain: str = "",
    ip: str = "",
    port: str = "",
    host: str = "",
    body: str = "",
    icon_hash: str = "",
    icp: str = "",
    status_code: str = "200",
) -> dict[str, Any] | str:
    """FOFA network asset search. Combine domain/IP/port/hostname/page content/icon hash/ICP/status code.

    Args:
        domain: domain name
        ip: IP address
        port: port
        host: hostname
        body: page content
        icon_hash: favicon hash
        icp: ICP filing number
        status_code: HTTP status code (default 200; pass an empty string to drop this condition)
    """
    accounts = _account_list()
    if not accounts:
        return {
            "error": "FOFA_KEY not configured. Set FOFA_EMAIL and FOFA_KEY in mcp-servers/fofa_MCP/.env (or the env of the Claude MCP `fofa` config); backups use FOFA_KEY_BACKUP / FOFA_KEY_BACKUP2."
        }

    query_parts: list[str] = []
    if domain:
        query_parts.append(f'domain="{domain}"')
    if ip:
        query_parts.append(f'ip="{ip}"')
    if port:
        query_parts.append(f'port="{port}"')
    if host:
        query_parts.append(f'host="{host}"')
    if body:
        query_parts.append(f'body="{body}"')
    if icon_hash:
        query_parts.append(f'icon_hash="{icon_hash}"')
    if icp:
        query_parts.append(f'icp="{icp}"')
    if status_code:
        query_parts.append(f"status_code={status_code}")

    if not query_parts:
        return {"error": "provide at least one query condition (domain/ip/port/host/body/icon_hash/icp)"}

    query_str = "&&".join(query_parts)
    last_error: dict[str, Any] | None = None
    used_accounts: list[str] = []

    for label, email, key in accounts:
        used_accounts.append(label)
        url = _build_url(email, key, query_str)
        result = await make_fofa_request(url)

        if result is None:
            last_error = {"error": "request failed or no response", "account": label}
            continue

        http_status = result.get("http_status")
        if _is_rate_limited(result, http_status if isinstance(http_status, int) else None):
            _exhausted.add(label)
            last_error = {
                "error": f"rate limit/quota: {result.get('message') or result.get('errmsg') or result}",
                "account": label,
                "http_status": http_status,
            }
            continue

        if result.get("error") is True and "message" in result and "results" not in result:
            # non-rate-limit hard error: try a backup if any; otherwise return
            last_error = {"error": f"request error: {result['message']}", "account": label}
            if _is_rate_limited(result):
                _exhausted.add(label)
                continue
            # auth failures etc. may still work on a backup
            msg = str(result.get("message") or "")
            if any(x in msg for x in ("401", "403", "[-1]", "[-3]", "incorrect", "invalid", "unauthorized")):
                continue
            # other errors still try the next account
            continue

        if result.get("error") and result.get("errmsg") and "results" not in result:
            if _is_rate_limited(result):
                _exhausted.add(label)
                last_error = {"error": result.get("errmsg"), "account": label, "raw": result}
                continue
            last_error = {"error": result.get("errmsg"), "account": label, "raw": result}
            continue

        if "results" in result:
            formatted = format_alerts(result.get("results") or [])
            out = {
                "query": query_str,
                "size": result.get("size"),
                "page": result.get("page"),
                "mode": result.get("mode"),
                "query_consumed": result.get("consumed_fpoint") or result.get("required_fpoints"),
                "count": len(result.get("results") or []),
                "data": formatted,
                "raw_results": result.get("results"),
                "account_used": label,
            }
            if used_accounts != [label]:
                out["account_tried"] = used_accounts
            return out

        last_error = {"error": "no matching assets found", "raw": result, "account": label}

    if last_error:
        last_error["account_tried"] = used_accounts
        return last_error
    return {"error": "no matching assets found", "account_tried": used_accounts}


# ---------------------------------------------------------------------------
# ONE-FOX community proxy channel (fofa.one-fox.cn)
# The site is a front-end shell over a PHP server-side proxy: the real FOFA key lives on
# the site's server; the front end only carries the site token `onefox` (hardcoded in
# js.js, not a FOFA key). Call chain: POST pagepwd on the homepage to open a PHP session
# -> POST function.php (action=fofa_cx). Site limits: 60s rate limit / exceeding the trial
# count returns HTTP 500 / site F-points exhausted returns a coin error. Returns FOFA
# official API v1 native JSON with fixed fields host,ip,title,port.
# ---------------------------------------------------------------------------

ONEFOX_BASE = os.getenv("ONEFOX_BASE_URL", "https://fofa.one-fox.cn").rstrip("/")
ONEFOX_PASSWORD = os.getenv("ONEFOX_PASSWORD", "").strip()
ONEFOX_SITE_TOKEN = "onefox"
ONEFOX_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
)
ONEFOX_STATE_FILE = Path(__file__).resolve().parent / ".onefox_session.json"
ONEFOX_MIN_INTERVAL = 65.0  # site 60s rate limit + margin; enforced cross-process via a state file
ONEFOX_ALLOWED_SIZES = (10, 100, 1000, 10000)
_onefox_lock = asyncio.Lock()


def _onefox_load_state() -> dict[str, Any]:
    try:
        data = json.loads(ONEFOX_STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _onefox_save_state(state: dict[str, Any]) -> None:
    try:
        ONEFOX_STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _onefox_nearest_size(size: int) -> int:
    return min(ONEFOX_ALLOWED_SIZES, key=lambda s: (abs(s - size), s))


def format_onefox_rows(rows: list[Any]) -> str:
    """The ONE-FOX proxy returns fixed [host, ip, title, port] rows."""
    lines: list[str] = []
    for row in rows:
        if isinstance(row, (list, tuple)):
            vals = [str(row[i]) if len(row) > i else "" for i in range(4)]
            lines.append(f"hostname: {vals[0]}\nIP: {vals[1]}\ntitle: {vals[2]}\nport: {vals[3]}\n")
        else:
            lines.append(str(row))
    return "\n".join(lines)


async def _onefox_login(client: httpx.AsyncClient) -> tuple[bool, str]:
    """GET the homepage for the WAF challenge cookie -> POST pagepwd to open a session."""
    try:
        await client.get(f"{ONEFOX_BASE}/", timeout=30.0)
    except Exception as e:
        return False, f"homepage request failed: {e}"
    last_status = 0
    for attempt in range(3):
        try:
            r = await client.post(
                f"{ONEFOX_BASE}/",
                data={"pagepwd": ONEFOX_PASSWORD},
                headers={"Referer": f"{ONEFOX_BASE}/"},
                timeout=30.0,
            )
        except Exception as e:
            return False, f"password submission failed: {e}"
        last_status = r.status_code
        if r.status_code == 200 and ("function.php" in r.text or "search widget" in r.text):
            return True, "ok"
        await asyncio.sleep(2.0 * (attempt + 1))  # WAF challenge not passed: back off and retry
    return False, f"login failed (HTTP {last_status})"


async def _onefox_post_query(client: httpx.AsyncClient, query: str, size: int) -> dict[str, Any]:
    r = await client.post(
        f"{ONEFOX_BASE}/function.php",
        data={
            "action": "fofa_cx",
            "fofa_yf": query,
            "fofa_ts": size,
            "api_key": ONEFOX_SITE_TOKEN,
        },
        headers={
            "Referer": f"{ONEFOX_BASE}/",
            "X-Requested-With": "XMLHttpRequest",
        },
        timeout=60.0,
    )
    if r.status_code == 500:
        return {"error": True, "errmsg": "HTTP 500: exceeded the site's trial row count (site-side limit) — retry with a smaller size"}
    try:
        data = r.json()
    except Exception:
        if r.status_code == 403:
            return {"error": True, "errmsg": "session_waf_403"}
        return {"error": True, "errmsg": f"non-JSON response (HTTP {r.status_code}): {r.text[:200]}"}
    if isinstance(data, dict):
        return data
    return {"error": True, "errmsg": str(data)[:200]}


async def _onefox_search_impl(query: str, size: int) -> dict[str, Any]:
    if not ONEFOX_PASSWORD:
        return {
            "error": "ONEFOX_PASSWORD not configured. Add ONEFOX_PASSWORD to mcp-servers/fofa_MCP/.env (the ONE-FOX planet access password)."
        }

    size = _onefox_nearest_size(int(size))
    async with _onefox_lock:
        state = _onefox_load_state()
        waited = 0.0
        remain = ONEFOX_MIN_INTERVAL - (time.time() - float(state.get("last_query") or 0))
        if remain > 0:
            waited = remain
            await asyncio.sleep(remain)

        result: dict[str, Any] | None = None
        async with httpx.AsyncClient(
            trust_env=False,
            follow_redirects=True,
            cookies=state.get("cookies") or {},
            headers={"User-Agent": ONEFOX_UA},
        ) as client:
            for attempt in range(2):
                result = await _onefox_post_query(client, query, size)
                errmsg = str(result.get("errmsg") or "")
                need_relogin = "session is" in errmsg.lower() or errmsg == "session_waf_403"
                if need_relogin and attempt == 0:
                    ok, msg = await _onefox_login(client)
                    if not ok:
                        result = {"error": True, "errmsg": f"ONE-FOX session rebuild failed: {msg}"}
                        break
                    continue
                break

            result = result or {"error": True, "errmsg": "unknown error"}
            _onefox_save_state({"cookies": dict(client.cookies), "last_query": time.time()})

        out: dict[str, Any] = {"channel": "onefox-proxy"}
        if waited:
            out["waited_seconds"] = round(waited)

        if result.get("error"):
            errmsg = str(result.get("errmsg") or result.get("error") or "")
            if "Too frequent" in errmsg:
                errmsg += " (site 60s rate limit — query again later)"
            elif "coin" in errmsg.lower():
                errmsg += " (site-side FOFA F-points exhausted — this channel is unavailable for now)"
            out["error"] = errmsg
            return out

        rows = result.get("results") or []
        out.update(
            {
                "query": result.get("query") or query,
                "size": result.get("size"),
                "page": result.get("page"),
                "mode": result.get("mode"),
                "count": len(rows),
                "data": format_onefox_rows(rows),
                "raw_results": rows,
                "account_used": "onefox-proxy",
            }
        )
        return out


@mcp.tool()
async def get_alerts_onefox(query: str, size: int = 10) -> dict[str, Any]:
    """FOFA asset search (ONE-FOX community proxy channel; consumes none of your own FOFA key/F-points).

    Use when all three official accounts are rate-limited or you don't want to spend
    F-points. Pass FOFA syntax verbatim, e.g. header="ThinkPHP" && country="CN".
    Returned fields are fixed host,ip,title,port; the site enforces a 60s rate limit (the
    tool waits automatically, effective across calls); size accepts only 10/100/1000/10000
    (snaps to the nearest tier).

    Args:
        query: FOFA syntax query string, e.g. icon_hash="123456789" or domain="example.com"
        size: row count; only 10/100/1000/10000 accepted
    """
    return await _onefox_search_impl(query, size)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
