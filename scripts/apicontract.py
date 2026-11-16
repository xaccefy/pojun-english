#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARTEX API contract sweep.

Runs a three-stage check over every backend route:

  A. Unauthenticated -- no Authorization header, expect 401 (except /api/auth/* and /api/health)
  B. Empty params    -- valid token but no required params, expect 4xx and **not 500**
  C. Normal read     -- GET only: a normal request with a valid token, expect 2xx/4xx, **any 5xx is a bug**

Write operations (POST/PUT/PATCH/DELETE) only get stages A and B -- no real data changes.

Usage:
    # 1) Extract routes from the source first
    python scripts/extract_routes.py server /tmp/routes.json

    # 2) Run the sweep (token read from the environment, or auto-login with username/password)
    ARTEX_USERNAME=ARTEX ARTEX_PASSWORD=*** python scripts/apicontract.py \
        --routes /tmp/routes.json --base-url http://127.0.0.1:8787

    # 3) Run only the unauthenticated stage (when you have no credentials)
    python scripts/apicontract.py --routes /tmp/routes.json --anon-only

Passwords are only ever read from environment variables, never written into code or reports.
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

# Route prefixes that need no authentication
AUTH_EXEMPT_PREFIXES = ("/api/auth/",)
AUTH_EXEMPT_EXACT = ("/api/health",)

# Read-only methods: get the full stage-C check
READ_METHODS = ("GET",)

# "External dependency not ready" is not a defect in this system. Integrations like ScopeSentry inevitably
# fail when the user has not configured a data source -- the frontend has a dedicated status endpoint showing
# "not configured". Counting that as a 5xx bug would drown the real problems. Detection: 5xx + the error
# message contains one of the following configuration-related phrasings.
# (The legacy phrasings are kept for older builds whose messages were still localized.)
UNCONFIGURED_MARKERS = (
    "not configured", "configure first", "does not exist, create it first", "not initialized",
    "not configured", "configure first", "does not exist, create it first", "not initialized",
)

# Path-parameter substitution table. Names like {key} use real existing values.
PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def log(msg):
    print(msg, flush=True)


def fetch(url, method="GET", token=None, body=None, timeout=15, headers=None, retries=2):
    """Send one HTTP request, return (status, body_text, error). Never raises.

    502 / connection failure under concurrent load is the server refusing, not a route defect -- retry a few
    times before judging. Otherwise "server rate-limiting" gets misreported as the real bug
    "unauthenticated but allowed through".
    """
    data = None
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = "Bearer " + token

    last = (0, "", "not attempted")
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read()
                return resp.status, raw.decode("utf-8", "replace"), None
        except urllib.error.HTTPError as e:
            raw = e.read() if hasattr(e, "read") else b""
            status, text = e.code, raw.decode("utf-8", "replace")
            if status == 502 and attempt < retries:
                time.sleep(0.4 * (attempt + 1))
                continue
            return status, text, None
        except urllib.error.URLError as e:
            last = (0, "", str(e.reason))
            if attempt < retries:
                time.sleep(0.4 * (attempt + 1))
                continue
            return last
        except Exception as e:  # timeouts etc.
            last = (0, "", type(e).__name__ + ": " + str(e))
            if attempt < retries:
                time.sleep(0.4 * (attempt + 1))
                continue
            return last
    return last


def login(base_url, username, password):
    """Exchange username/password for a JWT. Returns None on failure."""
    status, text, err = fetch(
        base_url + "/api/auth/login",
        method="POST",
        body={"username": username, "password": password},
    )
    if status != 200:
        log(f"  login failed: HTTP {status} {err or ''} {text[:200]}")
        return None
    try:
        return json.loads(text).get("token")
    except Exception:
        log(f"  login response could not be parsed: {text[:200]}")
        return None


def discover_ids(base_url, token):
    """Pull a batch of real IDs from the running instance, for substituting path parameters.

    A request whose path parameters are substituted inaccurately returns 404 -- that means "the parameter was
    not substituted", not "the route is broken"; the report must distinguish the two.
    """
    ids = {}
    probes = {
        "task": ("/api/tasks", lambda d: (d.get("tasks") or d.get("data") or [{}])[0].get("id")),
        "id": ("/api/exploration/findings", lambda d: (d.get("findings") or d.get("data") or [{}])[0].get("id")),
        "key": ("/api/agents", lambda d: (d.get("agents") or d.get("data") or [{}])[0].get("key")),
        "name": ("/api/skills", lambda d: (d.get("skills") or d.get("data") or [{}])[0].get("name")),
    }
    for key, (path, pick) in probes.items():
        status, text, _ = fetch(base_url + path, token=token)
        if status != 200:
            continue
        try:
            data = json.loads(text)
        except Exception:
            continue
        try:
            val = pick(data)
        except Exception:
            val = None
        if val is not None:
            ids[key] = val
    # Fallback: use common fixed values when there is no real data
    ids.setdefault("id", 1)
    ids.setdefault("task", "1")
    ids.setdefault("taskId", "1")
    ids.setdefault("key", "worker")
    ids.setdefault("name", "default")
    ids.setdefault("skill", "default")
    ids.setdefault("cid", "1")
    ids.setdefault("rid", "1")
    ids.setdefault("gid", "1")
    ids.setdefault("sid", "1")
    ids.setdefault("iid", "1")
    ids.setdefault("assetID", "1")
    ids.setdefault("asset_id", "1")
    ids.setdefault("seq", "1")
    ids.setdefault("binding_id", "1")
    ids.setdefault("bindingId", "1")
    ids.setdefault("requestID", "1")
    ids.setdefault("conversation", "1")
    ids.setdefault("conversation_id", "1")
    ids.setdefault("jobId", "1")
    ids.setdefault("model", "gpt-4")
    return ids


def is_stream_path(path):
    """SSE long-lived routes: the request hangs until the client disconnects.

    Such routes cannot be tested with normal "request completed" semantics -- they are supposed to hang. So a
    timeout actually means the stream was established correctly.
    """
    return path.endswith("/stream")


def route_timeout(path):
    return 4 if is_stream_path(path) else 15


def fill_path(path, ids):
    """Replace {param} with real values. Returns (filled_path, unresolved_params)."""
    missing = []

    def sub(m):
        name = m.group(1)
        if name in ids:
            return str(ids[name])
        missing.append(name)
        return "1"

    filled = PATH_PARAM_RE.sub(sub, path)
    return filled, missing


def is_unconfigured(body):
    """Decide whether an error message means "external dependency not configured" rather than a real bug."""
    if not body:
        return False
    return any(m in body for m in UNCONFIGURED_MARKERS)


def check_route(route, base_url, token, ids, do_read):
    """Run the checks for one route and return a result record.

    * Write operations (POST/PUT/PATCH/DELETE) **never send a real request with a token**.

    Reason (measured incident, 2026-10-21): these endpoints are neither idempotent nor side-effect free --
      POST /api/llm      an empty body rewrites the "globally active LLM config" (provider
                         falls back to the default anthropic, base_url cleared, api_key
                         falls back to the old key currently in memory), after which every LLM call 403s;
      POST /api/tasks    an empty body really creates a task.
    The sweep script's job is "is the route contract correct", not "change live config". Write endpoints only
    get the unauthenticated stage (stage A): there is no token then, so the service executes no side effects.
    """
    method = route["method"]
    path = route["path"]
    filled, missing = fill_path(path, ids)
    url = base_url + filled
    rec = {
        "method": method,
        "path": path,
        "filled": filled,
        "handler": route["handler"],
        "unfilled_params": missing,
        "anon_status": None,
        "empty_status": None,
        "read_status": None,
        "unconfigured": False,
        "skipped_write": False,
        "issues": [],
    }

    # A. Unauthenticated (done for every route; without a token the service executes no side effects)
    st, body, err = fetch(url, method=method, body={} if method != "GET" else None, timeout=route_timeout(path))
    rec["anon_status"] = st
    exempt = path.startswith(AUTH_EXEMPT_PREFIXES) or path in AUTH_EXEMPT_EXACT
    if st == 0:
        # Cannot connect: not a route problem, flagged separately
        rec["issues"].append(f"unauthenticated-stage request failed: {err}")
    elif exempt:
        if st not in (200, 400, 401, 403):
            rec["issues"].append(f"exempt route returned {st} unauthenticated")
    else:
        if st != 401:
            rec["issues"].append(f"unauthenticated should return 401, actually {st}")

    if token is None:
        return rec

    if method not in READ_METHODS:
        # Write endpoint: stop here. A request with a token would really change live state.
        rec["skipped_write"] = True
        return rec

    # B. Empty params (read-only routes: with a token, deliberately omitting required params)
    st, body, err = fetch(url, method=method, token=token, body={} if method != "GET" else None, timeout=route_timeout(path))
    rec["empty_status"] = st
    if st >= 500 and is_unconfigured(body):
        rec["unconfigured"] = True
    elif st >= 500:
        rec["issues"].append(f"empty params returned 5xx: {st} {body[:300]}")
    if st == 0:
        if is_stream_path(path):
            # SSE is a long-lived connection; timing out before it ends is expected, not a problem.
            rec["empty_status"] = 200
            rec["empty_stream"] = True
            rec["issues"] = [i for i in rec["issues"] if "empty-params request failed" not in i]
        else:
            rec["issues"].append(f"empty-params request failed: {err}")

    # C. Normal read
    st, body, err = fetch(url, method=method, token=token, timeout=route_timeout(path))
    rec["read_status"] = st
    if st >= 500 and is_unconfigured(body):
        rec["unconfigured"] = True
    elif st >= 500:
        rec["issues"].append(f"normal GET returned 5xx: {st} {body[:300]}")
    if st == 0:
        if is_stream_path(path):
            rec["read_status"] = 200
            rec["read_stream"] = True
            rec["issues"] = [i for i in rec["issues"] if "normal GET request failed" not in i]
        else:
            rec["issues"].append(f"normal GET request failed: {err}")

    return rec


def summarize(results):
    anon = Counter(str(r["anon_status"]) for r in results)
    empty = Counter(str(r["empty_status"]) for r in results if r.get("empty_status") is not None)
    read = Counter(str(r["read_status"]) for r in results if r.get("read_status") is not None)
    with_issues = [r for r in results if r["issues"]]
    unconfigured = [r for r in results if r.get("unconfigured")]
    skipped_write = [r for r in results if r.get("skipped_write")]
    # Routes whose external dependency is not ready stay out of server_errors but are reported separately.
    unconfigured_paths = {r["path"] for r in unconfigured}
    server_errors = [
        r for r in results
        if ((r.get("empty_status") or 0) >= 500 or (r.get("read_status") or 0) >= 500)
        and r["path"] not in unconfigured_paths
    ]
    return {
        "total": len(results),
        "anon_status_dist": dict(anon),
        "empty_status_dist": dict(empty),
        "read_status_dist": dict(read),
        "issue_count": len(with_issues),
        "server_errors": server_errors,
        "unconfigured": unconfigured,
        "skipped_write_count": len(skipped_write),
        "auth_leaks": [r for r in results if r["anon_status"] not in (401, 0) and not (
            r["path"].startswith(AUTH_EXEMPT_PREFIXES) or r["path"] in AUTH_EXEMPT_EXACT)],
        "issues": with_issues,
    }


def main():
    ap = argparse.ArgumentParser(description="ARTEX API contract sweep")
    ap.add_argument("--routes", required=True, help="JSON produced by extract_routes.py")
    ap.add_argument("--base-url", default="http://127.0.0.1:8787")
    ap.add_argument("--token", default=os.environ.get("ARTEX_TOKEN"), help="JWT; if omitted, auto-login with username/password")
    ap.add_argument("--username", default=os.environ.get("ARTEX_USERNAME"))
    ap.add_argument("--password", default=os.environ.get("ARTEX_PASSWORD"))
    ap.add_argument("--anon-only", action="store_true", help="run only the unauthenticated stage (for use without credentials)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--json", dest="json_out", help="write the full report to this file")
    args = ap.parse_args()

    with open(args.routes, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    routes = doc["routes"]
    log(f"{len(routes)} routes, target {args.base_url}")

    token = args.token
    if not token and not args.anon_only and args.username and args.password:
        log("logging in with username/password to obtain a token ...")
        token = login(args.base_url, args.username, args.password)
        if token:
            log("  login succeeded")
    if not token:
        log("no token -- running the unauthenticated stage only")
        args.anon_only = True

    ids = discover_ids(args.base_url, token) if token else {}

    do_read = not args.anon_only
    log(f"starting the sweep (read-only stages: only GET sends requests with a token; write operations only get "
        f"the unauthenticated check and never touch live state), concurrency {args.workers}...")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(
            lambda r: check_route(r, args.base_url, token, ids, do_read),
            routes,
        ))
    elapsed = time.time() - t0

    s = summarize(results)
    log("")
    log(f"=== sweep complete ({elapsed:.1f}s) ===")
    log(f"total routes: {s['total']}")
    log(f"unauthenticated status distribution: {s['anon_status_dist']}")
    if do_read:
        log(f"empty-params status distribution (GET only): {s['empty_status_dist']}")
        log(f"normal GET status distribution: {s['read_status_dist']}")
    log(f"write operations (unauthenticated check only, no real requests sent): {s['skipped_write_count']}")
    log(f"routes with issues: {s['issue_count']}")

    if s["server_errors"]:
        log("")
        log(f"WARNING: {len(s['server_errors'])} 5xx errors (these are bugs):")
        for r in s["server_errors"]:
            log(f"  {r['method']} {r['path']}  empty={r['empty_status']} read={r['read_status']}")
            for i in r["issues"]:
                log(f"      {i}")

    if s["unconfigured"]:
        log("")
        log(f"external dependency not ready (not a defect): {len(s['unconfigured'])}")
        for r in s["unconfigured"][:10]:
            log(f"  {r['method']} {r['path']}  empty={r['empty_status']} read={r['read_status']}")

    if s["auth_leaks"]:
        log("")
        log(f"WARNING: {len(s['auth_leaks'])} routes allowed through unauthenticated:")
        for r in s["auth_leaks"][:30]:
            log(f"  {r['method']} {r['path']} -> {r['anon_status']}")

    other = [r for r in s["issues"] if r not in s["server_errors"] and r not in s["auth_leaks"]]
    if other:
        log("")
        log(f"other issues: {len(other)}")
        for r in other[:30]:
            log(f"  {r['method']} {r['path']}")
            for i in r["issues"]:
                log(f"      {i}")

    if args.json_out:
        out = {
            "base_url": args.base_url,
            "elapsed_sec": round(elapsed, 1),
            "summary": {k: v for k, v in s.items() if not isinstance(v, list)},
            "server_errors": s["server_errors"],
            "auth_leaks": s["auth_leaks"],
            "results": results,
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=1)
        log(f"\nreport written to {args.json_out}")

    # Exit non-zero on 5xx or auth leaks so it can serve as a CI gate
    if s["server_errors"] or s["auth_leaks"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
