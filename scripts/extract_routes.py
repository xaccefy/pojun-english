#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract all of ARTEX's API routes from the Go source.

ARTEX uses net/http's ServeMux (Go 1.22+ supports the "METHOD /path/{wildcard}" pattern).
Route registrations are scattered across several files under server/, and the vast majority are literals:

    mux.HandleFunc("GET /api/tasks", s.listTasks)

A few are assembled from variables (the base in finding_traffic.go):

    base := "/api/exploration/findings/{id}/traffic"
    mux.HandleFunc("PATCH "+base+"/{binding_id}", s.editFindingTraffic)

This script handles both forms and outputs a JSON route table for the contract test to consume.
"""

import json
import os
import re
import sys

# mux.HandleFunc("METHOD <path expr>", handler)
HANDLE_RE = re.compile(
    r'mux\.HandleFunc\(\s*"(?P<method>[A-Z]+)\s+(?P<path>[^"]*)"\s*(?:\+\s*(?P<plus>[^,]+?))?\s*,\s*(?P<handler>[A-Za-z0-9_.]+)\s*\)'
)

# base := "/api/..."
BASE_RE = re.compile(r'\bbase\s*:?=\s*"(?P<value>/api[^"]*)"')

# Registrations in var form (not handled for now, but they must be reported)
VAR_RE = re.compile(r'mux\.HandleFunc\(\s*(?P<expr>[^,]+?)\s*,\s*(?P<handler>[A-Za-z0-9_.]+)\s*\)')


def extract_from_file(path):
    """Extract routes from one Go file. Returns (routes, unresolved)."""
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()

    # First collect the base variables in this file
    bases = {m.group("value") for m in BASE_RE.finditer(src)}

    routes = []
    unresolved = []

    for m in HANDLE_RE.finditer(src):
        method = m.group("method")
        path = m.group("path")
        plus = m.group("plus")
        handler = m.group("handler")
        if plus:
            # Of the form "PATCH " + base + "/{binding_id}"
            expr = f'"{method} {path}" + {plus}'
            resolved = None
            for b in bases:
                # Substitute the base variable in; plus may also contain literal concatenation
                candidate = plus.replace("base", f'"{b}"')
                # candidate now looks like ""/api/.../traffic" + "/{binding_id}"
                parts = re.findall(r'"([^"]*)"', candidate)
                if parts:
                    resolved = "".join(parts)
            if resolved is None:
                unresolved.append({"expr": expr, "handler": handler, "file": os.path.basename(path)})
                continue
            path = resolved
        routes.append({"method": method, "path": path, "handler": handler, "file": os.path.basename(path)})

    # Find registration forms we failed to parse and report them rather than silently missing them
    for m in VAR_RE.finditer(src):
        expr = m.group("expr").strip()
        if expr.startswith('"') and " " in expr:
            continue  # already covered by HANDLE_RE
        # Try concatenating the base once more
        parts = re.findall(r'"([^"]*)"', expr)
        if parts:
            joined = "".join(parts)
            if joined.startswith("/api") or " " in joined:
                mm = re.match(r'([A-Z]+)\s+(/api.*)$', joined)
                if mm:
                    routes.append({
                        "method": mm.group(1),
                        "path": mm.group(2),
                        "handler": m.group("handler"),
                        "file": os.path.basename(path),
                    })
                    continue
        unresolved.append({"expr": expr, "handler": m.group("handler"), "file": os.path.basename(path)})

    return routes, unresolved


def main():
    server_dir = sys.argv[1] if len(sys.argv) > 1 else "server"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "routes.json"

    all_routes = []
    all_unresolved = []
    for name in sorted(os.listdir(server_dir)):
        if not name.endswith(".go") or name.endswith("_test.go"):
            continue
        r, u = extract_from_file(os.path.join(server_dir, name))
        all_routes.extend(r)
        all_unresolved.extend(u)

    # Deduplicate (keep the first when the same method+path is registered multiple times)
    seen = set()
    deduped = []
    for r in all_routes:
        key = (r["method"], r["path"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    deduped.sort(key=lambda r: (r["path"], r["method"]))

    doc = {
        "count": len(deduped),
        "routes": deduped,
        "unresolved": all_unresolved,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)

    print(f"extracted {len(deduped)} routes -> {out_path}")
    if all_unresolved:
        print(f"WARNING: {len(all_unresolved)} unresolved (need manual confirmation):")
        for u in all_unresolved:
            print(f"  {u['file']}: {u['expr']} -> {u['handler']}")


if __name__ == "__main__":
    main()
