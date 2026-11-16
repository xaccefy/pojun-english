#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARTEX page-sweep helper.

Used together with the chrome-devtools MCP: this list gives the pages to visit, the DOM anchors to check on
each page (to tell whether the page actually rendered rather than being stuck on loading / an error page),
and where screenshots are stored.

Usage (executed by Claude through the chrome-devtools tools):
    1. browser_navigate to each url
    2. browser_take_snapshot to get the a11y tree -> check the key elements against anchors
    3. browser_take_screenshot into screenshots/<name>.png
    4. browser_console_messages to collect console errors

The page list doubles as the baseline for "which pages exist and what each page should contain".
"""

import json
import os
import sys

# (name, path, key text/role anchors that must be present)
# anchors are judged by "text that should be visible on the page", which survives frontend refactors better than selectors.
# NOTE: the anchor strings are literal on-screen text and stay in the language the UI actually renders.
PAGES = [
    ("login",           "/login",                      ["ARTEX", "Password"]),
    ("dashboard",       "/dashboard",                  []),
    ("tasks",           "/function/tasks",             ["Tasks"]),
    ("task-detail",     "/function/tasks/detail?id=1",  []),
    ("assets",          "/function/assets",            []),
    ("findings",        "/function/findings",          []),
    ("finding-detail",  "/function/findings/detail?id=1", []),
    ("traffic",         "/function/traffic",           []),
    ("commands",        "/function/commands",          []),
    ("llm-records",     "/function/llm-records",       []),
    ("sync",            "/function/sync",              []),
    ("workspace",       "/function/workspace",         []),
    ("chat",            "/chat",                       []),
    ("agents",          "/system/agents",              []),
    ("agent-detail",    "/system/agents/detail?key=worker", []),
    ("hostenv",         "/system/hostenv",             []),
    ("intercept",       "/system/intercept",           []),
    ("intercept-approvals", "/system/intercept/approvals", []),
    ("intercept-assets",    "/system/intercept/assets",    []),
    ("llm",             "/system/llm",                 []),
    ("logs",            "/system/logs",                []),
    ("mcp",             "/system/mcp",                 []),
    ("notify",          "/system/notify",              []),
    ("proxypool",       "/system/proxypool",           []),
    ("settings",        "/system/settings",            []),
    ("skills",          "/system/skills",              []),
    ("tools",           "/system/tools",               []),
    ("vulnintel",       "/system/vulnintel",           []),
]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "pages.json"
    base = os.environ.get("ARTEX_BASE", "http://10.10.70.17:8787")
    doc = {
        "base": base,
        "count": len(PAGES),
        "pages": [
            {"name": n, "url": base + p, "path": p, "anchors": a}
            for (n, p, a) in PAGES
        ],
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    print(f"{len(PAGES)} pages -> {out}")
    for n, p, _ in PAGES:
        print(" ", n, p)


if __name__ == "__main__":
    main()
