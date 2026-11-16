#!/usr/bin/env python3
"""Capture full-page PNG screenshots of a running site with headless Chromium.

Uses the DevTools protocol over a websocket so the page can settle on real time
(the client-rendered screens fetch their data from the API before they paint,
which --virtual-time-budget based captures cut short).

Usage:
    python3 scripts/shoot.py --out DIR [--size WxH] URL NAME [URL NAME ...]
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request

import websockets

CHROME = "chromium"
PORT = 9334


def start_chrome():
    proc = subprocess.Popen(
        [
            CHROME, "--headless", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
            "--disable-dev-shm-usage", "--force-prefers-reduced-motion",
            "--remote-debugging-port=" + str(PORT),
            "--user-data-dir=/tmp/opencode/chrome-profile",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/version", timeout=1)
            return proc
        except Exception:
            time.sleep(0.25)
    proc.kill()
    raise SystemExit("chromium did not expose the devtools endpoint")


def new_target(url):
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/json/new?{url}", method="PUT"
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def close_target(target_id):
    try:
        urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/json/close/{target_id}", timeout=5
        )
    except Exception:
        pass


async def shoot(ws_url, url, out_path, width, height, wait_text, settle):
    async with websockets.connect(ws_url, max_size=64 * 1024 * 1024) as ws:
        counter = [0]

        async def cmd(method, params=None, wait=True):
            counter[0] += 1
            mid = counter[0]
            await ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
            if not wait:
                return None
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == mid:
                    if "error" in msg:
                        raise RuntimeError(f"{method}: {msg['error']}")
                    return msg.get("result", {})

        await cmd("Page.enable")
        await cmd("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": height, "deviceScaleFactor": 1, "mobile": False,
        })
        await cmd("Page.navigate", {"url": url})
        deadline = time.time() + settle
        while time.time() < deadline:
            try:
                res = await cmd("Runtime.evaluate", {
                    "expression": "document.body ? document.body.innerText : ''",
                    "returnByValue": True,
                })
                text = (res.get("result") or {}).get("value") or ""
                if wait_text and wait_text not in text:
                    await asyncio.sleep(0.4)
                    continue
                if not wait_text:
                    await asyncio.sleep(1.0)
                if wait_text:
                    break
                break
            except Exception:
                await asyncio.sleep(0.4)
        await asyncio.sleep(0.8)
        shot = await cmd("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        data = shot.get("data")
        if not data:
            raise RuntimeError("no screenshot data")
        import base64
        with open(out_path, "wb") as fh:
            fh.write(base64.b64decode(data))


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--size", default="1600x900")
    ap.add_argument("--settle", type=float, default=8.0)
    ap.add_argument("--wait-text", default="")
    ap.add_argument("pairs", nargs="+", help="URL NAME pairs")
    args = ap.parse_args()
    w, h = (int(x) for x in args.size.lower().split("x"))
    os.makedirs(args.out, exist_ok=True)
    proc = start_chrome()
    try:
        for i in range(0, len(args.pairs), 2):
            url, name = args.pairs[i], args.pairs[i + 1]
            target = new_target(url)
            out = os.path.join(args.out, name)
            try:
                await shoot(target["webSocketDebuggerUrl"], url, out, w, h, args.wait_text, args.settle)
                print(f"  OK   {name}  ({os.path.getsize(out)} bytes)")
            except Exception as exc:
                print(f"  FAIL {name}: {exc}")
            finally:
                close_target(target["id"])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    asyncio.run(main())
