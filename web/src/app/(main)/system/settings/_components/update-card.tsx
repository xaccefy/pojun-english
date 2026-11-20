"use client";

import * as React from "react";

import {
  CheckCircle2Icon,
  DownloadIcon,
  ExternalLinkIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  TriangleAlertIcon,
} from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { api, sseUrl } from "@/lib/api";
import type { UpdateCheck, UpdateProgress } from "@/lib/types";

/** Maximum time to wait for the new version to come online. One upgrade goes through three process
 *  starts (staging → swap → new version), each on the order of seconds; three minutes is enough to
 *  cover slow disks and Docker container rebuilds. */
const RESTART_TIMEOUT_MS = 180_000;

function humanSize(n?: number): string {
  if (!n || n <= 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function UpdateCard() {
  const [info, setInfo] = React.useState<UpdateCheck | null>(null);
  const [checking, setChecking] = React.useState(true);
  const [progress, setProgress] = React.useState<UpdateProgress | null>(null);
  // Kept separate from progress: after staging completes the process is gone and SSE drops, so switch to polling /api/health.
  const [restarting, setRestarting] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  // `quiet` also decides whether to bypass the backend cache: the automatic check on page entry
  // uses the cache (the top bar just checked), while a manual "Check for updates" click forces a
  // fresh fetch — otherwise a just-published version would stay invisible until the cache expires.
  const check = React.useCallback((quiet = false) => {
    setChecking(true);
    api
      .checkUpdate(!quiet)
      .then((r) => {
        setInfo(r);
        if (!quiet) {
          if (r.error) toast.error(`Update check failed: ${r.error}`);
          else if (r.has_update) toast.success(`New version ${r.latest} available`);
          else if (r.comparable) toast.success("You are on the latest version");
        }
      })
      .catch((e) => {
        if (!quiet) toast.error(`Update check failed: ${(e as Error).message}`);
      })
      .finally(() => setChecking(false));
  }, []);

  React.useEffect(() => {
    check(true);
  }, [check]);

  // Poll /api/version (authenticated) until the version number changes.
  //
  // The criterion must be "the version changed", not "it's reachable": during the swap the old
  // version briefly comes back up once (that run only swaps in pojun.new and exits immediately),
  // so checking mere connectivity would falsely report success.
  const waitForNewVersion = React.useCallback(async (fromVersion: string) => {
    setRestarting(true);
    const deadline = Date.now() + RESTART_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await sleep(2000);
      try {
        // /api/health is de-identified (public fingerprint hardening): version queries go through the authenticated /api/version.
        const r = await fetch("/api/version", { cache: "no-store" });
        if (r.ok) {
          const j = (await r.json()) as { version?: string };
          if (j.version && j.version !== fromVersion) {
            toast.success(`Updated to ${j.version}, reloading the page`);
            await sleep(800);
            window.location.reload();
            return;
          }
        }
      } catch {
        // Being unreachable during the restart window is expected; keep polling.
      }
    }
    setRestarting(false);
    toast.error("Timed out waiting for the service to restart. Check the backend logs, or confirm pojun was started via start.sh / start.bat.");
  }, []);

  // Subscribe to update progress. SSE doesn't go through Next's /api rewrite (that layer buffers, so events can't be pushed).
  const openStream = React.useCallback(
    (fromVersion: string) => {
      const es = new EventSource(sseUrl("/api/update/stream"));
      es.onmessage = (ev) => {
        let p: UpdateProgress;
        try {
          p = JSON.parse(ev.data) as UpdateProgress;
        } catch {
          return;
        }
        setProgress(p);
        if (p.phase === "failed") {
          es.close();
          setBusy(false);
          toast.error(`Update failed: ${p.error || p.message}`);
          return;
        }
        if (p.phase === "staged") {
          es.close();
          void waitForNewVersion(fromVersion);
        }
      };
      es.onerror = () => {
        // SSE inevitably drops when the process exits. If we've already entered the restart-wait
        // phase, that's normal — let the /api/health polling continue the determination.
        es.close();
      };
      return es;
    },
    [waitForNewVersion],
  );

  const doUpdate = () => {
    if (!info) return;
    const from = info.current;
    const ok = window.confirm(
      `Update to ${info.latest}?\n\n` +
        "The update restarts the program and will interrupt running tasks.\n" +
        (info.mode === "docker"
          ? "\nNote: updating inside a container only replaces the program itself; it does not update " +
            "toolchains like playwright / nmap in the image. If the new version needs new tools, use docker compose pull instead."
          : ""),
    );
    if (!ok) return;

    setBusy(true);
    setProgress({ phase: "downloading", percent: 0, message: "Preparing…" });
    const es = openStream(from);
    api.applyUpdate().catch((e) => {
      es.close();
      setBusy(false);
      setProgress(null);
      toast.error(`Failed to start update: ${(e as Error).message}`);
    });
  };

  const doRollback = () => {
    if (!info) return;
    if (
      !window.confirm(
        "Roll back to the previous version?\n\nThe program will restart and running tasks will be interrupted.\nNote: the database schema is not rolled back, so the old version may not recognize data written by the new one.",
      )
    )
      return;
    const from = info.current;
    setBusy(true);
    api
      .rollbackUpdate()
      .then(() => {
        toast.success("Switched to the previous version, restarting…");
        void waitForNewVersion(from);
      })
      .catch((e) => {
        setBusy(false);
        toast.error(`Rollback failed: ${(e as Error).message}`);
      });
  };

  const phase = progress?.phase;
  const showProgress = busy || restarting;
  // Only the download phase yields a real percentage (computed from Content-Length). Verification,
  // extraction, and restart-waiting are all phases of unknown duration; fill the bar and add a pulse
  // animation to mean "busy, but no ETA".
  const downloading = !restarting && phase === "downloading";
  const pct = downloading ? Math.max(progress?.percent ?? 0, 0) : 100;

  return (
    // The settings page uses a multi-column masonry layout; each card handles its own row spacing and prevents column breaks (see the comment in page.tsx).
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <DownloadIcon className="size-4" />
          Version and updates
        </CardTitle>
        <CardDescription>Check for and install new versions from GitHub. Updating restarts the program and will interrupt running tasks.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">Current version</span>
          <Badge variant="secondary" className="font-mono">
            {info?.current ?? "…"}
          </Badge>
          {info && (
            <>
              <Badge variant="outline" className="font-mono">
                {info.os}/{info.arch}
              </Badge>
              <Badge variant="outline">{info.mode === "docker" ? "Docker" : "Standalone"}</Badge>
            </>
          )}
          {info?.latest && (
            <>
              <span className="text-muted-foreground">Latest version</span>
              <Badge variant={info.has_update ? "default" : "secondary"} className="font-mono">
                {info.latest}
              </Badge>
            </>
          )}
          {info?.html_url && (
            <a
              href={info.html_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-muted-foreground text-xs underline-offset-4 hover:underline"
            >
              Changelog <ExternalLinkIcon className="size-3" />
            </a>
          )}
        </div>

        {info?.boot_notice && (
          <p className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-amber-700 text-xs dark:text-amber-400">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            {info.boot_notice}
          </p>
        )}

        {info?.error && (
          <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-destructive text-xs">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            Cannot connect to GitHub: {info.error}
            {"  "}Configure a global proxy above and retry.
          </p>
        )}

        <p className="text-muted-foreground text-xs">
          Checking and downloading updates prefers{" "}
          <Link href="/system/hostenv#install-proxy-settings" className="underline underline-offset-4">
            Host environment → Install proxy
          </Link>
          {" "}(it can also come from <code>POJUN_INSTALL_PROXY</code>). The global proxy is only used when no install proxy is
          configured; with neither, the connection is direct.
          {info?.mode === "docker" &&
            " Under Docker bridge networking 127.0.0.1 points at the container itself — if the proxy runs on the host, enter an address the container can reach."}
        </p>

        {info && !info.comparable && info.reason && <p className="text-muted-foreground text-xs">{info.reason}</p>}

        {info?.has_update && info.asset_available === false && (
          <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-destructive text-xs">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            {info.latest} has no release package for {info.os}/{info.arch} (missing {info.asset}), so automatic update is unavailable.
          </p>
        )}

        {info?.has_update && info.asset_available !== false && (
          <p className="text-muted-foreground text-xs">
            Will download <span className="font-mono">{info.asset}</span>
            {info.size ? ` (${humanSize(info.size)})` : ""}; it will only be swapped in after SHA256 verification and a smoke test, with automatic fallback to the current version on failure.
          </p>
        )}

        {info && !info.has_update && info.comparable && !info.error && (
          <p className="flex items-center gap-2 text-muted-foreground text-xs">
            <CheckCircle2Icon className="size-3.5 text-emerald-600" />
            You are on the latest version.
          </p>
        )}

        {info?.mode === "docker" && info.has_update && (
          <p className="text-muted-foreground text-xs">
            Updating under Docker only replaces the program itself; it does not update toolchains like
            playwright / nmap in the image, and recreating the container with
            <span className="font-mono"> docker compose up -d </span>
            will revert to the version bundled in the image. To upgrade the image as well, run
            <span className="font-mono"> docker compose pull pojun &amp;&amp; docker compose up -d pojun</span>.
          </p>
        )}

        {showProgress && (
          <div className="space-y-1.5">
            <Progress value={pct} className={downloading ? undefined : "animate-pulse"} />
            <p className="text-muted-foreground text-xs">
              {restarting ? "Restarting and applying the new version, please wait (the page will refresh automatically)…" : progress?.message}
            </p>
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => check(false)} disabled={checking || busy || restarting}>
            <RefreshCwIcon className={checking ? "size-4 animate-spin" : "size-4"} />
            Check for updates
          </Button>
          <Button
            size="sm"
            onClick={doUpdate}
            disabled={busy || restarting || !info?.has_update || info?.asset_available === false}
          >
            <DownloadIcon className="size-4" />
            {info?.has_update ? `Update to ${info.latest}` : "Update now"}
          </Button>
          {info?.has_backup && (
            <Button variant="ghost" size="sm" onClick={doRollback} disabled={busy || restarting}>
              <RotateCcwIcon className="size-4" />
              Roll back
            </Button>
          )}
        </div>

        <p className="text-muted-foreground text-xs">
          One-click update relies on a watchdog script to restart the program. Start POJUN via
          <span className="font-mono"> start.sh</span> (on Windows,
          <span className="font-mono"> start.bat</span>); when running the pojun binary directly, it will not be relaunched automatically after exiting.
        </p>
      </CardContent>
    </Card>
  );
}
