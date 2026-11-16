"use client";

import * as React from "react";

import {
  ActivityIcon,
  DatabaseIcon,
  FolderGitIcon,
  Loader2Icon,
  PlugZapIcon,
  RefreshCwIcon,
  SaveIcon,
  ShieldAlertIcon,
  SquareIcon,
  TriangleAlertIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { VulnIntelStatus } from "@/lib/types";

const SOURCE_LABEL: Record<string, string> = {
  nvd: "NVD (CVE full/incremental)",
  kev: "CISA KEV (in-the-wild exploitation)",
  poc: "GitHub PoC aggregation",
};

type ProbeRow = {
  source: string;
  target: string;
  ok: boolean;
  status: number;
  latency_ms: number;
  error?: string;
  hint?: string;
};

function fmtTime(v?: string): string {
  if (!v) return "—";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return v;
  return d.toLocaleString();
}

// System → Vulnerability Intel: sync config + watermark + fault diagnosis + connectivity self-check + manual sync.
// This page used to be read-only, with failure reasons hidden in the badge's title and no config entry point at all—
// now config, diagnostics, and fix actions are all on one page.
export default function VulnintelPage() {
  const [status, setStatus] = React.useState<VulnIntelStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);
  const [cancelling, setCancelling] = React.useState(false);
  const [probing, setProbing] = React.useState(false);
  const [probeRows, setProbeRows] = React.useState<ProbeRow[]>([]);

  // Config draft: leaving credential fields blank = keep unchanged (to avoid losing the key just by clearing the input).
  const [nvdKey, setNvdKey] = React.useState("");
  const [ghToken, setGhToken] = React.useState("");
  const [proxy, setProxy] = React.useState("");
  const [pocEnabled, setPocEnabled] = React.useState(false);
  const [backfillDays, setBackfillDays] = React.useState(0);
  const [maxRuntimeMin, setMaxRuntimeMin] = React.useState(30);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .vulnintelStatus()
      .then((s) => {
        setStatus(s);
        setError("");
        const c = s.config;
        if (c) {
          setNvdKey("");
          setGhToken("");
          setProxy(c.proxy ?? "");
          setPocEnabled(!!c.poc_enabled);
          setBackfillDays(c.backfill_days ?? 0);
          setMaxRuntimeMin(c.max_runtime_minutes ?? 30);
        }
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(load, [load]);

  const saveConfig = async () => {
    setSaving(true);
    try {
      await api.vulnintelSaveConfig({
        enabled: status?.enabled,
        nvd_api_key: nvdKey.trim() || undefined,
        github_token: ghToken.trim() || undefined,
        proxy: proxy.trim(),
        poc_enabled: pocEnabled,
        backfill_days: backfillDays,
        max_runtime_minutes: maxRuntimeMin,
      });
      toast.success("Config saved, takes effect on the next sync");
      load();
    } catch (e) {
      toast.error("Save failed: " + e);
    } finally {
      setSaving(false);
    }
  };

  const syncNow = async () => {
    setSyncing(true);
    try {
      await api.vulnintelSyncNow();
      toast.success("Sync triggered; refresh later to see the watermark");
    } catch (e) {
      toast.error("Trigger failed: " + e);
    } finally {
      setSyncing(false);
    }
  };

  // Interrupt the current sync round: cancellation is cooperative; after clicking, the backend kills the NVD/git
  // subprocesses and the state is refreshed via polling.
  const cancelSync = async () => {
    setCancelling(true);
    try {
      await api.vulnintelSyncCancel();
      toast.success("Interrupt request sent, wrapping up");
    } catch (e) {
      toast.error("Interrupt failed: " + e);
    } finally {
      setCancelling(false);
    }
  };

  const probe = async () => {
    setProbing(true);
    try {
      const res = await api.vulnintelProbe();
      setProbeRows(res.results ?? []);
      const bad = (res.results ?? []).filter((r) => !r.ok).length;
      if (bad === 0) toast.success("All data sources are reachable");
      else toast.warning(`${bad} data source(s) unavailable; expand for fix suggestions`);
    } catch (e) {
      toast.error("Check failed: " + e);
    } finally {
      setProbing(false);
    }
  };

  const toggleEnabled = async (on: boolean) => {
    try {
      await api.vulnintelSaveConfig({ enabled: on });
      toast.success(on ? "Sync enabled" : "Sync disabled");
      load();
    } catch (e) {
      toast.error("Setting failed: " + e);
    }
  };

  const cfg = status?.config;

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlertIcon className="size-5" />
          <h1 className="text-lg font-semibold">Vulnerability Intel</h1>
          {status && (
            <Badge variant={status.enabled ? "default" : "secondary"}>
              {status.enabled ? "Sync on" : "Sync off"}
            </Badge>
          )}
          {status?.sync_running && (
            <Badge variant="outline" className="max-w-md">
              <Loader2Icon className="mr-1 size-3 shrink-0 animate-spin" />
              <span className="truncate">
                Sync in progress{status.sync_phase ? ` · ${status.sync_phase}` : ""}
              </span>
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={probe} disabled={probing}>
            <PlugZapIcon className={"mr-1 size-4" + (probing ? " animate-pulse" : "")} />
            Test connectivity
          </Button>
          {status?.sync_running && (
            <Button
              variant="outline"
              size="sm"
              className="text-destructive"
              onClick={cancelSync}
              disabled={cancelling}
            >
              <SquareIcon className="mr-1 size-4" />
              {cancelling ? "Interrupting…" : "Interrupt sync"}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={syncNow} disabled={syncing}>
            <RefreshCwIcon className={"mr-1 size-4" + (syncing ? " animate-spin" : "")} />
            Sync now
          </Button>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={"mr-1 size-4" + (loading ? " animate-spin" : "")} />
            Refresh
          </Button>
        </div>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {status && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                  <DatabaseIcon className="size-4" /> CVE records
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold tabular-nums">{status.counts.cves.toLocaleString()}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">KEV in the wild</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold tabular-nums text-red-500">{status.counts.kev.toLocaleString()}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">PoC repositories</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold tabular-nums">{status.counts.pocs.toLocaleString()}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Sync config</CardTitle>
              <CardDescription className="text-xs">
                Credentials are write-only: leaving a field blank keeps the current value. After editing, click "Save config"; it takes effect on the next sync.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-3">
                <Switch checked={!!status.enabled} onCheckedChange={toggleEnabled} id="vi-enabled" />
                <Label htmlFor="vi-enabled" className="text-sm">
                  Enable scheduled sync
                </Label>
                <span className="text-muted-foreground text-xs">{status.next_tick_hint}</span>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-nvd" className="text-xs">
                    NVD API Key{cfg?.nvd_key_set ? " (configured)" : " (not configured)"}
                  </Label>
                  <Input
                    id="vi-nvd"
                    type="password"
                    value={nvdKey}
                    onChange={(e) => setNvdKey(e.target.value)}
                    placeholder={cfg?.nvd_key_set ? "••••••••" : "blank = anonymous (5 per 30s)"}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-gh" className="text-xs">
                    GitHub Token{cfg?.github_token_set ? " (configured)" : " (not configured)"}
                  </Label>
                  <Input
                    id="vi-gh"
                    type="password"
                    value={ghToken}
                    onChange={(e) => setGhToken(e.target.value)}
                    placeholder={cfg?.github_token_set ? "••••••••" : "blank = anonymous (PoC aggregation is rate-limited)"}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-proxy" className="text-xs">
                    Dedicated sync proxy (blank = follow maintenance proxy)
                  </Label>
                  <Input
                    id="vi-proxy"
                    value={proxy}
                    onChange={(e) => setProxy(e.target.value)}
                    placeholder={cfg?.maintenance_proxy || "http://127.0.0.1:7897"}
                  />
                  {cfg?.maintenance_proxy && (
                    <span className="text-muted-foreground text-xs">
                      Current maintenance proxy: {cfg.maintenance_proxy}
                    </span>
                  )}
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-backfill" className="text-xs">
                    Initial backfill days (0 = full)
                  </Label>
                  <Input
                    id="vi-backfill"
                    type="number"
                    min={0}
                    value={backfillDays}
                    onChange={(e) => setBackfillDays(Math.max(0, Number(e.target.value) || 0))}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-runtime" className="text-xs">
                    Per-round limit (minutes)
                  </Label>
                  <Input
                    id="vi-runtime"
                    type="number"
                    min={5}
                    value={maxRuntimeMin}
                    onChange={(e) => setMaxRuntimeMin(Math.max(5, Number(e.target.value) || 5))}
                  />
                </div>
                <div className="flex items-end gap-3">
                  <div className="flex items-center gap-2">
                    <Switch checked={pocEnabled} onCheckedChange={setPocEnabled} id="vi-poc" />
                    <Label htmlFor="vi-poc" className="text-sm">
                      Aggregate GitHub PoC repositories
                    </Label>
                  </div>
                </div>
              </div>

              <div className="flex justify-end">
                <Button size="sm" onClick={saveConfig} disabled={saving}>
                  <SaveIcon className="mr-1 size-4" />
                  Save config
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Sync status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="py-2 pr-4 font-medium">Data source</th>
                      <th className="py-2 pr-4 font-medium">Last sync</th>
                      <th className="py-2 pr-4 font-medium">Processed this round</th>
                      <th className="py-2 pr-4 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status.sources.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-3 text-muted-foreground">
                          Sync has not started yet (begins about 90 seconds after first launch; a full backfill takes several rounds)
                        </td>
                      </tr>
                    )}
                    {status.sources.map((s) => (
                      <tr key={s.source} className="border-b align-top last:border-0">
                        <td className="py-2 pr-4">{SOURCE_LABEL[s.source] ?? s.source}</td>
                        <td className="py-2 pr-4 tabular-nums">{fmtTime(s.last_sync_at)}</td>
                        <td className="py-2 pr-4 tabular-nums">{s.total_synced.toLocaleString()}</td>
                        <td className="py-2 pr-4">
                          {s.last_error ? (
                            <div className="space-y-1">
                              <Badge variant="destructive" className="gap-1">
                                <TriangleAlertIcon className="size-3" />
                                Has errors
                              </Badge>
                              <p className="max-w-xl text-muted-foreground text-xs">{s.last_error}</p>
                              {s.error_hint && (
                                <p className="max-w-xl text-xs text-amber-600 dark:text-amber-400">
                                  Suggestion: {s.error_hint}
                                </p>
                              )}
                            </div>
                          ) : (
                            <Badge variant="default">Normal</Badge>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <FolderGitIcon className="size-4" /> nuclei template library
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-muted-foreground text-xs">
                Directory: {status.nuclei?.dir || status.nuclei_templates_dir || "Not configured"}
              </p>
              {status.nuclei && (
                <>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="secondary">{status.nuclei.templates} templates</Badge>
                    {status.nuclei.is_git && <Badge variant="outline">git repository</Badge>}
                    {status.nuclei.updated_at && (
                      <span className="text-muted-foreground text-xs">
                        Last updated {fmtTime(status.nuclei.updated_at)}
                      </span>
                    )}
                  </div>
                  <p className="text-muted-foreground text-xs">{status.nuclei.hint}</p>
                </>
              )}
            </CardContent>
          </Card>

          {probeRows.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm font-medium">
                  <ActivityIcon className="size-4" /> Connectivity self-check
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left text-muted-foreground">
                        <th className="py-2 pr-4 font-medium">Data source</th>
                        <th className="py-2 pr-4 font-medium">Result</th>
                        <th className="py-2 pr-4 font-medium">Latency</th>
                        <th className="py-2 pr-4 font-medium">Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {probeRows.map((r) => (
                        <tr key={r.source} className="border-b align-top last:border-0">
                          <td className="py-2 pr-4">{SOURCE_LABEL[r.source] ?? r.source}</td>
                          <td className="py-2 pr-4">
                            {r.ok ? (
                              <Badge variant="default">OK {r.status}</Badge>
                            ) : (
                              <Badge variant="destructive">{r.status ? `HTTP ${r.status}` : "Failed"}</Badge>
                            )}
                          </td>
                          <td className="py-2 pr-4 tabular-nums">{r.latency_ms} ms</td>
                          <td className="py-2 pr-4 text-xs">
                            {r.error && <p className="text-destructive">{r.error}</p>}
                            {r.hint && <p className="text-amber-600 dark:text-amber-400">{r.hint}</p>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
