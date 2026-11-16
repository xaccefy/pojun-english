"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  ClipboardPasteIcon,
  FlaskConicalIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  Trash2Icon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ProxyPoolEntry, ProxyPoolRunning } from "@/lib/types";

const STRATEGY_LABEL: Record<string, string> = {
  round_robin: "Round robin (by weight)",
  sticky_host: "Sticky by target (fixed egress per target)",
  sticky_host_random: "Sticky by target (random on first use)",
  random: "Random",
};

type CheckRow = {
  index: number;
  url: string;
  ok: boolean;
  latency_ms: number;
  exit_ip?: string;
  error?: string;
  checked_at: string;
};

// System → Proxy pool: multi-upstream egress config (round-robin/sticky/random), per-entry enable/disable and weights.
// Saving applies live (the upstream hook picks a proxy per request); 5 consecutive failures auto-trip the circuit breaker for 10 minutes,
// plus a proactive health check that verifies on a schedule and trips the breaker when unreachable.
export default function ProxyPoolPage() {
  const [entries, setEntries] = React.useState<ProxyPoolEntry[]>([]);
  const [strategy, setStrategy] = React.useState("round_robin");
  const [running, setRunning] = React.useState<ProxyPoolRunning[]>([]);
  const [capturing, setCapturing] = React.useState(false);
  const [checkTarget, setCheckTarget] = React.useState("");
  const [healthMinutes, setHealthMinutes] = React.useState(10);
  const [lastCheck, setLastCheck] = React.useState<{
    at: string;
    target: string;
    count: number;
    ok_count: number;
    auto?: boolean;
  } | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [checking, setChecking] = React.useState(false);
  const [checkRows, setCheckRows] = React.useState<CheckRow[]>([]);
  const [bulkOpen, setBulkOpen] = React.useState(false);
  const [bulkText, setBulkText] = React.useState("");
  const [bulkMode, setBulkMode] = React.useState<"append" | "replace">("append");

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .proxyPoolGet()
      .then((r) => {
        setEntries(r.entries ?? []);
        setStrategy(r.strategy || "round_robin");
        setRunning(r.running ?? []);
        setCapturing(r.capturing);
        setCheckTarget(r.check_target ?? "");
        setHealthMinutes(r.health_minutes ?? 10);
        setLastCheck(r.last_check ?? null);
      })
      .catch((e) => toast.error("Load failed: " + e))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(load, [load]);

  const save = async () => {
    setSaving(true);
    try {
      await api.proxyPoolPut({ entries, strategy });
      toast.success("Proxy pool saved and applied live");
      load();
    } catch (e) {
      toast.error("Save failed: " + e);
    } finally {
      setSaving(false);
    }
  };

  const update = (i: number, patch: Partial<ProxyPoolEntry>) => {
    setEntries((prev) => prev.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  };

  const failuresByURL = React.useMemo(() => {
    const m: Record<string, ProxyPoolRunning> = {};
    for (const r of running) m[r.url] = r;
    return m;
  }, [running]);

  // Dead = circuit-broken (passive consecutive failures or proactive health check marked unreachable).
  const deadURLs = React.useMemo(
    () => new Set(running.filter((r) => (r.break_remaining ?? 0) > 0).map((r) => r.url)),
    [running],
  );

  const runCheck = async (urls?: string[]) => {
    setChecking(true);
    try {
      const res = await api.proxyPoolCheck({
        urls,
        target: checkTarget || undefined,
        break_on_fail: true,
      });
      setCheckRows(res.results ?? []);
      const ok = (res.results ?? []).filter((r) => r.ok).length;
      const total = (res.results ?? []).length;
      if (total === 0) {
        toast.warning("No entries to verify (pool is empty or all disabled)");
      } else {
        toast.success(`Verification complete: ${ok}/${total} available, unreachable ones circuit-broken`);
      }
      load();
    } catch (e) {
      toast.error("Verification failed: " + e);
    } finally {
      setChecking(false);
    }
  };

  const doBulk = async () => {
    try {
      const res = await api.proxyPoolBulk({ text: bulkText, mode: bulkMode });
      const bad = res.invalid?.length ?? 0;
      toast.success(
        `Import complete: added ${res.added}, updated ${res.updated}` + (bad ? `, ${bad} invalid rows` : ""),
      );
      setBulkOpen(false);
      setBulkText("");
      load();
    } catch (e) {
      toast.error("Import failed: " + e);
    }
  };

  const removeDead = () => {
    if (deadURLs.size === 0) {
      toast.info("No dead entries");
      return;
    }
    setEntries((prev) => prev.filter((e) => !deadURLs.has(e.url)));
    toast.success(`Removed ${deadURLs.size} dead entries, remember to click "Save & apply live"`);
  };

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold">Proxy Pool</h1>
          <Badge variant={entries.length > 0 ? "default" : "secondary"}>
            {entries.length > 0 ? `${entries.length} upstreams` : "Not enabled (direct / global proxy)"}
          </Badge>
          {deadURLs.size > 0 && (
            <Badge variant="destructive">
              {deadURLs.size} unavailable
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Dialog open={bulkOpen} onOpenChange={setBulkOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <ClipboardPasteIcon className="mr-1 size-4" />
                Bulk import
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-2xl">
              <DialogHeader>
                <DialogTitle>Bulk Import Proxies</DialogTitle>
                <DialogDescription>
                  One per line. Auto-detects <code>1.2.3.4:8080</code>,
                  {" "}<code>http://…</code>, <code>socks5://user:pass@…</code>,
                  {" "}<code>1.2.3.4:8080:user:pass</code>; lines starting with <code>#</code> are comments;
                  <code>name | address</code> sets a name. Omitted schemes default to http.
                </DialogDescription>
              </DialogHeader>
              <Textarea
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                rows={12}
                className="font-mono text-xs"
                placeholder={"# Name | Address\nHK-01 | 1.2.3.4:8080\nsocks5://user:pass@5.6.7.8:1080\n10.0.0.1:3128:user:pass"}
              />
              <div className="flex items-center gap-3">
                <Label className="text-xs">Import mode</Label>
                <Select
                  value={bulkMode}
                  onValueChange={(v) => setBulkMode(v as "append" | "replace")}
                >
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="append">Append to existing list</SelectItem>
                    <SelectItem value="replace">Replace entire list</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button variant="outline" size="sm" onClick={() => setBulkOpen(false)}>
                  Cancel
                </Button>
                <Button size="sm" onClick={doBulk} disabled={!bulkText.trim()}>
                  Import
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={"mr-1 size-4" + (loading ? " animate-spin" : "")} />
            Refresh
          </Button>
          <Button size="sm" onClick={save} disabled={saving}>
            <SaveIcon className="mr-1 size-4" />
            Save & apply live
          </Button>
        </div>
      </div>

      {!capturing && (
        <p className="text-sm text-amber-500">
          Note: the proxy pool has no effect when traffic capture is off (worker traffic must go through the capture proxy :8788 to use egress rotation).
        </p>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Rotation strategy</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Select value={strategy} onValueChange={setStrategy}>
            <SelectTrigger className="w-72">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="round_robin">Round robin (by weight)</SelectItem>
              <SelectItem value="sticky_host">Sticky by target (fixed egress per target)</SelectItem>
              <SelectItem value="sticky_host_random">Sticky by target (random on first use)</SelectItem>
              <SelectItem value="random">Random</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            5 consecutive failures auto-trip the breaker for 10 minutes; a non-empty pool takes priority over the "global egress proxy".
            "Random on first use" = pick a random egress for a target the first time and stick to it, switching automatically if that egress dies.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Health checks & verification</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="check-target" className="text-xs">
                Probe URL
              </Label>
              <Input
                id="check-target"
                className="w-72"
                value={checkTarget}
                onChange={(e) => setCheckTarget(e.target.value)}
                placeholder="https://api.ipify.org?format=json"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="health-min" className="text-xs">
                Auto-check interval (minutes, 0 = off)
              </Label>
              <Input
                id="health-min"
                type="number"
                min={0}
                className="w-32"
                value={healthMinutes}
                onChange={(e) => setHealthMinutes(Math.max(0, Number(e.target.value) || 0))}
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => runCheck()} disabled={checking}>
              <FlaskConicalIcon className={"mr-1 size-4" + (checking ? " animate-pulse" : "")} />
              Verify all
            </Button>
            {deadURLs.size > 0 && (
              <Button variant="outline" size="sm" onClick={removeDead}>
                <Trash2Icon className="mr-1 size-4" />
                Remove dead entries
              </Button>
            )}
          </div>
          {lastCheck && (
            <p className="text-xs text-muted-foreground">
              Last check: {new Date(lastCheck.at).toLocaleString()} · {lastCheck.ok_count}/{lastCheck.count} available
              {lastCheck.auto ? " (automatic)" : ""} · probe {lastCheck.target}
            </p>
          )}
          {checkRows.length > 0 && (
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="py-2 pr-4 font-medium">Egress</th>
                    <th className="py-2 pr-4 font-medium">Result</th>
                    <th className="py-2 pr-4 font-medium">Latency</th>
                    <th className="py-2 pr-4 font-medium">Egress IP</th>
                    <th className="py-2 pr-4 font-medium">Error</th>
                  </tr>
                </thead>
                <tbody>
                  {checkRows.map((r) => (
                    <tr key={r.url} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-mono text-xs">{r.url}</td>
                      <td className="py-2 pr-4">
                        {r.ok ? (
                          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                            <CheckCircle2Icon className="size-4" /> Available
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-destructive">
                            <XCircleIcon className="size-4" /> Unavailable
                          </span>
                        )}
                      </td>
                      <td className="py-2 pr-4 tabular-nums">{r.latency_ms} ms</td>
                      <td className="py-2 pr-4 font-mono text-xs">{r.exit_ip ?? "—"}</td>
                      <td className="py-2 pr-4 text-destructive text-xs">{r.error ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2 flex-row flex items-center justify-between space-y-0">
          <CardTitle className="text-sm font-medium">Upstream proxies</CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setEntries((p) => [...p, { url: "", name: "", enabled: true, weight: 1 }])}
          >
            <PlusIcon className="mr-1 size-4" />
            Add
          </Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {entries.length === 0 && (
            <p className="py-3 text-sm text-muted-foreground">
              No entries yet. Use "Bulk import" to paste a whole proxy list at once, or click "Add" to enter them one by one
              (http/https/socks5, with user:pass support).
            </p>
          )}
          {entries.map((e, i) => {
            const live = failuresByURL[e.url];
            const dead = deadURLs.has(e.url);
            return (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <Input
                  className="flex-1 font-mono text-xs"
                  placeholder="socks5://user:pass@1.2.3.4:1080"
                  value={e.url}
                  onChange={(ev) => update(i, { url: ev.target.value })}
                />
                <Input
                  className="w-36"
                  placeholder="Name (optional)"
                  value={e.name}
                  onChange={(ev) => update(i, { name: ev.target.value })}
                />
                <div className="flex items-center gap-1">
                  <span className="text-xs text-muted-foreground">Weight</span>
                  <Input
                    className="w-16"
                    type="number"
                    min={1}
                    value={e.weight}
                    onChange={(ev) => update(i, { weight: Math.max(1, Number(ev.target.value) || 1) })}
                  />
                </div>
                <Switch checked={e.enabled} onCheckedChange={(v) => update(i, { enabled: v })} />
                {dead && (
                  <Badge variant="destructive" title={live?.last_fail}>
                    <AlertTriangleIcon className="mr-1 size-3" />
                    Breaker {live?.break_remaining}s
                  </Badge>
                )}
                {!dead && live && live.failures > 0 && <Badge variant="destructive">{live.failures} consecutive fails</Badge>}
                {!dead && live?.last_ok && (
                  <Badge variant="secondary" title={`Last success ${live.last_ok}`}>
                    Available
                  </Badge>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setEntries((p) => p.filter((_, j) => j !== i))}
                >
                  <Trash2Icon className="size-4" />
                </Button>
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
