"use client";

import * as React from "react";
import Link from "next/link";

import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  ClipboardPasteIcon,
  DownloadIcon,
  FlaskConicalIcon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  SquareIcon,
  Trash2Icon,
  WifiIcon,
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
import type {
  LocalProxyCandidate,
  MihomoStatus,
  ProxyPoolEntry,
  ProxyPoolRunning,
  ProxyPoolSubscription,
} from "@/lib/types";

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
  // Strict egress (off by default, the public build keeps the old behavior; toggleable in the UI):
  // with a pool configured but fully unusable, fail the target request instead of falling back to direct.
  const [strict, setStrict] = React.useState(false);
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
  // Bulk selection stored by index and cleared after load/save/delete (indices shift).
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [bulkOpen, setBulkOpen] = React.useState(false);
  const [subOpen, setSubOpen] = React.useState(false);
  const [subURL, setSubURL] = React.useState("");
  const [subLoading, setSubLoading] = React.useState(false);
  const [subResult, setSubResult] = React.useState<ProxyPoolSubscription | null>(null);
  // Outbound group: which proxy-group Clash MATCHes to (empty = the first group by default).
  const [outbound, setOutbound] = React.useState("");
  const [mihomo, setMihomo] = React.useState<MihomoStatus | null>(null);
  const [mihomoBusy, setMihomoBusy] = React.useState(false);
  // Install sources: official GitHub assets often fail on restricted networks, so offer two routes — a mirror URL or a local file on the server.
  const [installSrcOpen, setInstallSrcOpen] = React.useState(false);
  const [installURL, setInstallURL] = React.useState("");
  const [installSHA, setInstallSHA] = React.useState("");
  const [installPath, setInstallPath] = React.useState("");
  const [localBusy, setLocalBusy] = React.useState(false);
  const [localCandidates, setLocalCandidates] = React.useState<LocalProxyCandidate[]>([]);
  const [bulkText, setBulkText] = React.useState("");
  const [bulkMode, setBulkMode] = React.useState<"append" | "replace">("append");
  // Auto-verify before import (on by default): unreachable rows are not imported, with a per-row reason.
  const [bulkVerify, setBulkVerify] = React.useState(true);
  const [bulkRejected, setBulkRejected] = React.useState<
    { line: number; raw: string; reason: string }[]
  >([]);
  // Master switch and usable count (with 0 usable, tasks fall back to direct/global proxy).
  const [enabled, setEnabled] = React.useState(true);
  const [usable, setUsable] = React.useState(0);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .proxyPoolGet()
      .then((r) => {
        setEntries(r.entries ?? []);
        setStrategy(r.strategy || "round_robin");
        setStrict(!!r.strict);
        setEnabled(r.enabled !== false);
        setRunning(r.running ?? []);
        setUsable(r.usable ?? (r.running ?? []).filter((x) => (x.break_remaining ?? 0) === 0).length);
        setCapturing(r.capturing);
        setCheckTarget(r.check_target ?? "");
        setHealthMinutes(r.health_minutes ?? 10);
        setLastCheck(r.last_check ?? null);
        setSelected(new Set());
      })
      .catch((e) => toast.error("Load failed: " + e))
      .finally(() => setLoading(false));
    api.proxyPoolMihomoStatus()
      .then((r) => setMihomo(r.status))
      .catch(() => {
        /* degrade silently when the backend predates the mihomo API */
      });
  }, []);

  React.useEffect(load, [load]);

  // Bulk-import a block of text (subscription URI list / direct nodes) with unified result messages.
  const bulkImportText = async (text: string, note?: string) => {
    const res = await api.proxyPoolBulk({ text, mode: "append", verify: true });
    toast.success(
      `Subscription import: added ${res.added}, updated ${res.updated}${note ? `; ${note}` : ""}`,
      { duration: 6000 },
    );
    if (res.verify_skipped) toast.warning(res.verify_skipped);
  };

  // Subscription pull: a URI list imports directly; Clash YAML offers three routes — start mihomo / local Clash / direct nodes.
  const importSubscription = async () => {
    if (!subURL.trim()) {
      toast.error("Enter a subscription URL");
      return;
    }
    setSubLoading(true);
    try {
      const r = await api.proxyPoolSubscriptionFetch(subURL.trim());
      setSubResult(r);
      setOutbound(r.group_names?.[0] ?? "");
      if (r.format === "clash") {
        toast.info(
          `Detected Clash YAML: ${r.proxies ?? 0} nodes, ${r.direct_nodes ?? 0} directly usable; start mihomo or detect the local Clash`,
          { duration: 8000 },
        );
        return;
      }
      if (!(r.supported?.length ?? 0)) {
        toast.error(r.note || "the subscription has no directly usable http/https/socks5 node");
        return;
      }
      await bulkImportText(r.text, r.note);
      setSubOpen(false);
      setSubURL("");
      setSubResult(null);
      load();
    } catch (e) {
      toast.error("Subscription import failed: " + String(e));
    } finally {
      setSubLoading(false);
    }
  };

  // Import only type=http/socks5 nodes from the Clash YAML (without starting the core).
  const importDirectNodes = async () => {
    if (!subResult?.text) {
      toast.error("this Clash config has no directly importable http/socks5 node");
      return;
    }
    try {
      await bulkImportText(subResult.text, subResult.note);
      load();
    } catch (e) {
      toast.error("Importing direct nodes failed: " + String(e));
    }
  };

  const installMihomo = async () => {
    setMihomoBusy(true);
    try {
      const r = await api.proxyPoolMihomoInstall();
      toast.success(`mihomo ${r.install.version} installed`, { duration: 6000 });
      const st = await api.proxyPoolMihomoStatus();
      setMihomo(st.status);
    } catch (e) {
      toast.error("Installing mihomo failed: " + String(e), { duration: 10000 });
    } finally {
      setMihomoBusy(false);
    }
  };

  // Install from a mirror URL / a local file on the server. Official GitHub assets time out at 60s on restricted networks.
  const installMihomoFrom = async (mode: "url" | "path") => {
    if (mode === "url" && !installSHA.trim()) {
      // Audit B8: a remote URL install requires a mandatory sha256 check (the backend enforces it too).
      toast.error("A remote URL install needs a sha256 (get the package hash in a trusted environment first); for offline cases use \"install from a server file\"", { duration: 10000 });
      return;
    }
    setMihomoBusy(true);
    try {
      const r = await api.proxyPoolMihomoInstall(
        mode === "url"
          ? { url: installURL.trim(), sha256: installSHA.trim() }
          : { path: installPath.trim() },
      );
      toast.success(`mihomo ${r.install.version || "installed"}`, { duration: 6000 });
      const st = await api.proxyPoolMihomoStatus();
      setMihomo(st.status);
    } catch (e) {
      toast.error("Installing mihomo failed: " + String(e), { duration: 10000 });
    } finally {
      setMihomoBusy(false);
    }
  };

  const startMihomo = async () => {
    const yaml = subResult?.clash_yaml;
    if (!yaml) {
      toast.error("Pull a Clash subscription first");
      return;
    }
    setMihomoBusy(true);
    try {
      const r = await api.proxyPoolMihomoStart({
        yaml,
        use: true,
        outbound: outbound || undefined,
      });
      setMihomo(r.status);
      toast.success(
        `mihomo started, mixed-port ${r.status.port}${r.status.last_error ? `; ${r.status.last_error}` : ""}`,
        { duration: 8000 },
      );
      load();
    } catch (e) {
      toast.error("Starting mihomo failed: " + String(e), { duration: 10000 });
    } finally {
      setMihomoBusy(false);
    }
  };

  const stopMihomo = async () => {
    setMihomoBusy(true);
    try {
      await api.proxyPoolMihomoStop();
      toast.success("mihomo stopped and its pool entries removed");
      const st = await api.proxyPoolMihomoStatus();
      setMihomo(st.status);
      load();
    } catch (e) {
      toast.error("Stopping mihomo failed: " + String(e));
    } finally {
      setMihomoBusy(false);
    }
  };

  const detectLocal = async (use = true, ports?: number[]) => {
    setLocalBusy(true);
    try {
      const r = await api.proxyPoolDetectLocal({ ports, use });
      setLocalCandidates(r.candidates ?? []);
      const ok = (r.candidates ?? []).filter((c) => c.ok).length;
      if (ok === 0) {
        toast.warning("No usable local Clash port found; start Clash/mihomo first, or check the port settings");
      } else {
        toast.success(`Found ${ok} usable local ports${use ? `, added ${r.added} entries` : ""}`);
      }
      if (use) load();
    } catch (e) {
      toast.error("Detecting the local proxy failed: " + String(e));
    } finally {
      setLocalBusy(false);
    }
  };

  const save = async () => {
    // Saving an empty list = wiping the whole pool: it needs human confirmation (a stale page must not silently wipe it either).
    let confirmClear = false;
    if (entries.length === 0) {
      if (typeof window !== "undefined" && !window.confirm("The list is empty — saving clears every entry in the proxy pool. Continue?")) {
        return;
      }
      confirmClear = true;
    }
    setSaving(true);
    try {
      await api.proxyPoolPut({ entries, strategy, enabled, strict, confirm_clear: confirmClear });
      toast.success("Proxy pool saved and applied live");
      load();
    } catch (e) {
      toast.error("Save failed: " + e);
    } finally {
      setSaving(false);
    }
  };

  // Strict egress: hot-applies at once. Once on, a fully tripped pool fails requests instead of going direct.
  const toggleStrict = async (v: boolean) => {
    setStrict(v);
    try {
      await api.proxyPoolPut({ entries, strategy, enabled, strict: v });
      toast.success(v ? "Strict egress on: requests fail when proxies are unusable, no direct fallback" : "Strict egress off: an unusable proxy falls back to the global proxy/direct");
      load();
    } catch (e) {
      setStrict(!v);
      toast.error("Toggle failed: " + e);
    }
  };

  // Master switch: hot-applies at once (no save needed).
  const toggleEnabled = async (v: boolean) => {
    setEnabled(v);
    try {
      await api.proxyPoolPut({ entries, strategy, enabled: v, strict });
      toast.success(v ? "Proxy pool enabled · new requests start using pool exits" : "Proxy pool disabled · falling back to global proxy/direct");
      load();
    } catch (e) {
      setEnabled(!v);
      toast.error("Toggle failed: " + e);
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
      const res = await api.proxyPoolBulk({
        text: bulkText,
        mode: bulkMode,
        verify: bulkVerify,
      });
      const bad = res.invalid?.length ?? 0;
      const rejected = res.rejected ?? [];
      setBulkRejected(rejected);
      const parts = [`added ${res.added}`, `updated ${res.updated}`];
      if (bad) parts.push(`${bad} invalid rows`);
      if (rejected.length) parts.push(`${rejected.length} unreachable (new ones dropped / existing ones disabled)`);
      if (res.verify_skipped) parts.push("verification skipped");
      toast.success(`Import complete: ${parts.join(", ")}`);
      if (res.verify_skipped) toast.warning(res.verify_skipped);
      setBulkOpen(rejected.length > 0 || bad > 0);
      if (rejected.length === 0 && bad === 0) {
        setBulkText("");
        setBulkOpen(false);
      }
      load();
    } catch (e) {
      toast.error("Import failed: " + e);
    }
  };

  // Entries the latest check judged failed (mapped back to entries by the backend's full index).
  const failedIndexes = React.useMemo(() => {
    const s = new Set<number>();
    for (const r of checkRows) {
      if (!r.ok && r.index >= 0 && r.index < entries.length) s.add(r.index);
    }
    return s;
  }, [checkRows, entries.length]);

  const deadIndexes = React.useMemo(() => {
    const s = new Set<number>();
    entries.forEach((e, i) => {
      if (deadURLs.has(e.url)) s.add(i);
    });
    return s;
  }, [entries, deadURLs]);

  const toggleSelect = (i: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  const selectedURLs = React.useMemo(
    () => [...selected].map((i) => entries[i]?.url).filter((u): u is string => Boolean(u)),
    [selected, entries],
  );

  const removeSelected = () => {
    if (selected.size === 0) {
      toast.info("Tick the entries to delete first");
      return;
    }
    setEntries((prev) => prev.filter((_, i) => !selected.has(i)));
    toast.success(`Removed ${selected.size} entries — click "Save & apply live" to apply`);
    setSelected(new Set());
    setCheckRows([]);
  };

  const removeDead = () => {
    const doomed = new Set<number>([...deadIndexes, ...failedIndexes]);
    if (doomed.size === 0) {
      toast.info("No dead entries (run \"Verify all\" for check results, or wait for breaker state)");
      return;
    }
    setEntries((prev) => prev.filter((_, i) => !doomed.has(i)));
    toast.success(`Removed ${doomed.size} dead entries — click "Save & apply live" to apply`);
    setSelected(new Set());
    setCheckRows([]);
  };

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold">Proxy pool</h1>
          <div className="flex items-center gap-1.5">
            <Switch
              checked={enabled}
              onCheckedChange={toggleEnabled}
              disabled={loading}
              aria-label="Enable the proxy pool"
            />
            <span className="text-xs text-muted-foreground">{enabled ? "Enabled" : "Disabled"}</span>
          </div>
          <Badge variant={enabled && entries.length > 0 ? "default" : "secondary"}>
            {!enabled
              ? `Disabled · ${entries.length} saved`
              : entries.length === 0
                ? "Empty pool (direct/global proxy)"
                : `${usable}/${entries.length} usable`}
          </Badge>
          {deadURLs.size > 0 && <Badge variant="destructive">{deadURLs.size} unavailable</Badge>}
          {mihomo && (
            <Badge
              variant={mihomo.running ? "default" : "secondary"}
              title={mihomo.last_error || mihomo.binary || "mihomo not installed"}
            >
              mihomo {mihomo.running ? `:${mihomo.port}` : mihomo.installed ? "installed" : "not installed"}
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void detectLocal(true)}
            disabled={localBusy}
          >
            <WifiIcon className="mr-1 size-4" />
            {localBusy ? "Detecting…" : "Detect local proxy"}
          </Button>
          {mihomo?.running && (
            <Button variant="outline" size="sm" onClick={() => void stopMihomo()} disabled={mihomoBusy}>
              <SquareIcon className="mr-1 size-4" />
              Stop mihomo
            </Button>
          )}
          <Dialog open={subOpen} onOpenChange={setSubOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <RefreshCwIcon className="mr-1 size-4" />
                Import subscription
              </Button>
            </DialogTrigger>
            <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
              <DialogHeader>
                <DialogTitle>Import from a subscription</DialogTitle>
                <DialogDescription>
                  Accepts a URI list or Clash/mihomo YAML. http/socks5 nodes in YAML go straight into the pool;
                  for vmess/ss/trojan/vless use "start mihomo and hook it in" or reuse the local Clash port.
                  Subscription URLs are checked against private/loopback ranges (SSRF guard).
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-2">
                <Label>Subscription URL</Label>
                <Input
                  value={subURL}
                  onChange={(e) => setSubURL(e.target.value)}
                  placeholder="https://example.com/api/v1/client/subscribe?token=..."
                  className="font-mono text-xs"
                />
              </div>
              {subResult && (
                <div className="space-y-2 rounded-md border p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant={subResult.format === "clash" ? "default" : "secondary"}>
                      {subResult.format === "clash" ? "Clash YAML" : "URI list"}
                    </Badge>
                    {typeof subResult.proxies === "number" && (
                      <Badge variant="secondary">Nodes {subResult.proxies}</Badge>
                    )}
                    <Badge variant="secondary">
                      Directly usable {subResult.direct_nodes ?? subResult.supported?.length ?? 0}
                    </Badge>
                    {subResult.unsupported > 0 && (
                      <Badge variant="secondary">Needs core {subResult.unsupported}</Badge>
                    )}
                    {subResult.invalid > 0 && (
                      <Badge variant="destructive">Invalid {subResult.invalid}</Badge>
                    )}
                    {(subResult.ignored ?? 0) > 0 && (
                      <Badge variant="outline">Ignored info {subResult.ignored}</Badge>
                    )}
                  </div>
                  {subResult.note && (
                    <p className="break-words text-muted-foreground">{subResult.note}</p>
                  )}
                  {!!subResult.local_ports?.length && (
                    <p>
                      Ports in the YAML:
                      <span className="ml-1 font-mono">{subResult.local_ports.join(", ")}</span>
                    </p>
                  )}
                  {subResult.format === "clash" && !!subResult.group_names?.length && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-muted-foreground">Outbound group</span>
                      <Select
                        value={outbound || subResult.group_names[0]}
                        onValueChange={setOutbound}
                      >
                        <SelectTrigger className="h-7 w-48 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {subResult.group_names.map((g) => (
                            <SelectItem key={g} value={g}>
                              {g}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <span className="text-[11px] text-muted-foreground">
                        Rules become MATCH,&lt;outbound group&gt; once started
                      </span>
                    </div>
                  )}
                  {subResult.format === "clash" && (
                    <div className="flex flex-wrap gap-2 pt-1">
                      <Button size="sm" onClick={() => void startMihomo()} disabled={mihomoBusy}>
                        <PlayIcon className="mr-1 size-4" />
                        Start mihomo and hook it in
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void installMihomo()}
                        disabled={mihomoBusy}
                      >
                        <DownloadIcon className="mr-1 size-4" />
                        Install mihomo
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void detectLocal(true, subResult.local_ports)}
                        disabled={localBusy}
                      >
                        <WifiIcon className="mr-1 size-4" />
                        Use the local Clash port
                      </Button>
                      {(subResult.direct_nodes ?? 0) > 0 && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => void importDirectNodes()}
                        >
                          <PlusIcon className="mr-1 size-4" />
                          Import direct nodes only
                        </Button>
                      )}
                    </div>
                  )}
                  {subResult.format === "clash" && (
                    <div className="space-y-2 pt-1">
                      <p className="text-[11px] text-muted-foreground">
"Install mihomo" prefers an accelerated mirror (verifying GitHub's official SHA-256) and falls back to the official source on failure; the install sources below also work.
                      </p>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 px-2 text-xs"
                        onClick={() => setInstallSrcOpen((v) => !v)}
                      >
                        {installSrcOpen ? "Hide install sources" : "GitHub unreachable? Switch install source (mirror / offline)"}
                      </Button>
                      {installSrcOpen && (
                        <div className="space-y-2 rounded border p-2">
                          <p className="break-words text-muted-foreground">
                            Official GitHub assets time out on restricted networks. Enter an intranet mirror address
                            (.gz/.zip/raw binary), or copy the package to the server first and install from a local file.
                          </p>
                          <Input
                            value={installURL}
                            onChange={(e) => setInstallURL(e.target.value)}
                            placeholder="https://intranet-mirror/mihomo-linux-amd64-vX.Y.Z.gz"
                            className="h-8 font-mono text-[11px]"
                          />
                          <Input
                            value={installSHA}
                            onChange={(e) => setInstallSHA(e.target.value)}
                            placeholder="sha256 (required for URL installs, 64 hex chars)"
                            className="h-8 font-mono text-[11px]"
                          />
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void installMihomoFrom("url")}
                            disabled={mihomoBusy || !installURL.trim()}
                          >
                            Install from URL
                          </Button>
                          <div className="border-t pt-2">
                            <Input
                              value={installPath}
                              onChange={(e) => setInstallPath(e.target.value)}
                              placeholder="local path on the server, e.g. /tmp/mihomo-linux-amd64-vX.Y.Z.gz"
                              className="h-8 font-mono text-[11px]"
                            />
                            <Button
                              size="sm"
                              variant="outline"
                              className="mt-2"
                              onClick={() => void installMihomoFrom("path")}
                              disabled={mihomoBusy || !installPath.trim()}
                            >
                              Install from a server file
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  {localCandidates.length > 0 && (
                    <div className="max-h-32 overflow-y-auto rounded border p-2 font-mono text-[11px]">
                      {localCandidates.map((c) => (
                        <div key={c.url} className={c.ok ? "text-emerald-600" : "text-muted-foreground"}>
                          {c.ok ? "✓" : "×"} {c.url}
                          {c.ok
                            ? ` · ${c.latency_ms}ms${c.exit_ip ? ` · ${c.exit_ip}` : ""}`
                            : ` · ${c.error ?? "unavailable"}`}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              <DialogFooter>
                <Button variant="outline" onClick={() => setSubOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={() => void importSubscription()} disabled={subLoading}>
                  {subLoading ? "Fetching…" : "Fetch subscription"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
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
              <div className="flex flex-wrap items-center gap-4">
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
                <div className="flex items-center gap-2">
                  <Switch
                    id="bulk-verify"
                    checked={bulkVerify}
                    onCheckedChange={setBulkVerify}
                  />
                  <Label htmlFor="bulk-verify" className="text-xs font-normal">
                    Verify connectivity on import (unreachable rows are dropped)
                  </Label>
                </div>
              </div>
              {bulkRejected.length > 0 && (
                <div className="max-h-40 overflow-y-auto rounded-md border p-2 text-xs">
                  <p className="mb-1 font-medium text-destructive">
                    These {bulkRejected.length} rows are unreachable and were dropped:
                  </p>
                  <ul className="space-y-0.5 font-mono">
                    {bulkRejected.slice(0, 50).map((r) => (
                      <li key={`${r.line}-${r.raw}`} className="truncate text-muted-foreground">
                        line {r.line} {r.raw} — {r.reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
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

      <p className="text-xs text-muted-foreground">
        {!enabled
          ? "Proxy pool disabled: Agent traffic falls back to the global egress proxy or direct."
          : capturing
            ? "Proxy pool enabled: Agent traffic rotates exits per policy through the recording proxy, fully recorded."
            : "Proxy pool enabled: with traffic capture off the pool is injected straight into Bash/WebFetch's HTTP_PROXY; each worker pins one exit at startup (no traffic records)."}
      </p>
      {enabled && entries.length > 0 && usable === 0 && (
        <p className="text-sm text-destructive">
          {strict
            ? "0 usable exits: strict egress is on, so target requests fail outright (no direct fallback). Re-verify or swap proxies."
            : "0 usable exits: tasks fall back to direct/global proxy (the real IP is exposed). Re-verify or swap proxies before enabling."}
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
          <label className="flex w-full items-center gap-2 text-xs">
            <input
              type="checkbox"
              className="size-4"
              checked={strict}
              onChange={(e) => void toggleStrict(e.target.checked)}
            />
            Strict egress: when a proxy is configured but unusable, fail the target request instead of falling back to direct (prevents real-IP exposure)
          </label>
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
            <div className="overflow-x-hidden rounded-md border">
              <table className="w-full table-fixed text-sm">
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
                    <tr key={r.index} className="border-b last:border-0">
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
          <div className="flex flex-wrap items-center gap-2">
            <Link href="/system/proxypool/clash">
              <Button variant="secondary" size="sm">
                <WifiIcon className="mr-1 size-4" />
                Clash node management
              </Button>
            </Link>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEntries((p) => [...p, { url: "", name: "", enabled: true, weight: 1 }])}
            >
              <PlusIcon className="mr-1 size-4" />
              Add
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-2">
          {entries.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/30 px-2 py-1.5 text-xs">
              <span className="text-muted-foreground">Bulk:</span>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                onClick={() => setSelected(new Set(entries.map((_, i) => i)))}
              >
                Select all
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                onClick={() =>
                  setSelected((prev) => {
                    const next = new Set<number>();
                    entries.forEach((_, i) => {
                      if (!prev.has(i)) next.add(i);
                    });
                    return next;
                  })
                }
              >
                Invert
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                disabled={selected.size === 0}
                onClick={() => setSelected(new Set())}
              >
                Clear
              </Button>
              <span className="tabular-nums text-muted-foreground">{selected.size} selected</span>
              <span className="mx-1 h-4 w-px bg-border" />
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={selected.size === 0 || checking}
                onClick={() => void runCheck(selectedURLs)}
              >
                <FlaskConicalIcon className={"mr-1 size-3.5" + (checking ? " animate-pulse" : "")} />
                Check selected
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={selected.size === 0}
                onClick={removeSelected}
              >
                <Trash2Icon className="mr-1 size-3.5" />
                Delete selected
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={deadIndexes.size + failedIndexes.size === 0}
                onClick={removeDead}
              >
                <AlertTriangleIcon className="mr-1 size-3.5" />
                Delete dead ({new Set([...deadIndexes, ...failedIndexes]).size})
              </Button>
            </div>
          )}
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
              <div
                key={i}
                className={
                  "flex flex-wrap items-center gap-2 rounded-md px-1 py-0.5" +
                  (selected.has(i) ? " bg-primary/5 ring-1 ring-primary/20" : "")
                }
              >
                <input
                  type="checkbox"
                  aria-label={`Select entry ${i + 1}`}
                  className="size-4 shrink-0 accent-primary"
                  checked={selected.has(i)}
                  onChange={() => toggleSelect(i)}
                />
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
                  onClick={() => {
                    setEntries((p) => p.filter((_, j) => j !== i));
                    setSelected(new Set());
                    setCheckRows([]);
                  }}
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
