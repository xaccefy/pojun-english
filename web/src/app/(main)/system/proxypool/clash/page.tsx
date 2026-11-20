"use client";

import * as React from "react";
import Link from "next/link";
import {
  ArrowLeftIcon,
  DownloadIcon,
  GaugeIcon,
  PlayIcon,
  RefreshCwIcon,
  SearchIcon,
  SquareIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";
import { useStoredSortPreference } from "@/lib/sort-preference";
import type { MihomoStatus, ProxyPoolSubscription } from "@/lib/types";

type PlanMode = "group" | "node" | "load-balance" | "url-test" | "fallback";

type DelayInfo = { ms: number; err?: string; at: number };

const MODES: { value: PlanMode; label: string; hint: string }[] = [
  {
    value: "group",
    label: "Subscription group (default)",
    hint: "Exit through a policy group the subscription ships (e.g. \"Auto select\", \"Hong Kong\"); the group's rules are defined by the subscription author.",
  },
  {
    value: "node",
    label: "Specific node (fixed exit)",
    hint: "Every request pins one node — for cases needing a stable exit IP.",
  },
  {
    value: "load-balance",
    label: "Round-robin (new node per request)",
    hint: "Builds a POJUN-AUTO group over the ticked nodes with strategy=round-robin; the same target also switches exit.",
  },
  {
    value: "url-test",
    label: "Auto delay test (fastest)",
    hint: "Builds a url-test group over the ticked nodes that re-tests every 300s and picks the lowest latency.",
  },
  {
    value: "fallback",
    label: "Failover (in tick order)",
    hint: "Builds a fallback group over the ticked nodes, tried in tick order; when the current node is down the next one is used.",
  },
];

type AppliedPlan = {
  mode: PlanMode;
  outbound: string;
  nodes: string[];
  at: string;
};

const SUB_URL_KEY = "pojun_clash_sub_url_v1";
const SELECT_KEY = "pojun_clash_selection_v1";
const DELAY_KEY = "pojun_clash_delays_v1";
const PLAN_KEY = "pojun_clash_plan_v1";
const SORT_KEY = "pojun_clash_sort_v1";
const SORT_FIELDS = ["name", "delay"] as const;

function readJSON<T>(key: string, fallback: T): T {
  const raw = getLocalStorageValue(key);
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writeJSON(key: string, value: unknown) {
  setLocalStorageValue(key, JSON.stringify(value));
}

const okDelay = (d?: DelayInfo): boolean => !!d && d.ms > 0 && !d.err;

// Sortable delay value: failures/untested all go last (ms=0 is a failure, not the fastest).
function delayRank(delays: Record<string, DelayInfo>, name: string): number {
  const d = delays[name];
  return okDelay(d) ? d!.ms : Number.MAX_SAFE_INTEGER;
}

function delayBadge(info?: DelayInfo) {
  if (!info) return <span className="text-xs text-muted-foreground">—</span>;
  if (info.err || info.ms <= 0) {
    return (
      <Badge variant="destructive" title={info.err || "Timeout"}>
        Timeout
      </Badge>
    );
  }
  const cls =
    info.ms < 150 ? "bg-emerald-600" : info.ms < 400 ? "bg-amber-500" : "bg-orange-600";
  return <Badge className={cls + " tabular-nums"}>{info.ms} ms</Badge>;
}

export default function ClashNodesPage() {
  const [status, setStatus] = React.useState<MihomoStatus | null>(null);
  const [poolEnabled, setPoolEnabled] = React.useState(false);
  const [poolEntries, setPoolEntries] = React.useState(0);
  const [busy, setBusy] = React.useState(false);
  const [subURL, setSubURL] = React.useState("");
  const [subLoading, setSubLoading] = React.useState(false);
  const [sub, setSub] = React.useState<ProxyPoolSubscription | null>(null);
  const [mode, setMode] = React.useState<PlanMode>("group");
  const [groupPick, setGroupPick] = React.useState("");
  const [nodePick, setNodePick] = React.useState("");
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [delays, setDelays] = React.useState<Record<string, DelayInfo>>({});
  const [search, setSearch] = React.useState("");
  const [sortPref, setSortPref] = useStoredSortPreference<"name" | "delay">(
    SORT_KEY,
    SORT_FIELDS,
    "name",
    "asc",
  );
  const [testing, setTesting] = React.useState(false);
  const [testingOne, setTestingOne] = React.useState("");
  const [usePool, setUsePool] = React.useState(true);
  const [applied, setApplied] = React.useState<AppliedPlan | null>(null);

  const nodes = sub?.nodes ?? [];
  const groups = sub?.groups ?? [];
  const groupNames = sub?.group_names ?? [];

  const load = React.useCallback(() => {
    api.proxyPoolMihomoStatus()
      .then((r) => setStatus(r.status))
      .catch((e) => toast.error("Reading mihomo status failed: " + String(e)));
    api
      .proxyPoolGet()
      .then((r) => {
        setPoolEnabled(r.enabled !== false);
        setPoolEntries((r.entries ?? []).length);
      })
      .catch(() => {
        /* pool state is not critical */
      });
  }, []);

  React.useEffect(load, [load]);

  React.useEffect(() => {
    const restored = readJSON<AppliedPlan | null>(PLAN_KEY, null);
    setApplied(restored);
    // Seed the form with the last applied plan: otherwise after a refresh the "last applied" card
    // shows failover while the form sits on the default "group", and clicking start silently swaps
    // the live exit to a different policy.
    if (restored) {
      const restoredMode = MODES.find((m) => m.value === restored.mode)?.value;
      if (restoredMode) setMode(restoredMode);
      if (restored.mode === "node") setNodePick(restored.outbound);
      if (restored.mode === "group") setGroupPick(restored.outbound);
    }
    setDelays(readJSON<Record<string, DelayInfo>>(DELAY_KEY, {}));
    const savedURL = getLocalStorageValue(SUB_URL_KEY) || "";
    if (savedURL) {
      setSubURL(savedURL);
      // Re-pull the subscription automatically after a refresh so node info is no longer lost.
      void fetchSub(savedURL, true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Nothing may be persisted before the subscription loads: these two effects also run once on mount,
  // when selected is still an empty set and delays an empty object, so writing first would overwrite the
  // saved ticks/delays (fetchSub only reads SELECT_KEY after an await, too late for this pass). Once sub
  // is ready, everything written is already restored.
  React.useEffect(() => {
    if (!sub) return;
    writeJSON(SELECT_KEY, [...selected]);
  }, [selected, sub]);

  React.useEffect(() => {
    if (!sub) return;
    writeJSON(DELAY_KEY, delays);
  }, [delays, sub]);

  const fetchSub = async (rawURL: string, silent = false) => {
    const u = rawURL.trim();
    if (!u) {
      toast.error("Enter a subscription URL");
      return;
    }
    setSubLoading(true);
    try {
      const r = await api.proxyPoolSubscriptionFetch(u);
      if (r.format !== "clash") {
        toast.error(r.note || "this is not a Clash subscription (node management needs Clash/mihomo YAML)");
        return;
      }
      setSub(r);
      const names = (r.nodes ?? []).map((n) => n.name);
      // On a subscription change the old delays no longer match (a same-named node may be another server), so they are dropped.
      const sameSub = (getLocalStorageValue(SUB_URL_KEY) || "") === u;
      // Intersect with the saved ticks: keep them if saved (including a deliberate empty selection), only
      // default to selecting all when nothing was saved or every node was renamed.
      const saved = readJSON<string[] | null>(SELECT_KEY, null);
      const kept = Array.isArray(saved) ? saved.filter((n) => names.includes(n)) : [];
      const keepSaved = Array.isArray(saved) && (saved.length === 0 || kept.length > 0);
      setSelected(new Set(keepSaved ? kept : names));
      setGroupPick((prev) =>
        prev && (r.group_names ?? []).includes(prev) ? prev : (r.group_names?.[0] ?? ""),
      );
      setNodePick((prev) => (prev && names.includes(prev) ? prev : (names[0] ?? "")));
      // Keep delays only for nodes that still exist (writing back to localStorage is done by the delays persistence effect).
      setDelays((prev) => {
        if (!sameSub) return {};
        const next: Record<string, DelayInfo> = {};
        for (const n of names) if (prev[n]) next[n] = prev[n];
        return next;
      });
      setLocalStorageValue(SUB_URL_KEY, u);
      if (!silent) {
        toast.success(
          `Subscription parsed: ${r.nodes?.length ?? r.proxies ?? 0} nodes, ${r.group_names?.length ?? 0} groups`,
          { duration: 6000 },
        );
      }
    } catch (e) {
      toast.error("Fetching the subscription failed: " + String(e));
    } finally {
      setSubLoading(false);
    }
  };

  const ensureCore = async (): Promise<MihomoStatus> => {
    const yaml = sub?.clash_yaml;
    if (!yaml) {
      throw new Error("Pull a Clash subscription first");
    }
    // Judge by fresh server state, not this page's possibly stale status: with the core already started in
    // another tab, or a failed status request, a false "not running" restarts the core — the mixed-port
    // changes, the pool's mihomo-local entry points at a dead port, and the restart rewrites the applied
    // exit policy. If the status can't be read, error out and let the user retry: better no test than
    // guessing from stale state and killing a running core.
    const fresh = await api.proxyPoolMihomoStatus().then((r) => r.status);
    if (fresh.running && fresh.controller_port) {
      setStatus(fresh);
      return fresh;
    }
    const r = await api.proxyPoolMihomoStart({
      yaml,
      use: false,
      mode: "group",
      outbound: groupPick || undefined,
    });
    setStatus(r.status);
    toast.info("Core started for delay testing (not hooked into the proxy pool)", { duration: 6000 });
    return r.status;
  };

  const runDelays = async (names: string[]) => {
    if (!names.length) {
      toast.info("No nodes to test");
      return;
    }
    setTesting(true);
    try {
      await ensureCore();
      const r = await api.proxyPoolMihomoDelays({ names });
      setDelays((prev) => {
        const next = { ...prev };
        for (const res of r.results ?? []) {
          next[res.name] = { ms: res.delay_ms, err: res.error, at: Date.now() };
        }
        return next;
      });
      const ok = (r.results ?? []).filter((x) => x.delay_ms > 0).length;
      toast.success(`Delay test done: ${ok}/${names.length} nodes usable`);
    } catch (e) {
      toast.error("Delay test failed: " + String(e), { duration: 10000 });
    } finally {
      setTesting(false);
    }
  };

  const testOne = async (name: string) => {
    setTestingOne(name);
    try {
      await runDelays([name]);
    } finally {
      setTestingOne("");
    }
  };

  const toggleSelected = (name: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const applyAndStart = async () => {
    const yaml = sub?.clash_yaml;
    if (!yaml) {
      toast.error("Pull a Clash subscription on the right first");
      return;
    }
    if (mode === "group" && !groupPick) {
      toast.error("The subscription has no usable group");
      return;
    }
    if (mode === "node" && !nodePick) {
      toast.error("The subscription has no usable node");
      return;
    }
    if ((mode === "load-balance" || mode === "url-test" || mode === "fallback") && selected.size === 0) {
      toast.error("This mode needs at least one ticked node");
      return;
    }
    setBusy(true);
    try {
      const nodesArr =
        mode === "load-balance" || mode === "url-test" || mode === "fallback" ? [...selected] : [];
      const outbound = mode === "group" ? groupPick : mode === "node" ? nodePick : "";
      const r = await api.proxyPoolMihomoStart({
        yaml,
        use: usePool,
        mode,
        outbound: outbound || undefined,
        nodes: nodesArr.length ? nodesArr : undefined,
      });
      setStatus(r.status);
      const plan: AppliedPlan = {
        mode,
        outbound:
          r.status.outbound ||
          outbound ||
          (mode === "load-balance" || mode === "url-test" || mode === "fallback" ? "POJUN-AUTO" : ""),
        nodes: r.status.nodes?.length ? r.status.nodes : nodesArr,
        at: new Date().toISOString(),
      };
      setApplied(plan);
      writeJSON(PLAN_KEY, plan);
      toast.success(
        `mihomo started (port ${r.status.port})${usePool ? ", hooked into the proxy pool" : ""}${
          r.status.last_error ? `; ${r.status.last_error}` : ""
        }`,
        { duration: 8000 },
      );
      load();
    } catch (e) {
      toast.error("Start failed: " + String(e), { duration: 10000 });
    } finally {
      setBusy(false);
    }
  };

  const stopMihomo = async () => {
    setBusy(true);
    try {
      await api.proxyPoolMihomoStop();
      toast.success("mihomo stopped and the mihomo-local pool entry removed");
      load();
    } catch (e) {
      toast.error("Stop failed: " + String(e));
    } finally {
      setBusy(false);
    }
  };

  const installMihomo = async () => {
    setBusy(true);
    try {
      const r = await api.proxyPoolMihomoInstall({});
      toast.success(`mihomo ${r.install?.version || "installed"}`, { duration: 6000 });
      load();
    } catch (e) {
      toast.error("Install failed: " + String(e), { duration: 10000 });
    } finally {
      setBusy(false);
    }
  };

  const visible = React.useMemo(() => {
    const kw = search.trim().toLowerCase();
    const list = nodes.filter((n) => !kw || n.name.toLowerCase().includes(kw));
    if (sortPref.field === "delay") {
      return [...list].sort((a, b) => delayRank(delays, a.name) - delayRank(delays, b.name));
    }
    return [...list].sort((a, b) => a.name.localeCompare(b.name, "en-US"));
  }, [nodes, search, sortPref.field, delays]);

  const selectedGroup = groups.find((g) => g.name === groupPick);
  const livePlan = React.useMemo(() => {
    if (!status?.outbound) return null;
    return { outbound: status.outbound, mode: status.mode ?? "", nodes: status.nodes ?? [] };
  }, [status]);
  const testedOK = Object.values(delays).filter(okDelay).length;
  // Only in "specific node" mode is status.nodes the single current exit; in group mode it is the whole
  // member list, and marking each row "current" would light up a row at a time.
  const activeNodes = React.useMemo(
    () => new Set(status?.running && status.mode === "node" ? (status.nodes ?? []) : []),
    [status],
  );
  // With a search filter only visible nodes are tested (the button label follows); otherwise all are. Huge subscriptions can be batched with the filter.
  const delayTargets = search.trim() ? visible : nodes;

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Link href="/system/proxypool">
            <Button variant="ghost" size="sm">
              <ArrowLeftIcon className="mr-1 size-4" />
              Back to the proxy pool
            </Button>
          </Link>
          <h1 className="text-lg font-semibold">Clash node management</h1>
          {status?.running ? (
            <Badge>
              Running · port {status.port}
              {status.version ? ` · ${status.version.split(" ").slice(0, 3).join(" ")}` : ""}
              {status.controller_port ? ` · delay-test port ${status.controller_port}` : ""}
            </Badge>
          ) : (
            <Badge variant="secondary">Not running</Badge>
          )}
          {status?.installed ? <Badge variant="outline">Installed</Badge> : <Badge variant="destructive">Not installed</Badge>}
          <Badge variant={poolEnabled ? "default" : "secondary"}>
            Proxy pool {poolEnabled ? "enabled" : "disabled"} · {poolEntries} entries
          </Badge>
          {testedOK > 0 && <Badge variant="outline">Delay-tested {testedOK}</Badge>}
        </div>
        <div className="flex flex-wrap gap-2">
          {!status?.installed && (
            <Button variant="outline" size="sm" onClick={() => void installMihomo()} disabled={busy}>
              <DownloadIcon className="mr-1 size-4" />
              Install mihomo
            </Button>
          )}
          {status?.running && (
            <Button variant="outline" size="sm" onClick={() => void stopMihomo()} disabled={busy || testing}>
              <SquareIcon className="mr-1 size-4" />
              Stop
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={load} disabled={busy}>
            <RefreshCwIcon className="mr-1 size-4" />
            Refresh
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="grid gap-2 pt-4 text-xs text-muted-foreground sm:grid-cols-2">
          <div className="truncate">Config: {status?.config_path || "—"}</div>
          <div className="truncate">Log: {status?.log_path || "—"}</div>
          {livePlan && (
            <div className="sm:col-span-2 flex flex-wrap items-center gap-2 text-foreground">
              <span className="text-muted-foreground">Currently in effect:</span>
              <Badge variant="secondary">Exit {livePlan.outbound}</Badge>
              {livePlan.mode && <Badge variant="outline">Policy {livePlan.mode}</Badge>}
              {livePlan.nodes.length > 0 && (
                <span className="truncate">
                  Nodes {livePlan.nodes.slice(0, 6).join(", ")}
                  {livePlan.nodes.length > 6 ? ` and ${livePlan.nodes.length} total` : ""}
                </span>
              )}
            </div>
          )}
          {status?.last_error && <div className="sm:col-span-2 text-destructive">Last error: {status.last_error}</div>}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_400px]">
        <Card className="min-w-0">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Subscription and nodes</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <Input
                className="min-w-0 flex-1 font-mono text-xs"
                value={subURL}
                onChange={(e) => setSubURL(e.target.value)}
                placeholder="https://example.com/api/v1/client/subscribe?token=..."
              />
              <Button size="sm" onClick={() => void fetchSub(subURL)} disabled={subLoading}>
                {subLoading ? "Fetching…" : sub ? "Fetch again" : "Fetch subscription"}
              </Button>
            </div>
            {sub ? (
              <>
                <div className="flex flex-wrap items-center gap-1.5 text-xs">
                  <Badge variant="default">Clash YAML</Badge>
                  <Badge variant="secondary">Nodes {nodes.length}</Badge>
                  <Badge variant="secondary">Groups {groupNames.length}</Badge>
                  {sub.ignored ? <Badge variant="outline">Ignored info {sub.ignored}</Badge> : null}
                  <span className="text-muted-foreground">The subscription URL is saved in this browser; a refresh re-fetches automatically</span>
                </div>
                {sub.note && <p className="break-words text-xs text-muted-foreground">{sub.note}</p>}
                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative min-w-0 flex-1">
                    <SearchIcon className="pointer-events-none absolute left-2 top-2.5 size-4 text-muted-foreground" />
                    <Input
                      className="pl-8"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Search node names"
                    />
                  </div>
                  <Select
                    value={sortPref.field}
                    onValueChange={(v) => setSortPref({ field: v as "name" | "delay", direction: "asc" })}
                  >
                    <SelectTrigger className="h-9 w-28">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="name">By name</SelectItem>
                      <SelectItem value="delay">By delay</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={testing || busy || delayTargets.length === 0}
                    onClick={() => void runDelays(delayTargets.map((n) => n.name))}
                  >
                    <GaugeIcon className={"mr-1 size-4" + (testing ? " animate-pulse" : "")} />
                    {testing
                      ? "Testing…"
                      : search.trim()
                        ? `Test ${delayTargets.length} visible`
                        : "Test all"}
                  </Button>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2"
                    onClick={() => setSelected(new Set(nodes.map((n) => n.name)))}
                  >
                    Select all
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2"
                    onClick={() =>
                      setSelected((prev) => {
                        const next = new Set<string>();
                        nodes.forEach((n) => {
                          if (!prev.has(n.name)) next.add(n.name);
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
                    className="h-8 px-2"
                    onClick={() => setSelected(new Set())}
                  >
                    Clear
                  </Button>
                  <span className="text-xs tabular-nums text-muted-foreground">{selected.size} selected</span>
                  {!status?.running && (
                    <span className="text-xs text-muted-foreground">
                      ("Test" starts the core automatically but does not hook it into the pool)
                    </span>
                  )}
                </div>
                <div className="max-h-[460px] overflow-y-auto rounded-md border">
                  {visible.length === 0 ? (
                    <p className="p-3 text-sm text-muted-foreground">No matching nodes</p>
                  ) : (
                    visible.map((n) => {
                      const d = delays[n.name];
                      const active = activeNodes.has(n.name);
                      return (
                        <label
                          key={n.name}
                          className={
                            "flex cursor-pointer items-center gap-2 border-b px-3 py-2 text-sm last:border-0 hover:bg-muted/40 " +
                            (selected.has(n.name) ? "bg-primary/5" : "")
                          }
                        >
                          <input
                            type="checkbox"
                            className="size-4 shrink-0 accent-primary"
                            checked={selected.has(n.name)}
                            onChange={() => toggleSelected(n.name)}
                          />
                          <span className="min-w-0 flex-1 truncate" title={n.name}>
                            {n.name}
                          </span>
                          {active && <Badge variant="outline">Current</Badge>}
                          <Badge variant="outline" className="uppercase">
                            {n.type}
                          </Badge>
                          <span className="w-16 text-right">{delayBadge(d)}</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            title="Test this node's delay"
                            disabled={testing || busy || testingOne === n.name}
                            onClick={(e) => {
                              // The row is a <label>: without stopping it, clicking test would also toggle the tick.
                              e.preventDefault();
                              e.stopPropagation();
                              void testOne(n.name);
                            }}
                          >
                            <ZapIcon
                              className={"size-3.5" + (testingOne === n.name ? " animate-pulse" : "")}
                            />
                          </Button>
                        </label>
                      );
                    })
                  )}
                </div>
                <p className="text-xs text-muted-foreground">
                  Delays come from real mihomo probes (a separate gstatic/204 request per node); testing needs the
                  core running. Tick order sets "failover" priority; round-robin/delay-test modes only use ticked nodes.
                </p>
              </>
            ) : (
              <p className="py-6 text-sm text-muted-foreground">
                {subLoading
                  ? "Re-fetching from the saved subscription URL…"
                  : "Enter a Clash subscription URL and fetch it; the URL is saved in this browser and the node list restores on refresh."}
              </p>
            )}
          </CardContent>
        </Card>

        <Card className="min-w-0">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Exit policy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-1.5">
              <Label className="text-xs">Policy</Label>
              <Select value={mode} onValueChange={(v) => setMode(v as PlanMode)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {MODES.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">{MODES.find((m) => m.value === mode)?.hint}</p>
            </div>

            {mode === "group" && (
              <div className="grid gap-1.5">
                <Label className="text-xs">Group</Label>
                <Select value={groupPick} onValueChange={setGroupPick}>
                  <SelectTrigger>
                    <SelectValue placeholder="Pick a subscription group" />
                  </SelectTrigger>
                  <SelectContent>
                    {groupNames.map((g) => (
                      <SelectItem key={g} value={g}>
                        {g}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedGroup?.members?.length ? (
                  <p className="break-words text-xs text-muted-foreground">
                    {selectedGroup.members.length} nodes in the group: {selectedGroup.members.slice(0, 8).join(", ")}
                    {selectedGroup.members.length > 8 ? " …" : ""}
                  </p>
                ) : null}
              </div>
            )}

            {mode === "node" && (
              <div className="grid gap-1.5">
                <Label className="text-xs">Node</Label>
                <Select value={nodePick} onValueChange={setNodePick}>
                  <SelectTrigger>
                    <SelectValue placeholder="Pick a node" />
                  </SelectTrigger>
                  <SelectContent>
                    {[...nodes]
                      .sort((a, b) => delayRank(delays, a.name) - delayRank(delays, b.name))
                      .map((n) => (
                        <SelectItem key={n.name} value={n.name}>
                          {n.name}
                          {delays[n.name]?.ms ? ` · ${delays[n.name].ms}ms` : ""}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {(mode === "load-balance" || mode === "url-test" || mode === "fallback") && (
              <p className="text-xs text-muted-foreground">
                Uses the <span className="font-medium text-foreground">{selected.size}</span> nodes ticked on the left
                {selected.size === 0 ? " (tick at least one)" : ""}
                {selected.size > 0 ? `, ${[...selected].filter((n) => okDelay(delays[n])).length} of them delay-tested` : ""}.
              </p>
            )}

            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <div>
                <p className="text-sm">Hook into the proxy pool after start</p>
                <p className="text-xs text-muted-foreground">Enables the master switch and adds the mihomo mixed-port as an upstream</p>
              </div>
              <Switch checked={usePool} onCheckedChange={setUsePool} />
            </div>

            <Button
              className="w-full"
              onClick={() => void applyAndStart()}
              disabled={busy || !sub || testing}
            >
              <PlayIcon className="mr-1 size-4" />
              {status?.running ? "Restart and apply policy" : "Start and apply policy"}
            </Button>

            {applied && (
              <div className="rounded-md border bg-muted/30 p-2 text-xs">
                <p className="text-muted-foreground">
                  Last applied: {new Date(applied.at).toLocaleString()} · policy {applied.mode} · exit {applied.outbound || "—"}
                </p>
                {applied.nodes.length > 0 && (
                  <p className="mt-1 break-words">Nodes: {applied.nodes.join(", ")}</p>
                )}
              </div>
            )}
            <p className="text-xs text-muted-foreground">
              Every start rewrites the config (rules collapse to MATCH,&lt;exit&gt;, GEO/rule-providers dropped) so an
              MMDB download on a restricted network can't stall the start.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
