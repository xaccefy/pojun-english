"use client";

import * as React from "react";

import {
  ChevronRightIcon,
  DownloadIcon,
  Loader2Icon,
  MonitorCog,
  PlugIcon,
  RefreshCwIcon,
  TerminalIcon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { HostenvStatus, HostTool, InstallJob, ProxyCheckResult } from "@/lib/types";

import { InstallSources } from "./install-sources";

const TERMINAL_STATES = new Set(["done", "failed", "cancelled"]);

const KIND_LABEL: Record<HostTool["kind"], string> = {
  apt: "System repository",
  github: "GitHub Release",
  pip: "pip",
  manual: "Manual installation",
};

// Attack surface categories. Ordered by the attack flow: first map the surface (network/DNS) → then attack (Web/credentials)
// → deeper (code/exploitation/middleware) → support (tunneling/out-of-band/reference material/general).
const CATEGORY_ORDER: HostTool["category"][] = [
  "network",
  "dns",
  "web",
  "cred",
  "code",
  "exploit",
  "middleware",
  "pivot",
  "oob",
  "material",
  "runtime",
  "",
];

const CATEGORY_LABEL: Record<HostTool["category"], string> = {
  network: "Network & Host",
  dns: "Subdomains & DNS",
  web: "Web Applications",
  cred: "Credentials & Passwords",
  code: "Code & Secrets",
  exploit: "Vulnerability Exploitation",
  middleware: "Middleware Protocols",
  pivot: "Internal Network & Tunneling",
  oob: "Out-of-Band & Callback",
  material: "Reference Material & Wordlists",
  runtime: "General & Runtime",
  "": "Other",
};

// Host environment: tool health check. In a binary deployment form, whatever is installed on the system, the agent can call it directly via Bash;
// this page makes the inventory explicit, and missing items can be installed with one click (executed by the privileged helper pojun-hostd).
export default function HostEnvPage() {
  const [inv, setInv] = React.useState<HostenvStatus | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [proxyInput, setProxyInput] = React.useState("");
  const [savingProxy, setSavingProxy] = React.useState(false);
  const [testingProxy, setTestingProxy] = React.useState(false);
  const [proxyCheck, setProxyCheck] = React.useState<ProxyCheckResult | null>(null);
  // Track install jobs by tool id: batch "install all" pushes N jobs into the helper queue at once
  // (the helper executes serially), so it's no longer a single-slot job.
  const [jobsByTool, setJobsByTool] = React.useState<Record<string, InstallJob>>({});
  const [selectedJobTool, setSelectedJobTool] = React.useState<string | null>(null);
  const [batchBusy, setBatchBusy] = React.useState(false);
  const logRef = React.useRef<HTMLPreElement | null>(null);

  const refresh = React.useCallback(() => {
    api
      .hostenvStatus()
      .then((s) => {
        setInv(s);
        setProxyInput(s.installer.proxy ?? "");
      })
      .catch(() => undefined)
      .finally(() => setLoaded(true));
  }, []);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  const activeJobs = React.useMemo(
    () => Object.values(jobsByTool).filter((j) => !TERMINAL_STATES.has(j.state)),
    [jobsByTool],
  );
  const installing = activeJobs.length > 0 || batchBusy;

  // Install job polling: poll all in-progress jobs in parallel every 1.2s; refresh the health check once all reach terminal state.
  const refreshedAllRef = React.useRef(true);
  React.useEffect(() => {
    if (activeJobs.length === 0) {
      refreshedAllRef.current = true;
      return;
    }
    const timer = setInterval(async () => {
      const results = await Promise.allSettled(
        activeJobs.map((j) => api.hostenvJob(j.id)),
      );
      let sawTerminal = false;
      setJobsByTool((prev) => {
        const next = { ...prev };
        for (const r of results) {
          if (r.status !== "fulfilled") continue; // A failed poll doesn't interrupt; try again next round
          const j = r.value;
          const before = next[j.tool_id];
          if (!before || before.state === j.state) continue;
          next[j.tool_id] = j;
          if (TERMINAL_STATES.has(j.state)) {
            sawTerminal = true;
            if (j.state === "done") toast.success(`${j.tool_name} installed successfully`);
            else if (j.state === "failed") toast.error(`${j.tool_name} installation failed`);
            else toast.info(`${j.tool_name} installation cancelled`);
          }
        }
        return next;
      });
      // Refresh the health check once when any job reaches terminal state (later rounds re-align via idempotent refresh).
      if (sawTerminal) refresh();
    }, 1200);
    return () => clearInterval(timer);
  }, [activeJobs, refresh]);

  React.useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, []);

  const saveProxy = async () => {
    setSavingProxy(true);
    try {
      await api.setSettings({ install_proxy: proxyInput.trim() });
      toast.success("Install proxy saved");
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSavingProxy(false);
    }
  };

  // Proxies expire, so you must be able to verify the path immediately after changing — otherwise you only find out when tool installation fails.
  // It tests the value in the input box (not yet saved), so you can check correctness whether or not you've saved.
  const testProxy = async () => {
    setTestingProxy(true);
    setProxyCheck(null);
    try {
      const r = await api.hostenvProxyCheck(proxyInput.trim());
      setProxyCheck(r);
      if (r.ok) toast.success(`Proxy available${r.exit_ip ? ` (exit ${r.exit_ip})` : ""}`);
      else toast.error(`Proxy unavailable: ${r.error || r.hint || "Unknown reason"}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Test failed");
    } finally {
      setTestingProxy(false);
    }
  };

  const install = async (tool: HostTool) => {
    try {
      const j = await api.hostenvInstall(tool.id);
      setJobsByTool((prev) => ({ ...prev, [tool.id]: j }));
      setSelectedJobTool(tool.id);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to start installation");
    }
  };

  // Install all: push a batch of tools into the helper queue at once (helper executes serially, no need to wait for each one).
  const installMany = async (tools: HostTool[]) => {
    const ids = tools.map((t) => t.id);
    if (ids.length === 0) return;
    setBatchBusy(true);
    try {
      const r = await api.hostenvInstallBatch(ids);
      setJobsByTool((prev) => {
        const next = { ...prev };
        const byId = new Map(tools.map((t) => [t.id, t]));
        for (const j of r.started) {
          const t = byId.get(j.tool_id);
          if (!t) continue;
          next[j.tool_id] = {
            ...j,
            id: j.job_id,
            tool_id: t.id,
            tool_name: t.name,
            state: "queued",
            exit_code: 0,
            started_at: new Date().toISOString(),
            log: "",
          } as InstallJob;
        }
        return next;
      });
      if (r.started.length > 0) setSelectedJobTool(r.started[0].tool_id);
      if (r.skipped.length > 0) {
        toast.warning(
          `${r.started.length} items added to the install queue; ${r.skipped.length} skipped (${r.skipped
            .slice(0, 3)
            .map((x) => x.tool_id)
            .join(", ")}${r.skipped.length > 3 ? " etc." : ""})`,
        );
      } else {
        toast.success(`${r.started.length} items added to the install queue and will be executed in order`);
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to start batch installation");
    } finally {
      setBatchBusy(false);
    }
  };

  const cancel = async () => {
    const j = selectedJobTool ? jobsByTool[selectedJobTool] : null;
    if (!j) return;
    try {
      await api.hostenvCancel(j.id);
    } catch {
      // Ignore: the job may have just ended on its own
    }
  };

  const available = inv?.tools.filter((t) => t.available) ?? [];
  const missing = inv?.tools.filter((t) => !t.available) ?? [];
  const installerReady = inv?.installer.available ?? false;

  // Group by attack surface. There are nearly 40 tools in the catalog; a flat table is unreadable — the question the user wants answered is
  // "what tools do I have on the Web side, and what's missing", not "there are 39 rows in total". Group order is fixed by the attack flow,
  // and doesn't change with availability, to avoid rows jumping around after a refresh.
  const grouped = React.useMemo(() => {
    const tools = inv?.tools ?? [];
    const byCat = new Map<HostTool["category"], HostTool[]>();
    for (const t of tools) {
      const c = t.category ?? "";
      const arr = byCat.get(c);
      if (arr) arr.push(t);
      else byCat.set(c, [t]);
    }
    const groups: { category: HostTool["category"]; tools: HostTool[] }[] = [];
    for (const c of CATEGORY_ORDER) {
      const ts = byCat.get(c);
      if (ts && ts.length > 0) groups.push({ category: c, tools: ts });
    }
    return groups;
  }, [inv?.tools]);

  // Missing items that can be installed with one click: used by "install all".
  const missingInstallable = React.useMemo(
    () => (inv?.tools ?? []).filter((t) => !t.available && t.installable),
    [inv?.tools],
  );
  const toolJobState = (id: string): InstallJob["state"] | null =>
    jobsByTool[id]?.state ?? null;
  const selectedJob = selectedJobTool ? (jobsByTool[selectedJobTool] ?? null) : null;

  // Collapse state: all expanded by default. Users usually come here to check "what's missing", so hiding things just causes confusion.
  const [collapsed, setCollapsed] = React.useState<Set<string>>(new Set());
  const toggleCat = React.useCallback((c: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });
  }, []);

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-sm">
              <MonitorCog className="size-4" /> Host Tool Health Check
            </CardTitle>
            <CardDescription className="mt-1">
              With these tools installed on the system, the Agent can call them directly; this list is the source of truth when choosing means for assigned tasks.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {inv && (
              <Badge variant={inv.deploy_mode === "docker" ? "secondary" : "outline"}>
                {inv.deploy_mode === "docker" ? "Docker Container" : "Host Binary"}
              </Badge>
            )}
            {installerReady && missingInstallable.length > 0 && (
              <Button
                size="sm"
                variant="default"
                disabled={installing}
                onClick={() => installMany(missingInstallable)}
              >
                {installing ? <Loader2Icon className="animate-spin" /> : <DownloadIcon />}
                Install Missing ({missingInstallable.length})
              </Button>
            )}
            <Button size="sm" variant="outline" onClick={refresh}>
              <RefreshCwIcon /> Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent id="install-proxy-settings" className="flex flex-col gap-4">
          {!loaded ? (
            <div className="space-y-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : (
            <>
              {/* Install proxy: only affects install actions, unrelated to target traffic/search/LLM proxies */}
              <div className="flex flex-col gap-2 rounded-lg border bg-muted/30 p-3">
                <div className="flex items-center justify-between gap-2">
                  <Label htmlFor="install-proxy" className="text-sm">
                    Install Proxy
                  </Label>
                  <div className="flex items-center gap-2">
                    {proxyCheck && (
                      <Badge
                        variant={proxyCheck.ok ? "default" : "destructive"}
                        title={proxyCheck.hint || proxyCheck.error || ""}
                      >
                        {proxyCheck.ok
                          ? `Available${proxyCheck.latency_ms ? ` · ${proxyCheck.latency_ms}ms` : ""}`
                          : "Unavailable"}
                      </Badge>
                    )}
                    <span className="text-muted-foreground text-xs">
                      {installerReady
                        ? "Used for tool installs and program updates"
                        : "Tool installs need the host helper; program updates can still use this proxy"}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Input
                    id="install-proxy"
                    autoComplete="off"
                    className="font-mono text-xs"
                    placeholder="http://10.0.0.14:7897 or socks5://host:1080 (leave empty = direct connection)"
                    value={proxyInput}
                    disabled={!loaded || savingProxy}
                    onChange={(e) => {
                      setProxyInput(e.target.value);
                      setProxyCheck(null);
                    }}
                  />
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={testProxy}
                    disabled={!loaded || testingProxy}
                  >
                    {testingProxy ? <Loader2Icon className="animate-spin" /> : <PlugIcon />}
                    Test
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={saveProxy}
                    disabled={!loaded || savingProxy}
                  >
                    Save
                  </Button>
                </div>
                {proxyCheck && !proxyCheck.ok && (
                  <p className="text-destructive text-xs">
                    {proxyCheck.error || "Proxy unavailable"}
                    {proxyCheck.hint ? ` — ${proxyCheck.hint}` : ""}
                  </p>
                )}
                {proxyCheck?.ok && proxyCheck.exit_ip && (
                  <p className="text-muted-foreground text-xs">
                    Exit IP: <span className="font-mono">{proxyCheck.exit_ip}</span>
                  </p>
                )}
                <p className="text-muted-foreground text-xs">
                  In domestic (Chinese) environments, installing tools that go through GitHub Release like nuclei usually requires it; it does not affect the "global proxy" (Agent
                  target traffic). Leave empty to use the deployment environment's <code>POJUN_INSTALL_PROXY</code> (if set).
                  After changing it, click "Test" to check the path first; once saved, retry the GitHub connection under
                  "Version and update" — proxies expire, so when a tool installation fails, check here first.
                </p>
              </div>

              {inv && (
                <InstallSources
                  sources={inv.installer.sources ?? { apt: "", pypi: "" }}
                  supported={!!inv.installer.sources_supported}
                  onSaved={(sources) => setInv((prev) => prev && { ...prev, installer: { ...prev.installer, sources } })}
                />
              )}

              {!installerReady && inv?.installer.reason && (
                <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
                  {inv.installer.reason}
                  {inv.deploy_mode === "docker" && (
                    <span className="text-muted-foreground">
                      {" "}
                      The tools in the container image are fixed at build time; if you need additional tools, please build on top of the official image.
                    </span>
                  )}
                </div>
              )}

              {installerReady && inv?.installer.upgrade_required && (
                <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
                  The helper version is older and lacks self-replacement capability, so it cannot auto-upgrade with the main program. Re-run {" "}
                  <code className="font-mono">install.sh</code> on the server, and after bootstrapping, the helper will automatically follow every future release.
                </div>
              )}

              <p className="text-muted-foreground text-sm">
                Available <span className="font-medium text-foreground">{available.length}</span> / {inv?.tools.length ?? 0}
                {missing.length > 0 && (
                  <span className="ml-3">
                    Missing {missing.length} items{installerReady && " (one-click install available)"}
                  </span>
                )}
              </p>

              <div className="flex flex-col gap-3">
                {grouped.map((g) => {
                  const isCollapsed = collapsed.has(g.category);
                  const okCount = g.tools.filter((t) => t.available).length;
                  return (
                    <div key={g.category} className="rounded-lg border">
                      <div className="flex w-full items-center gap-2 px-3 py-2">
                        <button
                          type="button"
                          onClick={() => toggleCat(g.category)}
                          className="flex flex-1 items-center gap-2 text-left hover:bg-muted/50"
                        >
                          <ChevronRightIcon
                            className={
                              "size-4 shrink-0 text-muted-foreground transition-transform" +
                              (isCollapsed ? "" : "rotate-90")
                            }
                          />
                          <span className="font-medium text-sm">{CATEGORY_LABEL[g.category]}</span>
                          <span className="text-muted-foreground text-xs">
                            {okCount}/{g.tools.length} available
                            {g.tools.length - okCount > 0 && (
                              <span className="ml-1 text-amber-600 dark:text-amber-400">
                                Missing {g.tools.length - okCount}
                              </span>
                            )}
                          </span>
                        </button>
                        {installerReady &&
                          g.tools.some((t) => !t.available && t.installable) && (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-7 px-2 text-xs"
                              disabled={installing}
                              onClick={() =>
                                installMany(g.tools.filter((t) => !t.available && t.installable))
                              }
                            >
                              Install This Group
                            </Button>
                          )}
                      </div>
                      {!isCollapsed && (
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead className="w-32">Tool</TableHead>
                              <TableHead>Purpose</TableHead>
                              <TableHead className="w-24">Status</TableHead>
                              <TableHead>Install Method / Notes</TableHead>
                              <TableHead className="w-28 text-right">Actions</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {g.tools.map((t) => (
                              <TableRow key={t.id}>
                                <TableCell className="font-mono text-sm">{t.bin}</TableCell>
                                <TableCell className="text-muted-foreground text-sm">{t.purpose}</TableCell>
                                <TableCell>
                                  {t.available ? <Badge>Available</Badge> : <Badge variant="outline">Missing</Badge>}
                                </TableCell>
                                <TableCell className="text-muted-foreground text-xs">
                                  {t.available ? (
                                    "—"
                                  ) : (
                                    // break-all: missing-item hints may contain long URLs (such as msfconsole's official docs),
                                    // without wrapping, the table overflows horizontally and you'd have to scroll sideways to see the first column.
                                    <span className="break-all">
                                      <span className="mr-1 text-foreground/70">{KIND_LABEL[t.kind]}</span>
                                      {t.install}
                                    </span>
                                  )}
                                </TableCell>
                                <TableCell className="text-right">
                                  {!t.available && t.installable && installerReady && (
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      disabled={installing}
                                      onClick={() => install(t)}
                                    >
                                      {toolJobState(t.id) &&
                                      !TERMINAL_STATES.has(toolJobState(t.id)!) ? (
                                        <Loader2Icon className="animate-spin" />
                                      ) : (
                                        <DownloadIcon />
                                      )}
                                      {toolJobState(t.id) === "queued"
                                        ? "Queued"
                                        : toolJobState(t.id) === "running"
                                          ? "Installing"
                                          : "Install"}
                                    </Button>
                                  )}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      )}
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Install progress: in batch mode, one tab per tool; the selected one shows its log */}
      {selectedJob && (
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <div className="min-w-0 flex-1">
              <CardTitle className="flex items-center gap-2 text-sm">
                <TerminalIcon className="size-4" /> Install Progress
              </CardTitle>
              <CardDescription className="mt-2 flex flex-wrap items-center gap-1.5">
                {Object.values(jobsByTool)
                  .sort((a, b) => a.tool_name.localeCompare(b.tool_name))
                  .map((j) => (
                    <button
                      key={j.tool_id}
                      type="button"
                      onClick={() => setSelectedJobTool(j.tool_id)}
                      className="focus:outline-none"
                      title={`${j.tool_name} · ${j.state}`}
                    >
                      <Badge
                        variant={
                          j.tool_id === selectedJobTool
                            ? "default"
                            : j.state === "failed"
                              ? "destructive"
                              : "outline"
                        }
                      >
                        {j.state === "running" && <Loader2Icon className="mr-1 size-3 animate-spin" />}
                        {j.tool_name}
                      </Badge>
                    </button>
                  ))}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              {selectedJob && !TERMINAL_STATES.has(selectedJob.state) && (
                <Button size="sm" variant="outline" onClick={cancel}>
                  <XIcon /> Cancel
                </Button>
              )}
              {selectedJob && TERMINAL_STATES.has(selectedJob.state) && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    if (selectedJobTool) {
                      setJobsByTool((prev) => {
                        const next = { ...prev };
                        delete next[selectedJobTool];
                        return next;
                      });
                    }
                    setSelectedJobTool(null);
                  }}
                >
                  Close
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent>
            <CardDescription className="mb-2 flex items-center gap-2">
              <span className="font-medium text-foreground">{selectedJob.tool_name}</span>
              <Badge
                variant={
                  selectedJob.state === "done"
                    ? "default"
                    : selectedJob.state === "failed"
                      ? "destructive"
                      : "secondary"
                }
              >
                {selectedJob.state}
              </Badge>
              {selectedJob.error && <span className="text-destructive">{selectedJob.error}</span>}
            </CardDescription>
            <pre
              ref={logRef}
              className="max-h-80 overflow-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed"
            >
              {selectedJob.log || "Waiting for output… (queued jobs will start outputting when their turn comes)"}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
