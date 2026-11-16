"use client";

import * as React from "react";

import { CpuIcon, FlaskConicalIcon, GaugeIcon, KeyboardIcon, RadioTowerIcon, SearchIcon, ShieldAlertIcon, TimerResetIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { CHAT_SEND_MODE_OPTIONS, type ChatSendMode, setChatSendMode, useChatSendMode } from "@/lib/chat-send-mode";
import type { Settings } from "@/lib/types";

import { UpdateCard } from "./_components/update-card";

export default function SystemSettingsPage() {
  const [trafficCapture, setTrafficCapture] = React.useState(false);
  const [agentTrafficBinding, setAgentTrafficBinding] = React.useState(false);
  const [webSearch, setWebSearch] = React.useState(false);
  const [backend, setBackend] = React.useState("ddgs");
  const [braveKeySet, setBraveKeySet] = React.useState(false);
  const [braveKeyInput, setBraveKeyInput] = React.useState("");
  const [tavilyKeySet, setTavilyKeySet] = React.useState(false);
  const [tavilyKeyInput, setTavilyKeyInput] = React.useState("");
  const [savingTavilyKey, setSavingTavilyKey] = React.useState(false);
  const [proxyInput, setProxyInput] = React.useState("");
  const [savingProxy, setSavingProxy] = React.useState(false);
  const [globalProxyInput, setGlobalProxyInput] = React.useState("");
  const [savingGlobalProxy, setSavingGlobalProxy] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [savingKey, setSavingKey] = React.useState(false);
  const [pyInterp, setPyInterp] = React.useState("");
  const [workers, setWorkers] = React.useState("3");
  const [savingWorkers, setSavingWorkers] = React.useState(false);
  // Task auto-finish (v0.5.0).
  const [autoFinishEnabled, setAutoFinishEnabled] = React.useState(true);
  const [autoFinishIdle, setAutoFinishIdle] = React.useState("3");
  const [autoFinishMin, setAutoFinishMin] = React.useState("5");
  const [autoFinishCoverage, setAutoFinishCoverage] = React.useState("0");
  const [autoFinishMax, setAutoFinishMax] = React.useState("80");
  const [intentBudgetEnabled, setIntentBudgetEnabled] = React.useState(true);
  const [intentBudgetTokens, setIntentBudgetTokens] = React.useState("3000000");
  const [savingIntentBudget, setSavingIntentBudget] = React.useState(false);
  const [savingAutoFinish, setSavingAutoFinish] = React.useState(false);
  // Output budget and wall-clock limit for cold-node compaction. 0 = use defaults (65536 tokens / 20 minutes).
  const [compactionTokens, setCompactionTokens] = React.useState("0");
  const [compactionTimeout, setCompactionTimeout] = React.useState("0");
  const [compactionMembers, setCompactionMembers] = React.useState("0");
  const [savingCompaction, setSavingCompaction] = React.useState(false);
  // B10: LLM profile pinned by the compactor. "0" = follow the planner (legacy behavior). Options come from the LLM profile list;
  // load failure does not block the page; only show the "Follow planner" item.
  const [compactorProfile, setCompactorProfile] = React.useState("0");
  const [llmProfileOpts, setLlmProfileOpts] = React.useState<{ id: string; name: string }[]>([]);
  // Operational constraint injection scope (both on by default).
  const [injectPlanner, setInjectPlanner] = React.useState(true);
  const [injectWorker, setInjectWorker] = React.useState(true);
  // Experimental feature: noa context compaction (off by default).
  const [noaCompaction, setNoaCompaction] = React.useState(false);
  // Pure frontend preference: does not go through /api/settings; reads/writes localStorage directly.
  const sendMode = useChatSendMode();

  const apply = React.useCallback((s: Settings) => {
    setTrafficCapture(!!s.traffic_capture);
    setAgentTrafficBinding(!!s.agent_traffic_binding);
    setWebSearch(!!s.web_search_enabled);
    setBackend(s.web_search_backend || "ddgs");
    setBraveKeySet(!!s.brave_key_set);
    setTavilyKeySet(!!s.tavily_key_set);
    setProxyInput(s.web_search_proxy ?? "");
    setGlobalProxyInput(s.global_proxy ?? "");
    setPyInterp(s.python_interpreter ?? "");
    setWorkers(String(s.workers ?? 3));
    setCompactionTokens(String(s.compaction_max_tokens ?? 0));
    setCompactionTimeout(String(s.compaction_timeout_seconds ?? 0));
    setCompactionMembers(String(s.compaction_max_members ?? 0));
    setCompactorProfile(String(s.compactor_profile_id ?? 0));
    setInjectPlanner(s.constraints_inject_planner !== false);
    setInjectWorker(s.constraints_inject_worker !== false);
    setNoaCompaction(!!s.noa_compaction);
    setAutoFinishEnabled(s.auto_finish_enabled !== false);
    setAutoFinishIdle(String(s.auto_finish_idle_rounds ?? 3));
    setAutoFinishMin(String(s.auto_finish_min_rounds ?? 5));
    setAutoFinishCoverage(String(s.auto_finish_coverage_pct ?? 0));
    setAutoFinishMax(String(s.auto_finish_max_rounds ?? 80));
    setIntentBudgetEnabled(s.intent_budget_enabled !== false);
    setIntentBudgetTokens(String(s.intent_budget_tokens ?? 3000000));
  }, []);

  const saveWorkers = () => {
    const n = Number(workers);
    if (!Number.isInteger(n) || n <= 0) {
      toast.error("Concurrency must be an integer greater than 0");
      return;
    }
    setSavingWorkers(true);
    api
      .setSettings({ workers: n })
      .then((s) => {
        apply(s);
        toast.success("Saved the number of concurrent work agents (takes effect for tasks started later)");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingWorkers(false));
  };

  const saveAutoFinish = () => {
    const idle = Number(autoFinishIdle);
    const min = Number(autoFinishMin);
    const cov = Number(autoFinishCoverage);
    const max = Number(autoFinishMax);
    if (!Number.isInteger(idle) || idle < 2 || idle > 20) {
      toast.error("Consecutive no-new-progress rounds must be between 2–20");
      return;
    }
    if (!Number.isInteger(min) || min < 1 || min > 50) {
      toast.error("Minimum planning rounds must be between 1–50");
      return;
    }
    if (!Number.isInteger(cov) || cov < 0 || cov > 100) {
      toast.error("Coverage threshold must be between 0–100 (0 = off)");
      return;
    }
    if (!Number.isInteger(max) || max < 0 || max > 500) {
      toast.error("Maximum planning rounds must be between 0–500 (0 = unlimited)");
      return;
    }
    setSavingAutoFinish(true);
    api
      .setSettings({
        auto_finish_enabled: autoFinishEnabled,
        auto_finish_idle_rounds: idle,
        auto_finish_min_rounds: min,
        auto_finish_coverage_pct: cov,
        auto_finish_max_rounds: max,
      })
      .then((s) => {
        apply(s);
        toast.success("Saved auto-finish settings (takes effect next planning round)");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingAutoFinish(false));
  };

  const saveIntentBudget = () => {
    const tokens = Number(intentBudgetTokens);
    if (!Number.isInteger(tokens) || tokens < 500000 || tokens > 20000000) {
      toast.error("Intent token budget must be between 500000–20000000");
      return;
    }
    setSavingIntentBudget(true);
    api
      .setSettings({ intent_budget_enabled: intentBudgetEnabled, intent_budget_tokens: tokens })
      .then((s) => {
        apply(s);
        toast.success("Saved intent budget (takes effect for intents started later)");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingIntentBudget(false));
  };

  const saveCompaction = () => {
    const t = Number(compactionTokens);
    const to = Number(compactionTimeout);
    const m = Number(compactionMembers);
    if (!Number.isInteger(t) || t < 0) {
      toast.error("Output budget must be an integer not less than 0 (0 = default)");
      return;
    }
    if (!Number.isInteger(to) || to < 0) {
      toast.error("Timeout must be an integer number of seconds not less than 0 (0 = default)");
      return;
    }
    if (!Number.isInteger(m) || m < 0) {
      toast.error("Nodes per chunk must be an integer not less than 0 (0 = default)");
      return;
    }
    setSavingCompaction(true);
    api
      .setSettings({
        compaction_max_tokens: t,
        compaction_timeout_seconds: to,
        compaction_max_members: m,
      })
      .then((s) => {
        apply(s);
        toast.success("Saved compaction parameters (takes effect for tasks started later)");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingCompaction(false));
  };

  const savePython = () => {    setSaving(true);
    api
      .setSettings({ python_interpreter: pyInterp.trim() })
      .then((s) => {
        apply(s);
        toast.success("Saved Python interpreter configuration");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSaving(false));
  };
  const detectPython = () => {
    setSaving(true);
    api
      .detectPython()
      .then((r) => setPyInterp(r.python_interpreter))
      .catch(() => undefined)
      .finally(() => setSaving(false));
  };

  React.useEffect(() => {
    api
      .settings()
      .then(apply)
      .catch(() => undefined)
      .finally(() => setLoaded(true));
    // B10: The compactor model dropdown needs the profile list. Best-effort — failure just means fewer options.
    api
      .llmProfiles()
      .then((ps) => setLlmProfileOpts(ps.map((p) => ({ id: p.id, name: p.name }))))
      .catch(() => setLlmProfileOpts([]));
  }, [apply]);

  const toggleTraffic = (v: boolean) => {
    setTrafficCapture(v); // optimistic
    setSaving(true);
    api
      .setSettings({ traffic_capture: v })
      .then(apply)
      .catch(() => setTrafficCapture(!v)) // revert on failure
      .finally(() => setSaving(false));
  };

  const toggleInjectPlanner = (v: boolean) => {
    setInjectPlanner(v); // optimistic
    api
      .setSettings({ constraints_inject_planner: v })
      .then(apply)
      .catch(() => setInjectPlanner(!v)); // revert on failure
  };

  const toggleAgentTrafficBinding = (v: boolean) => {
    setAgentTrafficBinding(v);
    setSaving(true);
    api
      .setSettings({ agent_traffic_binding: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "Enabled automatic traffic binding for the Agent" : "Disabled automatic traffic binding for the Agent");
      })
      .catch((e) => {
        setAgentTrafficBinding(!v);
        toast.error(`Save failed: ${(e as Error).message}`);
      })
      .finally(() => setSaving(false));
  };

  const toggleInjectWorker = (v: boolean) => {
    setInjectWorker(v); // optimistic
    api
      .setSettings({ constraints_inject_worker: v })
      .then(apply)
      .catch(() => setInjectWorker(!v)); // revert on failure
  };

  const toggleNoaCompaction = (v: boolean) => {
    setNoaCompaction(v); // optimistic
    api
      .setSettings({ noa_compaction: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "Enabled noa context compaction (takes effect for runs started later)" : "Disabled noa context compaction (restored built-in compaction)");
      })
      .catch((e) => {
        setNoaCompaction(!v); // revert on failure
        toast.error(`Save failed: ${(e as Error).message}`);
      });
  };

  // B10: The compactor-pinned profile is saved immediately on onValueChange (optimistic update). It takes effect for tasks started later
  // and for the next round of running tasks — the backend rebuilds the task's agent set on save.
  const saveCompactorProfile = (v: string) => {
    const prev = compactorProfile;
    setCompactorProfile(v);
    api
      .setSettings({ compactor_profile_id: Number(v) })
      .then((s) => {
        apply(s);
        toast.success(Number(v) > 0 ? "Saved compactor model (takes effect for tasks started later)" : "Restored compactor to follow the planner");
      })
      .catch((e) => {
        setCompactorProfile(prev); // revert on failure
        toast.error(`Save failed: ${(e as Error).message}`);
      });
  };

  // Persist a web-search patch (enable and/or backend). Optimistic with refetch.
  const saveWebSearch = (patch: Partial<Settings>) => {
    setSaving(true);
    api
      .setSettings(patch)
      .then((s) => {
        apply(s);
        toast.success("Saved web search configuration");
      })
      .catch((e) => {
        toast.error(`Save failed: ${(e as Error).message}`);
        api
          .settings()
          .then(apply)
          .catch(() => undefined);
      })
      .finally(() => setSaving(false));
  };

  const saveBraveKey = () => {
    setSavingKey(true);
    api
      .setSettings({ brave_search_api_key: braveKeyInput })
      .then((s) => {
        apply(s);
        setBraveKeyInput("");
        toast.success("Saved Brave API Key");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingKey(false));
  };

  const saveTavilyKey = () => {
    setSavingTavilyKey(true);
    api
      .setSettings({ tavily_search_api_key: tavilyKeyInput })
      .then((s) => {
        apply(s);
        setTavilyKeyInput("");
        toast.success("Saved Tavily API Key");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingTavilyKey(false));
  };

  const saveProxy = () => {
    setSavingProxy(true);
    api
      .setSettings({ web_search_proxy: proxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(proxyInput.trim() ? "Saved egress proxy" : "Cleared egress proxy (switched to direct connection)");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingProxy(false));
  };

  const saveGlobalProxy = () => {
    setSavingGlobalProxy(true);
    api
      .setSettings({ global_proxy: globalProxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(globalProxyInput.trim() ? "Saved global proxy" : "Cleared global proxy (switched to direct connection)");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingGlobalProxy(false));
  };


  // Run a real "test" search ("test") against the CURRENT form values (backend +
  // proxy + entered key), falling back to saved values server-side. Toasts result.
  const runTest = () => {
    setTesting(true);
    api
      .testWebSearch({
        web_search_backend: backend,
        web_search_proxy: proxyInput.trim(),
        brave_search_api_key: braveKeyInput,
        tavily_search_api_key: tavilyKeyInput,
      })
      .then((r) => {
        if (r.ok) toast.success(`Search test succeeded · ${r.backend} returned ${r.count} results`);
        else toast.error(`Search test failed: ${r.error || "Unknown error"}`);
      })
      .catch((e) => toast.error(`Search test failed: ${(e as Error).message}`))
      .finally(() => setTesting(false));
  };

  // brave-free selected but no key stored and none being entered → tool stays off.
  const braveNeedsKey = webSearch && backend === "brave-free" && !braveKeySet;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="font-semibold text-xl tracking-tight">System Settings</h1>
        <p className="text-muted-foreground text-sm">Global runtime switches</p>
      </div>

      {/* Multiple columns instead of grid: the web search card is several times taller than the rest, and its height varies with the selected backend (brave/tavily
          key inputs are conditionally rendered). A grid would stretch the whole row to the tallest card, leaving large blank spaces beside it,
          while multiple columns balance fill by content height automatically. Card spacing uses mb rather than gap — in a multi-column layout
          column-gap only governs spacing between columns, so row spacing must be provided by the children themselves. */}
      <div className="columns-1 gap-4 md:gap-6 lg:columns-2">
        <UpdateCard />

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Traffic Capture
            </CardTitle>
            <CardDescription>
              When enabled, all Agents' HTTP traffic is fully recorded to the database via the recording proxy, and traffic_search / traffic_get tools are injected into Agents
              along with proxy configuration (the prompt includes proxy instructions).
              <br />
              When disabled (the default), no traffic is recorded: Agents
              {" "}<b>will not</b> receive proxy configuration or traffic tools, and the prompt <b>does not</b> contain anything about proxies. Toggling rebuilds Agents immediately to take effect.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="traffic-capture" className="font-normal text-muted-foreground text-sm">
              {trafficCapture ? "Enabled · Recording traffic and injecting proxy" : "Disabled · No recording, no proxy injection"}
            </Label>
            <Switch
              id="traffic-capture"
              checked={trafficCapture}
              disabled={!loaded || saving}
              onCheckedChange={toggleTraffic}
            />
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Agent Automatic Traffic Binding
            </CardTitle>
            <CardDescription id="agent-traffic-binding-description">
              Off by default. When enabled, the report Agent triggered when a vulnerability is stored checks existing HTTP requests/responses and associates the matching traffic before writing the report.
              {" "}<b>Reviewing packets and extra tool calls increase token consumption.</b>
              <br />
              Reporting still works normally for TCP, unrecorded traffic, or when no matching traffic exists. This switch does not affect traffic capture, manual binding, or viewing saved evidence. It takes effect for the next round of Agents;
              disabling it immediately rejects new automatic bindings.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="agent-traffic-binding" className="font-normal text-muted-foreground text-sm">
              {agentTrafficBinding ? "Enabled · Increases token consumption" : "Disabled · Manual binding still available"}
            </Label>
            <Switch
              id="agent-traffic-binding"
              aria-describedby="agent-traffic-binding-description"
              checked={agentTrafficBinding}
              disabled={!loaded || saving}
              onCheckedChange={toggleAgentTrafficBinding}
            />
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Global Proxy
            </CardTitle>
            <CardDescription>
              All Agents' <b>target traffic</b> exits through this proxy (hiding the source IP / via a jump host). Supports <b>http / https / socks5</b>, optionally with{" "}
              <code>user:pass</code> authentication. Leave blank = direct connection.
              <br />
              When <b>Traffic Capture</b> is enabled, it acts as the <b>upstream</b> of the recording proxy (traffic is still fully recorded, then exits through this proxy); when capture is off, it is injected directly into
              Agents' bash / WebFetch for egress. Independent of the web search proxy and the LLM proxy.
              <br />
              <b>Tip</b>: with capture <b>off</b>, socks5 relies on each command-line tool's support for <code>ALL_PROXY</code> (curl
              works, some tools may ignore it); if you mainly use socks5, it is recommended to enable Traffic Capture — on this path the MITM
              dials the connection itself, so tools are unaware of it and it works reliably.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Label htmlFor="global-proxy" className="font-normal text-muted-foreground text-sm">
              Proxy Address
            </Label>
            <div className="flex items-center gap-2">
              <Input
                id="global-proxy"
                autoComplete="off"
                placeholder="socks5://user:pass@host:1080 or http://host:port (leave blank = direct connection)"
                value={globalProxyInput}
                disabled={!loaded || savingGlobalProxy}
                onChange={(e) => setGlobalProxyInput(e.target.value)}
              />
              <Button type="button" onClick={saveGlobalProxy} disabled={!loaded || savingGlobalProxy}>
                Save
              </Button>
            </div>
            <p className="text-muted-foreground text-xs">
              {globalProxyInput.trim() ? "Configured · All target traffic exits through this proxy" : "Not configured · Target traffic exits directly"}
            </p>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlertIcon className="size-4" />
              Operational Constraint Injection
            </CardTitle>
            <CardDescription>
              When enabled, each task's <b>operational constraints</b> (the allow/deny entries maintained under "Operational Constraints" in the task overview) are appended to the corresponding Agent's
              system prompt to bound the exploration scope (e.g. "only test the current port", "no brute forcing").
              <br />
              Injection into the <b>planner</b> and the <b>worker</b> can be controlled separately;
              both are on by default. Toggling takes effect immediately (read on the next round), no Agent rebuild needed. After disabling, that Agent no longer sees the constraints.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="inject-planner" className="font-normal text-muted-foreground text-sm">
                Inject into planner{injectPlanner ? " · Enabled" : " · Disabled"}
              </Label>
              <Switch
                id="inject-planner"
                checked={injectPlanner}
                disabled={!loaded}
                onCheckedChange={toggleInjectPlanner}
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="inject-worker" className="font-normal text-muted-foreground text-sm">
                Inject into worker{injectWorker ? " · Enabled" : " · Disabled"}
              </Label>
              <Switch
                id="inject-worker"
                checked={injectWorker}
                disabled={!loaded}
                onCheckedChange={toggleInjectWorker}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <FlaskConicalIcon className="size-4" />
              Experimental Features
            </CardTitle>
            <CardDescription>
              Mechanisms still under validation, off by default. They may change Agent behavior or affect stability; enable only after understanding the impact.
              <br />
              <b>noa context compaction</b>: the model proactively compresses long conversation history (norma v0.4.0). When enabled, the four types of Agents integrated into the platform (
              <b>planner / worker / main Agent / chat</b>) switch to noa for context management, replacing built-in compaction,
              the original compacted text is archived under the task's working directory for easy traceback. Toggling takes effect immediately (for runs started later), no Agent rebuild needed;
              disabling it immediately restores built-in compaction.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="noa-compaction" className="font-normal text-muted-foreground text-sm">
              noa context compaction{noaCompaction ? " · Enabled" : " · Disabled"}
            </Label>
            <Switch
              id="noa-compaction"
              checked={noaCompaction}
              disabled={!loaded}
              onCheckedChange={toggleNoaCompaction}
            />
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SearchIcon className="size-4" />
              Web Search
            </CardTitle>
            <CardDescription>
              This is the <b>master switch + source configuration</b> for web search. Only when it is on can you choose individually in <b>each Agent's configuration</b> whether to enable
              {" "}<b>web_search</b> (returns only title/link/snippet, does not fetch the body; fetching is handled by WebFetch). Web search <b>does not go through</b>
              the recording proxy and is independent of traffic capture.
              <br />
              Available sources: <b>DuckDuckGo (ddgs)</b> (no Key needed), <b>Brave (free tier)</b> (requires a Brave API Key),{" "}
              <b>Tavily</b> (requires a Tavily API Key), or <b>DeepSeek</b> (reuses the current LLM profile). When the master switch is off, each
              Agent's web search toggle is unavailable.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="web-search" className="font-normal text-muted-foreground text-sm">
                {webSearch ? "Master switch on · Can be enabled individually in each Agent's configuration" : "Off · Agents cannot enable web search"}
              </Label>
              <Switch
                id="web-search"
                checked={webSearch}
                disabled={!loaded || saving}
                onCheckedChange={(v) => {
                  setWebSearch(v); // optimistic
                  saveWebSearch({ web_search_enabled: v });
                }}
              />
            </div>

            {webSearch && (
              <div className="flex items-center justify-between gap-4">
                <Label className="font-normal text-muted-foreground text-sm">Search Source</Label>
                <Select
                  value={backend}
                  disabled={!loaded || saving}
                  onValueChange={(v) => {
                    setBackend(v); // optimistic
                    saveWebSearch({ web_search_backend: v });
                  }}
                >
                  <SelectTrigger className="w-48 shrink-0">
                    <SelectValue placeholder="Select a source" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ddgs">DuckDuckGo (ddgs · free, no Key)</SelectItem>
                    <SelectItem value="brave-free">Brave (free tier · Key required)</SelectItem>
                    <SelectItem value="tavily">Tavily (Key required)</SelectItem>
                    <SelectItem value="deepseek">DeepSeek (official)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}

            {webSearch && backend === "deepseek" && (
              <div className="flex flex-col gap-2 rounded-md border border-border/60 bg-muted/30 p-3">
                <p className="font-medium text-sm">DeepSeek Official Web Search</p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  This source directly reuses the <b>currently active LLM profile</b>. Therefore it
                  {" "}<b>only supports official DeepSeek models</b>, and that profile <b>must use the anthropic protocol</b>
                  — DeepSeek's OpenAI-protocol endpoint does not support server-side search. This source may stop working after switching LLM profiles.
                </p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  Unlike other sources, search is <b>performed by DeepSeek's server</b>: each search consumes one extra model call (incurring token
                  cost), and search requests <b>do not pass through the egress proxy above</b> nor <b>count toward traffic records</b>; returned results contain <b>only titles and links</b>
                  (no snippets), with WebFetch fetching the body when needed.
                </p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  You are responsible for confirming the above conditions; the system does not block anything. You can use the "Test Search" button below to run a real query and verify.
                </p>
              </div>
            )}

            {webSearch && backend === "brave-free" && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="brave-key" className="font-normal text-muted-foreground text-sm">
                  Brave Search API Key
                  {braveKeySet && <span className="ml-2 text-emerald-500 text-xs">Configured</span>}
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="brave-key"
                    type="password"
                    autoComplete="off"
                    placeholder={braveKeySet ? "Configured (leave blank to keep)" : "Enter Brave API Key"}
                    value={braveKeyInput}
                    disabled={!loaded || savingKey}
                    onChange={(e) => setBraveKeyInput(e.target.value)}
                  />
                  <Button
                    type="button"
                    onClick={saveBraveKey}
                    disabled={!loaded || savingKey || braveKeyInput.trim() === ""}
                  >
                    Save
                  </Button>
                </div>
                {braveNeedsKey && (
                  <p className="text-amber-500 text-xs">
                    Brave selected but no Key configured yet — the search tool will not be enabled until a Key is saved.
                  </p>
                )}
                <p className="text-muted-foreground text-xs">
                  The free tier allows about 2,000 queries/month. Go to https://brave.com/search/api/ to get a Key.
                </p>
              </div>
            )}

            {webSearch && backend === "tavily" && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="tavily-key" className="font-normal text-muted-foreground text-sm">
                  Tavily Search API Key
                  {tavilyKeySet && <span className="ml-2 text-emerald-500 text-xs">Configured</span>}
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="tavily-key"
                    type="password"
                    autoComplete="off"
                    placeholder={tavilyKeySet ? "Configured (leave blank to keep)" : "Enter Tavily API Key (tvly-…)"}
                    value={tavilyKeyInput}
                    disabled={!loaded || savingTavilyKey}
                    onChange={(e) => setTavilyKeyInput(e.target.value)}
                  />
                  <Button
                    type="button"
                    onClick={saveTavilyKey}
                    disabled={!loaded || savingTavilyKey || tavilyKeyInput.trim() === ""}
                  >
                    Save
                  </Button>
                </div>
                {webSearch && backend === "tavily" && !tavilyKeySet && (
                  <p className="text-amber-500 text-xs">
                    Tavily selected but no Key configured yet — the search tool will not be enabled until a Key is saved.
                  </p>
                )}
                <p className="text-muted-foreground text-xs">Go to https://tavily.com to sign up and get an API Key.</p>
              </div>
            )}

            {webSearch && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="ws-proxy" className="font-normal text-muted-foreground text-sm">
                  Egress Proxy (optional)
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="ws-proxy"
                    autoComplete="off"
                    placeholder="http://host:port or socks5://host:port (leave blank = direct connection)"
                    value={proxyInput}
                    disabled={!loaded || savingProxy}
                    onChange={(e) => setProxyInput(e.target.value)}
                  />
                  <Button type="button" onClick={saveProxy} disabled={!loaded || savingProxy}>
                    Save
                  </Button>
                </div>
                <p className="text-muted-foreground text-xs">
                  A separate egress proxy used only to reach search endpoints (VPN/SOCKS, etc.). Unrelated to the MITM recording proxy; when the network is unreachable, access goes through this proxy.
                </p>
              </div>
            )}

            {webSearch && (
              <div className="flex items-center justify-between gap-4 border-t pt-4">
                <p className="text-muted-foreground text-xs">
                  Run a real search for "test" with the current configuration (source + proxy + Key) to verify it works.
                </p>
                <Button
                  type="button"
                  variant="outline"
                  onClick={runTest}
                  disabled={!loaded || testing}
                  className="shrink-0"
                >
                  {testing ? "Testing…" : "Test Search"}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Custom Scripts · Python Interpreter
            </CardTitle>
            <CardDescription>
              Custom <b>script</b>-type tools use it to run Python. It is auto-detected at startup (python3 preferred); you can manually enter the absolute path to a venv /
              or a specific version here. Leave blank for runtime auto-detection.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Input
                className="font-mono text-sm"
                placeholder="/usr/bin/python3 (leave blank = auto-detect)"
                value={pyInterp}
                disabled={!loaded || saving}
                onChange={(e) => setPyInterp(e.target.value)}
              />
              <Button variant="outline" onClick={detectPython} disabled={!loaded || saving}>
                Re-detect
              </Button>
              <Button onClick={savePython} disabled={!loaded || saving}>
                Save
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CpuIcon className="size-4" />
              Work Concurrency · Work Agent Count
            </CardTitle>
            <CardDescription>
              The number of work agents running concurrently per task (default 3). A higher value means more concurrent probing and higher consumption. Changes
              {" "}<b>take effect for tasks started later</b>; running tasks are unaffected.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={1}
                className="w-32 font-mono text-sm"
                placeholder="3"
                value={workers}
                disabled={!loaded || savingWorkers}
                onChange={(e) => setWorkers(e.target.value)}
              />
              <Button onClick={saveWorkers} disabled={!loaded || savingWorkers}>
                Save
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <TimerResetIcon className="size-4" />
              Task Auto-Finish
            </CardTitle>
            <CardDescription>
              Stop when it's time to stop: auto-finish on <b>N consecutive rounds with no new progress</b> (no growth in facts/findings/tested assets, and no running intents),
              {" "}<b>coverage target met</b> (can be disabled), or reaching the <b>maximum planning rounds</b>. The planner also ends the task directly when it judges the goal
              (goal_met) and there are no running intents. All finishes are recorded as <code>done</code>, with the reason written to the activity stream;
              paused/queued tasks are not evaluated.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg border px-3 py-2">
              <div className="flex flex-col">
                <span className="text-sm font-medium">Enable auto-finish</span>
                <span className="text-muted-foreground text-xs">When disabled, the task can only end via timeout or goal closure</span>
              </div>
              <Switch
                checked={autoFinishEnabled}
                disabled={!loaded || savingAutoFinish}
                onCheckedChange={setAutoFinishEnabled}
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-sm">
                <span>Consecutive no-progress rounds (2–20)</span>
                <Input
                  type="number"
                  min={2}
                  max={20}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishIdle}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishIdle(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>Minimum planning rounds (1–50)</span>
                <Input
                  type="number"
                  min={1}
                  max={50}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishMin}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishMin(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>Coverage threshold % (0 = off)</span>
                <Input
                  type="number"
                  min={0}
                  max={100}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishCoverage}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishCoverage(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span>Maximum planning rounds (0 = unlimited)</span>
                <Input
                  type="number"
                  min={0}
                  max={500}
                  className="w-full font-mono text-sm sm:w-40"
                  value={autoFinishMax}
                  disabled={!loaded || savingAutoFinish}
                  onChange={(e) => setAutoFinishMax(e.target.value)}
                />
              </label>
            </div>
            <div>
              <Button onClick={saveAutoFinish} disabled={!loaded || savingAutoFinish}>
                {savingAutoFinish ? "Saving…" : "Save"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <GaugeIcon className="size-4" />
              Intent-Level Soft Budget and Duplicate-Call Interception
            </CardTitle>
            <CardDescription>
              Once a single intent's cumulative tokens reach the budget, the system injects a <b>wrap-up reminder</b> into the running worker:
              stop expanding exploration, write back existing conclusions, then finish (a soft reminder that does not kill the process; task timeout and auto-finish remain the final backstop).
              Default is 3 million — in Task 5 the measured per-intent average was ≈3 million; intents beyond that are usually spinning their wheels.
              <br />
              Duplicate-call interception is tied to this switch: the same tool with exactly identical arguments called 3 times in a row is blocked and fed back a correction prompt
              (at most 2 blocks per same sequence, then allowed through as a backstop so it never deadlocks). Changes <b>take effect for intents started later</b>.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg border px-3 py-2">
              <div className="flex flex-col">
                <span className="text-sm font-medium">Enable intent budget reminder</span>
                <span className="text-muted-foreground text-xs">When disabled, no reminders are injected and no duplicate-call interception is performed</span>
              </div>
              <Switch
                checked={intentBudgetEnabled}
                disabled={!loaded || savingIntentBudget}
                onCheckedChange={setIntentBudgetEnabled}
              />
            </div>
            <label className="flex flex-col gap-1 text-sm">
              <span>Per-intent token budget (500000–20000000)</span>
              <Input
                type="number"
                min={500000}
                max={20000000}
                step={100000}
                className="w-full font-mono text-sm sm:w-48"
                value={intentBudgetTokens}
                disabled={!loaded || savingIntentBudget}
                onChange={(e) => setIntentBudgetTokens(e.target.value)}
              />
            </label>
            <div>
              <Button onClick={saveIntentBudget} disabled={!loaded || savingIntentBudget}>
                {savingIntentBudget ? "Saving…" : "Save"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CpuIcon className="size-4" />
              Context Compaction Parameters
            </CardTitle>
            <CardDescription>
              Cold-node compaction (compressing completed exploration conclusions into a summary) runs in the <b>background</b> and does not block agents from working;
              waiting longer only means the summary lands later.
              <br />
              <b>Output budget</b> is the allowance shared by "thinking + body": for thinking models (those that force adaptive thinking),
              their thinking length grows linearly with this allowance; set it too small and the model keeps thinking without emitting a single word of body text
              — in tests, 1500 / 2048 / 4096 / 8192 all produced empty bodies. Default 65536.
              <br />
              <b>Node limit per chunk</b> decides how many nodes are packed into one request: in tests, 9 nodes split into 3 chunks still had 1 chunk fail,
              while 6 nodes finished reliably. So very large connected components must be split. Default 6.
              <br />
              Set either to 0 to use the default. Changes <b>take effect for tasks started later</b>.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <Label htmlFor="compaction-tokens" className="w-40 shrink-0 text-sm">
                Output budget (tokens)
              </Label>
              <Input
                id="compaction-tokens"
                type="number"
                min={0}
                step={1024}
                className="w-full font-mono text-sm sm:w-40"
                placeholder="0 = default 65536"
                value={compactionTokens}
                disabled={!loaded || savingCompaction}
                onChange={(e) => setCompactionTokens(e.target.value)}
              />
              <Label htmlFor="compaction-timeout" className="w-40 shrink-0 text-sm">
                Per-call timeout (seconds)
              </Label>
              <Input
                id="compaction-timeout"
                type="number"
                min={0}
                step={60}
                className="w-full font-mono text-sm sm:w-40"
                placeholder="0 = default 1200"
                value={compactionTimeout}
                disabled={!loaded || savingCompaction}
                onChange={(e) => setCompactionTimeout(e.target.value)}
              />
              <Label htmlFor="compaction-members" className="w-40 shrink-0 text-sm">
                Node limit per chunk
              </Label>
              <Input
                id="compaction-members"
                type="number"
                min={0}
                className="w-full font-mono text-sm sm:w-40"
                placeholder="0 = default 6"
                value={compactionMembers}
                disabled={!loaded || savingCompaction}
                onChange={(e) => setCompactionMembers(e.target.value)}
              />
              <Button onClick={saveCompaction} disabled={!loaded || savingCompaction}>
                Save
              </Button>
            </div>
            {/* B10: Compactor model. When the planner runs an expensive model, pin the mechanical cold-node compaction to a cheaper one to save money;
                the one-shot design makes compaction far more speed-sensitive than chat, so a low-cost, high-speed model is actually the better fit. */}
            <div className="flex flex-wrap items-center gap-2">
              <Label htmlFor="compactor-profile" className="w-40 text-sm">
                Compactor Model
              </Label>
              <Select value={compactorProfile} onValueChange={saveCompactorProfile}>
                <SelectTrigger id="compactor-profile" className="w-72">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">Follow planner (default)</SelectItem>
                  {llmProfileOpts.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <span className="text-muted-foreground text-xs">
                Cold-node compaction is a one-shot background call, well suited to being pinned to a low-cost model to save money. If the pinned profile is deleted / has no Key,
                it automatically falls back to following the planner; when the quota is exhausted it fails directly per the binding semantics (switch profiles or change back to "Follow planner").
              </span>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyboardIcon className="size-4" />
              Chat Input Send Key
            </CardTitle>
            <CardDescription>
              The chat page and the main Agent chat input on the task detail page share this setting; it takes effect immediately after selection, no save needed.
              <br />
              This preference <b>exists only in this browser</b> and is not synced with your account; you'll need to set it again after switching browsers or clearing site data.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="chat-send-mode" className="font-normal text-muted-foreground text-sm">
              Send Method
            </Label>
            <Select value={sendMode} onValueChange={(v) => setChatSendMode(v as ChatSendMode)}>
              <SelectTrigger id="chat-send-mode" className="w-72">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CHAT_SEND_MODE_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
