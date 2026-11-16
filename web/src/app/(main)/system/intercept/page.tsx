"use client";

import * as React from "react";
import { toast } from "sonner";
import {
  BotIcon,
  ListFilterIcon,
  PencilIcon,
  PlusIcon,
  ShieldAlertIcon,
  Trash2Icon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type {
  InterceptAction,
  InterceptRule,
  JudgeConfig,
  JudgeDayUsage,
  JudgeUsage,
  LLMProfile,
  Tool,
} from "@/lib/types";

// fmtTokens compresses token counts into a compact form (1.2k / 3.4M), used for approval usage stats.
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

// JudgeStat is a stat block (label + value).
function JudgeStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border bg-muted/20 px-3 py-2">
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="mt-0.5 font-semibold text-lg tabular-nums">{value}</div>
    </div>
  );
}

// JudgeSparkbars draws a mini bar chart of daily consumption (input+output) over the last N days using pure divs, avoiding a chart library dependency.
function JudgeSparkbars({ daily }: { daily: JudgeDayUsage[] }) {
  const max = Math.max(1, ...daily.map((d) => d.input_tokens + d.output_tokens));
  return (
    <div className="flex h-16 items-end gap-0.5">
      {daily.map((d) => {
        const total = d.input_tokens + d.output_tokens;
        const h = Math.max(2, Math.round((total / max) * 100));
        return (
          <div
            key={d.date}
            title={`${d.date} · ${d.calls} calls · ${fmtTokens(total)} tokens`}
            className="min-w-[2px] flex-1 rounded-sm bg-violet-500/60 hover:bg-violet-500"
            style={{ height: `${h}%` }}
          />
        );
      })}
    </div>
  );
}

// ---- tool scope ----

// SDK tools are intentionally not seeded into the DB (they apply to every agent
// and have no per-agent binding). We hardcode them here so they still appear in
// the scope dialog.
function sdkTool(key: string, description: string): Tool {
  return { key, system: true, description, schema: {}, agents: [], enabled: true, kind: "builtin" };
}

const SDK_EXEC: Tool[] = [
  sdkTool("Bash",        "Execute commands in the shell"),
  sdkTool("WebFetch",    "Make HTTP/HTTPS requests (including proxy support)"),
  sdkTool("web_search",  "Web search"),
  sdkTool("shell_open",  "Open a persistent PTY interactive session"),
  sdkTool("shell_send",  "Send input to an interactive session"),
  sdkTool("shell_read",  "Read output from an interactive session"),
  sdkTool("shell_close", "Close an interactive session"),
  sdkTool("shell_list",  "List all interactive sessions"),
];

const SDK_WRITE: Tool[] = [
  sdkTool("Write",     "Write a file"),
  sdkTool("Edit",      "Edit a file (exact replacement)"),
  sdkTool("MultiEdit", "Batch edit a file"),
];

const SDK_KEYS = new Set([...SDK_EXEC, ...SDK_WRITE].map((t) => t.key));

function groupTools(dbTools: Tool[]) {
  const sys: Tool[] = [], custom: Tool[] = [];
  for (const t of dbTools) {
    if (SDK_KEYS.has(t.key)) continue; // already covered by hardcoded groups
    if (t.system) sys.push(t);
    else          custom.push(t);
  }
  return [
    { label: "Execution",      tools: SDK_EXEC },
    { label: "Write/Edit", tools: SDK_WRITE },
    { label: "System Tools",    tools: sys },
    { label: "Custom Tools",  tools: custom },
  ].filter((g) => g.tools.length > 0);
}

// ---- form state ----

type RuleForm = {
  name: string;
  enabled: boolean;
  priority: number;
  match_target: "tool_name" | "tool_input";
  match_type: "string" | "regex";
  pattern: string;
  action: InterceptAction;
  message: string;
  timeout_enabled: boolean;
  timeout_seconds: number;
  timeout_action: "deny" | "allow";
};

const defaultForm = (): RuleForm => ({
  name: "",
  enabled: true,
  priority: 0,
  match_target: "tool_name",
  match_type: "string",
  pattern: "",
  action: "deny",
  message: "",
  timeout_enabled: true,
  timeout_seconds: 180,
  timeout_action: "allow",
});

// ---- small components ----

function ActionBadge({ action }: { action: InterceptAction }) {
  if (action === "allow") return <Badge variant="secondary">Allow</Badge>;
  if (action === "deny")  return <Badge variant="destructive">Deny</Badge>;
  if (action === "judge") return <Badge variant="default">Agent Judge</Badge>;
  return <Badge variant="outline" className="border-amber-400 text-amber-600">Request</Badge>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label className="font-medium text-muted-foreground text-xs uppercase tracking-wide">
        {label}
      </Label>
      {children}
    </div>
  );
}

// ---- LLM fallback judge card ----

const FOLLOW_ACTIVE = "0"; // profile_id 0 = follow active/default config

const defaultJudge = (): JudgeConfig => ({
  enabled: false,
  profile_id: 0,
  prompt: "",
  timeout_seconds: 180,
  fail_action: "ask",
  ask_timeout_seconds: 180,
  ask_timeout_action: "allow",
});

function JudgeCard() {
  const [cfg, setCfg] = React.useState<JudgeConfig>(defaultJudge());
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [usage, setUsage] = React.useState<JudgeUsage | null>(null);

  // Approval usage stats: a failure doesn't interrupt the config page, only fetched when enabled.
  const loadUsage = React.useCallback(async () => {
    try {
      setUsage(await api.interceptJudgeUsage(30));
    } catch {
      // Ignore: stats being unavailable shouldn't affect config editing
    }
  }, []);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [j, ps] = await Promise.all([api.interceptGetJudgeConfig(), api.llmProfiles()]);
      setCfg(j);
      setProfiles(ps);
    } catch (e) {
      toast.error(`Failed to load model fallback config: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  // After enabling (including when the switch is initially read as true on first load), fetch approval usage stats.
  React.useEffect(() => {
    if (cfg.enabled) loadUsage();
  }, [cfg.enabled, loadUsage]);

  function patch(p: Partial<JudgeConfig>) {
    setCfg((c) => ({ ...c, ...p }));
  }

  async function save() {
    setSaving(true);
    try {
      await api.interceptSetJudgeConfig(cfg);
      toast.success("Model fallback config saved");
      await load(); // Re-read: if the prompt was cleared, refill the built-in template
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function restorePrompt() {
    // Clear the prompt and save → next time the server returns the full built-in template, refilled into the input box.
    setSaving(true);
    try {
      await api.interceptSetJudgeConfig({ ...cfg, prompt: "" });
      const j = await api.interceptGetJudgeConfig();
      setCfg(j);
      toast.success("Built-in default template restored");
    } catch (e) {
      toast.error(`Restore failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      {/* Enable switch — separate highlight bar */}
      <div
        className={`flex items-center justify-between gap-3 rounded-lg border px-4 py-3 ${
          cfg.enabled ? "border-violet-400/50 bg-violet-50/40 dark:bg-violet-950/20" : "bg-muted/40"
        }`}
      >
        <div className="flex items-center gap-2.5">
          <BotIcon className={`h-5 w-5 shrink-0 ${cfg.enabled ? "text-violet-600" : "text-muted-foreground"}`} />
          <div>
            <p className="font-semibold text-sm leading-tight">Model Fallback Approval</p>
            <p className="mt-0.5 text-muted-foreground text-xs">
              Only commands within the <span className="font-medium text-foreground">interception scope</span> and with <span className="font-medium text-foreground">no interception rule matched</span> are judged semantically by the model (allow / escalate to human / block)
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className="text-muted-foreground text-xs">{cfg.enabled ? "Enabled" : "Disabled"}</span>
          <Switch checked={cfg.enabled} disabled={loading} onCheckedChange={(v) => patch({ enabled: v })} />
        </div>
      </div>

      {/* Approval Token usage stats (globally accumulated, independent of each model config) */}
      {cfg.enabled && usage && (
        <Card>
          <CardContent className="p-4">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <p className="font-medium text-sm">Approval Token Consumption</p>
                <p className="text-muted-foreground text-xs">
                  Cumulative usage of model fallback approval, metered separately (worker=judge), not mixed with per-model config stats
                </p>
              </div>
              <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={loadUsage}>
                Refresh
              </Button>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <JudgeStat label="Approval Calls" value={usage.calls.toLocaleString()} />
              <JudgeStat label="Input Tokens" value={fmtTokens(usage.input_tokens)} />
              <JudgeStat label="Output Tokens" value={fmtTokens(usage.output_tokens)} />
              <JudgeStat label="Cache Read" value={fmtTokens(usage.cache_read_tokens)} />
              <JudgeStat label="Cache Write" value={fmtTokens(usage.cache_write_tokens)} />
            </div>
            {usage.daily.length > 0 && (
              <div className="mt-4">
                <p className="mb-2 text-[10px] text-muted-foreground uppercase tracking-wider">
                  Daily consumption over the last 30 days (input + output)
                </p>
                <JudgeSparkbars daily={usage.daily} />
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {cfg.enabled && (
        <div className="grid gap-4 lg:grid-cols-5">
          {/* Left: prompt editor (expanded directly, main area) */}
          <Card className="lg:col-span-3">
            <CardContent className="flex h-full flex-col gap-2 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-sm">Approval Prompt</p>
                  <p className="text-muted-foreground text-xs">The model judges ALLOW / ASK / DENY based on this; editable directly</p>
                </div>
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={restorePrompt} disabled={saving}>
                  Restore Default Template
                </Button>
              </div>
              <Textarea
                className="min-h-[22rem] flex-1 resize-none font-mono text-xs leading-relaxed"
                value={cfg.prompt}
                onChange={(e) => patch({ prompt: e.target.value })}
                placeholder="Leave empty to use the built-in template"
                spellCheck={false}
              />
              <p className="text-right text-[11px] text-muted-foreground">{cfg.prompt.length} chars</p>
            </CardContent>
          </Card>

          {/* Right: judgment parameters (settings panel) */}
          <Card className="lg:col-span-2">
            <CardContent className="space-y-5 p-4">
              <div className="space-y-4">
                <p className="font-semibold text-[10px] text-muted-foreground uppercase tracking-wider">Judgment Model & Strategy</p>
                <Field label="Approval Model">
                  <Select value={String(cfg.profile_id || 0)} onValueChange={(v) => patch({ profile_id: Number(v) })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value={FOLLOW_ACTIVE}>Follow Active Config</SelectItem>
                      {profiles.map((p) => (
                        <SelectItem key={p.id} value={p.id}>
                          {p.name} ({p.model})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="Model Judgment Timeout (seconds)">
                  <Input
                    type="number"
                    min={1}
                    value={cfg.timeout_seconds}
                    onChange={(e) => {
                      const n = parseInt(e.target.value, 10);
                      if (n > 0) patch({ timeout_seconds: n });
                    }}
                  />
                  <p className="text-muted-foreground mt-1 text-xs">
                    Judgment time for thinking models (those forcing adaptive thinking) varies with command length:
                    short commands take a few seconds, long ones (shell scripts of hundreds or thousands of characters) noticeably longer; when the body is empty it also
                    raises the budget and retries. Setting it too short misjudges "the model could actually judge" as a timeout failure — default 180 seconds.
                  </p>
                </Field>
                <Field label="On Model Failure (error / timeout / unparseable)">
                  <Select value={cfg.fail_action} onValueChange={(v) => patch({ fail_action: v as JudgeConfig["fail_action"] })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ask">Escalate to Human Approval (recommended)</SelectItem>
                      <SelectItem value="allow">Allow</SelectItem>
                      <SelectItem value="deny">Block</SelectItem>
                    </SelectContent>
                  </Select>
                  <span className="text-muted-foreground text-xs">
                    When the model is down, "Allow" means the gate opens automatically (mostly config issues: thinking incompatibility, quota exhausted, upstream 5xx),
                    escalating to a human is recommended — at least it leaves a pending task record.
                  </span>
                </Field>
              </div>

              <Separator />

              <div className="space-y-4">
                <p className="font-semibold text-[10px] text-muted-foreground uppercase tracking-wider">Human Approval (when the model rules "escalate to human")</p>
                <Field label="Approval Wait Timeout (seconds)">
                  <Input
                    type="number"
                    min={5}
                    value={cfg.ask_timeout_seconds}
                    onChange={(e) => {
                      const n = parseInt(e.target.value, 10);
                      if (n > 0) patch({ ask_timeout_seconds: n });
                    }}
                  />
                </Field>
                <Field label="Default Action After Timeout">
                  <Select value={cfg.ask_timeout_action} onValueChange={(v) => patch({ ask_timeout_action: v as JudgeConfig["ask_timeout_action"] })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="allow">Allow (recommended · won't stall when no one is around)</SelectItem>
                      <SelectItem value="deny">Block</SelectItem>
                    </SelectContent>
                  </Select>
                  <span className="text-muted-foreground text-xs">
                    Human approval **synchronously blocks** the worker executing it. If you choose "Block" and you're away from the computer,
                    the entire pentest chain stops at this command; choosing "Allow" lets it continue, and you can still see the record afterward on the
                    "Interception Approval" page and ratify it retroactively.
                  </span>
                </Field>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="flex justify-end">
        <Button size="sm" onClick={save} disabled={saving || loading}>
          {saving ? "Saving…" : "Save Config"}
        </Button>
      </div>
    </div>
  );
}

// ---- page ----

export default function InterceptPage() {
  const [rules, setRules]     = React.useState<InterceptRule[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [open, setOpen]       = React.useState(false);
  const [editing, setEditing] = React.useState<InterceptRule | null>(null);
  const [form, setForm]       = React.useState<RuleForm>(defaultForm());
  const [saving, setSaving]   = React.useState(false);
  const [regexErr, setRegexErr] = React.useState("");
  const [regexWarn, setRegexWarn] = React.useState(false); // true = JS can't parse but may be valid Go syntax

  // ---- tool scope dialog ----
  const [scopeOpen, setScopeOpen]       = React.useState(false);
  const [allTools, setAllTools]         = React.useState<Tool[]>([]);
  const [enabledTools, setEnabledTools] = React.useState<Set<string>>(new Set());
  const [scopeLoading, setScopeLoading] = React.useState(false);
  const [scopeSaving, setScopeSaving]   = React.useState(false);
  const [scopeTools, setScopeTools]     = React.useState<string[]>([]); // header info bar: tools currently in scope for interception

  // ---- data ----

  const loadScope = React.useCallback(async () => {
    try {
      const cfg = await api.interceptGetToolConfig();
      setScopeTools(cfg.enabled_tools);
    } catch {
      // Info bar is non-critical, fail silently
    }
  }, []);

  const load = React.useCallback(async () => {
    try {
      const r = await api.interceptRules();
      setRules(r);
    } catch {
      toast.error("Failed to load interception rules");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { load(); loadScope(); }, [load, loadScope]);

  React.useEffect(() => {
    if (form.match_type !== "regex" || !form.pattern) { setRegexErr(""); setRegexWarn(false); return; }
    try {
      new RegExp(form.pattern);
      setRegexErr("");
      setRegexWarn(false);
    } catch {
      // JS RegExp doesn't support Go RE2 extension syntax (e.g. (?i) inline flags).
      // A preview validation failure here doesn't mean it's invalid on the Go side; leave final validation to the server.
      setRegexErr("");
      setRegexWarn(true);
    }
  }, [form.pattern, form.match_type]);

  // ---- rule handlers ----

  function set(patch: Partial<RuleForm>) { setForm(f => ({ ...f, ...patch })); }

  function openNew() {
    setEditing(null);
    setForm(defaultForm());
    setRegexErr("");
    setOpen(true);
  }

  function openEdit(rule: InterceptRule) {
    setEditing(rule);
    setForm({
      name: rule.name, enabled: rule.enabled, priority: rule.priority,
      match_target: rule.match_target, match_type: rule.match_type,
      pattern: rule.pattern, action: rule.action, message: rule.message,
      timeout_enabled: rule.timeout_enabled, timeout_seconds: rule.timeout_seconds,
      timeout_action: rule.timeout_action,
    });
    setRegexErr("");
    setOpen(true);
  }

  async function handleSave() {
    if (!form.name.trim())    { toast.error("Name cannot be empty"); return; }
    if (!form.pattern.trim()) { toast.error("Pattern cannot be empty"); return; }
    if (regexErr)             { toast.error("Invalid regular expression syntax"); return; }
    setSaving(true);
    try {
      if (editing) {
        await api.updateInterceptRule(editing.id, form);
        toast.success("Rule updated");
      } else {
        await api.createInterceptRule(form);
        toast.success("Rule created");
      }
      setOpen(false);
      await load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    try {
      await api.deleteInterceptRule(id);
      toast.success("Rule deleted");
      await load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function handleToggle(rule: InterceptRule) {
    try {
      await api.toggleInterceptRule(rule.id, !rule.enabled);
      await load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  // ---- scope handlers ----

  async function openScope() {
    setScopeOpen(true);
    setScopeLoading(true);
    try {
      const [tools, cfg] = await Promise.all([api.tools(), api.interceptGetToolConfig()]);
      setAllTools(tools);
      setEnabledTools(new Set(cfg.enabled_tools));
    } catch (e) {
      toast.error(`Load failed: ${(e as Error).message}`);
    } finally {
      setScopeLoading(false);
    }
  }

  function toggleTool(key: string, val: boolean) {
    setEnabledTools(prev => {
      const next = new Set(prev);
      if (val) next.add(key); else next.delete(key);
      return next;
    });
  }

  async function saveScope() {
    setScopeSaving(true);
    try {
      await api.interceptSetToolConfig([...enabledTools]);
      toast.success("Interception scope saved");
      setScopeTools([...enabledTools]);
      setScopeOpen(false);
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setScopeSaving(false);
    }
  }

  const toolGroups = React.useMemo(() => groupTools(allTools), [allTools]);

  // ---- render ----

  return (
    <div className="flex flex-1 flex-col gap-5 p-6">

      {/* ---- header ---- */}
      <div className="flex items-center gap-2.5">
        <ShieldAlertIcon className="h-5 w-5 shrink-0" />
        <div>
          <h1 className="font-semibold text-lg leading-tight">Command Interception</h1>
          <p className="mt-0.5 text-muted-foreground text-sm">
            Before a tool executes, match against interception rules first; unmatched commands can be handed to the model for fallback judgment
          </p>
        </div>
      </div>

      {/* ---- Interception scope info bar (shared by rule matching and model fallback: tools out of scope are untouched by both) ---- */}
      <div
        className={`flex items-center justify-between gap-3 rounded-lg border px-4 py-2.5 ${
          scopeTools.length === 0
            ? "border-amber-400/60 bg-amber-50/50 dark:bg-amber-950/20"
            : "bg-muted/40"
        }`}
      >
        <div className="flex min-w-0 items-center gap-2 text-sm">
          <ListFilterIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
          <span className="shrink-0 font-medium">Interception Scope</span>
          {scopeTools.length === 0 ? (
            <span className="text-amber-700 dark:text-amber-500">
              No tools enabled — neither interception rules nor model fallback will take effect
            </span>
          ) : (
            <>
              <Badge variant="secondary" className="shrink-0">{scopeTools.length} tools</Badge>
              <span className="truncate text-muted-foreground" title={scopeTools.join(", ")}>
                {scopeTools.join(", ")}
              </span>
            </>
          )}
        </div>
        <Button
          variant={scopeTools.length === 0 ? "default" : "outline"}
          size="sm"
          className="shrink-0"
          onClick={openScope}
        >
          <ListFilterIcon className="h-4 w-4" />
          Adjust Scope
        </Button>
      </div>

      <Tabs defaultValue="rules" className="flex-1">
        <TabsList>
          <TabsTrigger value="rules">Interception Rules</TabsTrigger>
          <TabsTrigger value="judge">Model Config</TabsTrigger>
        </TabsList>

        {/* ---- tab: Interception Rules ---- */}
        <TabsContent value="rules" className="mt-4 flex flex-col gap-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-muted-foreground text-xs">
              Matched one by one by priority (higher numbers first); the first matching rule takes effect
            </p>
            <Button onClick={openNew} size="sm" className="shrink-0">
              <PlusIcon className="h-4 w-4" />
              New Rule
            </Button>
          </div>

          <Card>
            <CardContent className="p-0">
          {loading ? (
            <p className="p-6 text-muted-foreground text-sm">Loading…</p>
          ) : rules.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
              <ShieldAlertIcon className="h-8 w-8 text-muted-foreground/40" />
              <p className="text-muted-foreground text-sm">No rules yet</p>
              <Button size="sm" variant="outline" onClick={openNew}>
                <PlusIcon className="h-4 w-4" />
                Create the first rule
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[72px]">Priority</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-[90px]">Target</TableHead>
                  <TableHead className="w-[80px]">Type</TableHead>
                  <TableHead>Pattern</TableHead>
                  <TableHead className="w-[72px]">Strategy</TableHead>
                  <TableHead className="w-[64px] text-center">Enabled</TableHead>
                  <TableHead className="w-[80px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id} className={!rule.enabled ? "opacity-40" : ""}>
                    <TableCell>
                      <span className="font-mono text-xs tabular-nums">{rule.priority}</span>
                    </TableCell>
                    <TableCell className="font-medium text-sm">{rule.name}</TableCell>
                    <TableCell>
                      <span className="text-muted-foreground text-xs">
                        {rule.match_target === "tool_name" ? "Tool Name" : "Input Content"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-muted-foreground text-xs">
                        {rule.match_type === "regex" ? "Regex" : "String"}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-[220px]">
                      <code className="block truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                        {rule.pattern}
                      </code>
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={rule.action} />
                      {/*
                        The timeout strategy must be shown explicitly, because it now **really takes effect**.

                        Before 2026-10-22, a rule's timeout_enabled/seconds/action
                        were dead fields: the UI showed "timeout 60s / deny after timeout", but what actually took effect
                        was the global "180s / escalate to human on failure" — what the user saw didn't match what actually happened.
                        Now the rule's own declaration takes precedence over the global, so the user must be able to
                        see "how this rule itself computes it".
                      */}
                      <div className="mt-1 whitespace-nowrap text-[10px] text-muted-foreground">
                        {rule.timeout_enabled
                          ? `Timeout ${rule.timeout_seconds}s → ${rule.timeout_action === "allow" ? "Allow" : "Deny"}`
                          : "Use global config for timeout"}
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <Switch
                        checked={rule.enabled}
                        onCheckedChange={() => handleToggle(rule)}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-0.5">
                        <Button
                          size="icon" variant="ghost" className="h-7 w-7"
                          onClick={() => openEdit(rule)}
                        >
                          <PencilIcon className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon" variant="ghost"
                          className="h-7 w-7 text-destructive hover:text-destructive"
                          onClick={() => handleDelete(rule.id)}
                        >
                          <Trash2Icon className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---- tab: Model Config ---- */}
        <TabsContent value="judge" className="mt-4">
          <JudgeCard />
        </TabsContent>
      </Tabs>

      {/* ---- editor sheet ---- */}
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="flex flex-col gap-0 p-0 sm:max-w-md">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle>{editing ? "Edit Rule" : "New Rule"}</SheetTitle>
            <SheetDescription className="text-xs">
              Higher priority matches first; the first matching rule takes effect, later ones are skipped
            </SheetDescription>
          </SheetHeader>

          <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-6 py-5">
            <Field label="Name">
              <Input
                placeholder="Give the rule a name"
                value={form.name}
                onChange={(e) => set({ name: e.target.value })}
              />
            </Field>

            <Field label="Priority (higher numbers match first)">
              <Input
                type="number"
                value={form.priority}
                onChange={(e) => set({ priority: parseInt(e.target.value, 10) || 0 })}
              />
            </Field>

            <Separator />

            <Field label="Match Target">
              <Select
                value={form.match_target}
                onValueChange={(v) => set({ match_target: v as RuleForm["match_target"] })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="tool_name">Tool Name (tool_name)</SelectItem>
                  <SelectItem value="tool_input">Input Content (tool_input JSON)</SelectItem>
                </SelectContent>
              </Select>
            </Field>

            <Field label="Match Type">
              <Select
                value={form.match_type}
                onValueChange={(v) => set({ match_type: v as RuleForm["match_type"] })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="string">String Contains</SelectItem>
                  <SelectItem value="regex">Regular Expression</SelectItem>
                </SelectContent>
              </Select>
            </Field>

            <Field label="Pattern">
              <Input
                placeholder={form.match_type === "regex" ? "^Bash$" : "rm -rf"}
                value={form.pattern}
                onChange={(e) => set({ pattern: e.target.value })}
                className={regexErr ? "border-destructive focus-visible:ring-destructive" : ""}
              />
              {regexErr && (
                <p className="mt-1 text-destructive text-xs">{regexErr}</p>
              )}
              {regexWarn && (
                <p className="mt-1 text-amber-600 text-xs">Contains Go RE2 extension syntax (such as <code className="font-mono">(?i)</code>); the browser can't preview it, the server validates on submit</p>
              )}
            </Field>

            <Separator />

            <Field label="Interception Strategy">
              <Select
                value={form.action}
                onValueChange={(v) => set({ action: v as InterceptAction })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">Allow — pass through directly, skip later rules</SelectItem>
                  <SelectItem value="deny">Deny — block, return a rejection message to the model</SelectItem>
                  <SelectItem value="ask">Request from User — wait for approval</SelectItem>
                  <SelectItem value="judge">Agent Judge — on match the model assesses risk before deciding</SelectItem>
                </SelectContent>
              </Select>
            </Field>

            {form.action === "judge" && (
              <div className="rounded-md border border-blue-500/30 bg-blue-500/5 p-3 text-xs">
                <p className="mb-1 font-medium text-blue-600 dark:text-blue-400">Agent Judge</p>
                <p className="text-muted-foreground">
                  On match, calls the adjudication model in "Model Config": read-only/normal pentest actions are allowed, actions directly destroying real assets are blocked,
                  escalating to a human only when uncertain. Adds one more LLM call (timeout, failure strategy, and usage stats all go through "Model Config").
                  This rule still takes effect even if the global fallback approval switch is off.
                </p>
              </div>
            )}

            {form.action !== "allow" && form.action !== "judge" && (
              <Field label={form.action === "deny" ? "Rejection Message (returned to the model)" : "Approval Note (optional)"}>
                <Textarea
                  placeholder={form.action === "deny" ? "Operation blocked by security policy" : ""}
                  value={form.message}
                  onChange={(e) => set({ message: e.target.value })}
                  rows={2}
                  className="resize-none"
                />
              </Field>
            )}

            {form.action === "ask" && (
              <>
                <Separator />
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">Enable Approval Timeout</p>
                    <p className="text-muted-foreground text-xs">Auto-handle after timeout, no more waiting</p>
                  </div>
                  <Switch
                    checked={form.timeout_enabled}
                    onCheckedChange={(v) => set({ timeout_enabled: v })}
                  />
                </div>
                {form.timeout_enabled && (
                  <div className="flex items-end gap-3">
                    <Field label="Timeout (seconds)">
                      <Input
                        type="number"
                        min={5}
                        className="w-28"
                        value={form.timeout_seconds}
                        onChange={(e) => {
                          const n = parseInt(e.target.value, 10);
                          if (n > 0) set({ timeout_seconds: n });
                        }}
                      />
                    </Field>
                    <Field label="Timeout Action">
                      <Select
                        value={form.timeout_action}
                        onValueChange={(v) => set({ timeout_action: v as "deny" | "allow" })}
                      >
                        <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="deny">Auto Deny</SelectItem>
                          <SelectItem value="allow">Auto Allow</SelectItem>
                        </SelectContent>
                      </Select>
                    </Field>
                  </div>
                )}
              </>
            )}

            <Separator />

            <div className="flex items-center gap-3">
              <Switch
                id="rule-enabled"
                checked={form.enabled}
                onCheckedChange={(v) => set({ enabled: v })}
              />
              <Label htmlFor="rule-enabled" className="cursor-pointer">Enable this rule</Label>
            </div>
          </div>

          <SheetFooter className="flex-row justify-end gap-2 border-t px-6 py-4">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !!regexErr}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      {/* ---- scope dialog ---- */}
      <Dialog open={scopeOpen} onOpenChange={setScopeOpen}>
        <DialogContent className="flex flex-col gap-0 overflow-hidden p-0 sm:max-w-lg" style={{ maxHeight: "min(80vh, 560px)" }}>
          <DialogHeader className="shrink-0 border-b px-6 py-4">
            <DialogTitle className="flex items-center gap-2">
              <ListFilterIcon className="h-4 w-4" />
              Interception Scope
            </DialogTitle>
            <DialogDescription className="text-xs">
              Only tools with interception enabled enter rule matching; all other tools pass through directly
            </DialogDescription>
          </DialogHeader>

          <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-6 py-4">
            {scopeLoading ? (
              <p className="py-4 text-muted-foreground text-sm">Loading…</p>
            ) : (
              toolGroups.map((group, gi) => (
                <div key={group.label}>
                  {gi > 0 && <Separator className="mb-5" />}
                  <p className="mb-2 font-semibold text-[10px] text-muted-foreground uppercase tracking-wider">
                    {group.label}
                  </p>
                  <div className="space-y-0.5">
                    {group.tools.map((t) => (
                      <div key={t.key} className="flex items-center gap-3 rounded-md px-2 py-1.5 hover:bg-muted/50">
                        <Switch
                          id={`scope-${t.key}`}
                          checked={enabledTools.has(t.key)}
                          onCheckedChange={(v) => toggleTool(t.key, v)}
                        />
                        <label htmlFor={`scope-${t.key}`} className="min-w-0 flex-1 cursor-pointer">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-sm">{t.key}</span>
                            {(t.kind && t.kind !== "builtin") && (
                              <Badge variant="outline" className="px-1 py-0 text-[10px]">{t.kind}</Badge>
                            )}
                          </div>
                          {t.description && (
                            <p className="line-clamp-1 text-[11px] text-muted-foreground">{t.description}</p>
                          )}
                        </label>
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="flex shrink-0 justify-end gap-2 border-t px-6 py-3">
            <Button variant="outline" size="sm" onClick={() => setScopeOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={saveScope} disabled={scopeSaving || scopeLoading}>
              {scopeSaving ? "Saving…" : "Save"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
