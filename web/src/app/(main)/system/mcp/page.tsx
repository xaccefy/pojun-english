"use client";

import * as React from "react";
import { toast } from "sonner";
import { PlusIcon, RefreshCwIcon, ServerIcon, Trash2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { MCPServer, MCPTool, Agent } from "@/lib/types";

type Transport = "stdio" | "http" | "sse";
type FormState = {
  name: string;
  transport: Transport;
  command: string;
  args: string;
  url: string;
  env: string;
  insecure: boolean;
};
const emptyForm: FormState = {
  name: "",
  transport: "stdio",
  command: "",
  args: "",
  url: "",
  env: "",
  insecure: false,
};

// Common MCP preset catalog (v0.4.56): one-click form filling, no need to
// memorize package names and launch arguments by hand.
// Only publicly available official/mainstream implementations are included;
// the dialog hints at missing dependencies (e.g. uvx requires uv installed first).
type MCPPreset = {
  name: string;
  title: string;
  description: string;
  transport: Transport;
  command?: string;
  args?: string;
  url?: string;
  requires?: string; // Runtime prerequisite hint
};

const mcpPresets: MCPPreset[] = [
  {
    name: "playwright",
    title: "Playwright Browser",
    description: "Browser automation: render real pages, take screenshots, read the DOM, fill forms.",
    transport: "stdio",
    command: "npx",
    args: "@playwright/mcp@latest --headless --no-sandbox",
    requires: "Bundled in the image; bare metal requires node ≥ 20",
  },
  {
    name: "chrome-devtools",
    title: "Chrome DevTools",
    description: "Chrome native debugging protocol: performance tracing, network requests, console and DOM inspection.",
    transport: "stdio",
    command: "npx",
    args: "chrome-devtools-mcp@latest --headless",
    requires: "Requires local Chrome/Chromium",
  },
  {
    name: "burp",
    title: "Burp Suite MCP",
    description: "Connect to Burp's proxy history and scanning capabilities (official MCP extension).",
    transport: "sse",
    url: "http://127.0.0.1:9876/sse",
    requires: "Requires Burp with the MCP extension installed and port 9876 open",
  },
  {
    name: "fetch",
    title: "Fetch Web Scraping",
    description: "Fetch web pages and convert the body to Markdown for analysis (external references, docs).",
    transport: "stdio",
    command: "uvx",
    args: "mcp-server-fetch",
    requires: "Requires uv (pip install uv)",
  },
  {
    name: "sequential-thinking",
    title: "Sequential Thinking",
    description: "Step-by-step reasoning scratchpad: break complex problems into a backtrackable chain of thought.",
    transport: "stdio",
    command: "npx",
    args: "@modelcontextprotocol/server-sequential-thinking",
    requires: "Requires node ≥ 18",
  },
  {
    name: "memory",
    title: "Memory Knowledge Base",
    description: "Persistent entity/relation memory across sessions (local JSON).",
    transport: "stdio",
    command: "npx",
    args: "@modelcontextprotocol/server-memory",
    requires: "Requires node ≥ 18",
  },
  {
    name: "filesystem",
    title: "Filesystem Access",
    description: "Read and write files in a specified directory (defaults to the task data directory).",
    transport: "stdio",
    command: "npx",
    args: "@modelcontextprotocol/server-filesystem /opt/pojun/data",
    requires: "Requires node ≥ 18; adjust the path as needed",
  },
  {
    name: "hexstrike",
    title: "HexStrike Tool Bridge",
    description: "Bridges 150+ security tools (nmap/sqlmap/metasploit/nuclei/ghidra…), orchestrated uniformly by AI.",
    transport: "stdio",
    command: "python3",
    args: "mcp-servers/hexstrike-ai/hexstrike_mcp.py --server http://127.0.0.1:5000",
    requires: "First clone hexstrike-ai into mcp-servers/ and start hexstrike_server.py (:5000)",
  },
  {
    name: "fofa",
    title: "FOFA Asset Mapping",
    description: "Search assets by domain/certificate/port/fingerprint (built-in one-fox channel with multi-account rotation).",
    transport: "stdio",
    command: "uv",
    args: "--directory mcp-servers/fofa run python fofa.py",
    requires: "Requires uv (--with-tools installed); set FOFA_EMAIL/FOFA_KEY in the environment variables",
  },
  {
    name: "context7",
    title: "Context7 Documentation Lookup",
    description: "Look up the latest official docs and usage by library name (check APIs when writing PoCs).",
    transport: "stdio",
    command: "npx",
    args: "@upstash/context7-mcp",
    requires: "Requires node ≥ 18; for heavy use set API_KEY in the environment variables",
  },
];

export default function MCPPage() {
  const [servers, setServers] = React.useState<MCPServer[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [visibility, setVisibility] = React.useState<Record<number, string[]>>({});

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<MCPServer | null>(null); // null = add mode
  // Deletion confirmation (aligned with the standard tasks/skills interaction:
  // deleting directly changes the tool surface available to agents, so confirmation is required)
  const [pendingDelete, setPendingDelete] = React.useState<MCPServer | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [tab, setTab] = React.useState<"config" | "tools">("config");
  const [form, setForm] = React.useState<FormState>(emptyForm);
  const [saving, setSaving] = React.useState(false);
  const [tools, setTools] = React.useState<MCPTool[]>([]);
  const [toolsLoading, setToolsLoading] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  const load = React.useCallback(() => {
    api.agents().then(setAgents).catch(() => {});
    api
      .mcpServers()
      .then((ss) => {
        setServers(ss);
        ss.forEach((s) =>
          api
            .resourceVisibility("mcp", s.id)
            .then((ids) => setVisibility((v) => ({ ...v, [s.id]: ids })))
            .catch(() => {}),
        );
      })
      .catch(() => {});
  }, []);
  React.useEffect(() => {
    load();
  }, [load]);

  function setF(patch: Partial<FormState>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function parseEnv(text: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const idx = trimmed.indexOf("=");
      if (idx > 0) {
        const key = trimmed.slice(0, idx).trim();
        if (key) out[key] = trimmed.slice(idx + 1).trim();
      }
    }
    return out;
  }
  function envToText(env: Record<string, string> | undefined): string {
    return Object.entries(env ?? {})
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");
  }

  function openAdd() {
    setEditing(null);
    setForm(emptyForm);
    setTools([]);
    setTab("config");
    setOpen(true);
  }

  function openPreset(p: MCPPreset) {
    setEditing(null);
    setForm({
      name: p.name,
      transport: p.transport,
      command: p.command ?? "",
      args: p.args ?? "",
      url: p.url ?? "",
      env: "",
      insecure: false,
    });
    setTools([]);
    setTab("config");
    setOpen(true);
  }

  function openEdit(s: MCPServer) {
    setEditing(s);
    setForm({
      name: s.name,
      transport: s.transport,
      command: s.command ?? "",
      args: (s.args ?? []).join(" "),
      url: s.url ?? "",
      env: envToText(s.env),
      insecure: s.insecure ?? false,
    });
    setTab("config");
    setOpen(true);
    loadTools(s.id);
  }

  async function loadTools(id: number) {
    setToolsLoading(true);
    try {
      setTools(await api.mcpTools(id));
    } catch {
      setTools([]);
    } finally {
      setToolsLoading(false);
    }
  }

  async function saveForm() {
    if (!form.name.trim()) {
      toast.error("Please enter a name");
      return;
    }
    if (form.transport === "stdio" && !form.command.trim()) {
      toast.error("Please enter a command");
      return;
    }
    if (form.transport !== "stdio" && !form.url.trim()) {
      toast.error("Please enter a remote URL");
      return;
    }
    setSaving(true);
    try {
      const base =
        form.transport !== "stdio"
          ? {
              transport: form.transport,
              url: form.url.trim(),
              command: "",
              args: [] as string[],
              env: parseEnv(form.env), // in remote mode, env is the request headers
              insecure: form.insecure,
            }
          : {
              transport: "stdio" as const,
              command: form.command.trim(),
              args: form.args.trim() ? form.args.trim().split(/\s+/) : [],
              env: parseEnv(form.env),
              insecure: false,
            };
      await api.saveMcpServer({
        ...(editing ? { id: editing.id } : {}),
        name: form.name.trim(),
        enabled: editing ? editing.enabled : true,
        ...base,
      });
      toast.success(editing ? "Saved" : "MCP server added");
      if (!editing) setOpen(false);
      load();
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function refreshTools() {
    if (!editing) return;
    setRefreshing(true);
    try {
      const t = await api.refreshMcpServer(editing.id);
      setTools(t);
      toast.success(`Discovered ${t.length} tools`);
      load();
    } catch (e) {
      toast.error(`Refresh failed: ${(e as Error).message}`);
    } finally {
      setRefreshing(false);
    }
  }

  async function removeServer(s: MCPServer) {
    setDeleting(true);
    try {
      await api.deleteMcpServer(s.id);
      toast.success(`Deleted: ${s.name}`);
      setOpen(false);
      load();
      setPendingDelete(null);
    } catch (e) {
      toast.error(`Delete failed: ${(e as Error).message}`);
    } finally {
      setDeleting(false);
    }
  }

  async function toggleEnabled(s: MCPServer) {
    try {
      await api.saveMcpServer({ ...s, enabled: !s.enabled });
      load();
    } catch (e) {
      toast.error(`Operation failed: ${(e as Error).message}`);
    }
  }

  async function toggleVisibility(serverId: number, agentId: string, agentName: string) {
    const on = (visibility[serverId] ?? []).includes(agentId);
    try {
      await api.toggleVisibility(agentId, "mcp", serverId, !on);
      toast.success(`${on ? "Revoked" : "Granted"} visibility to "${agentName}"`);
      load();
    } catch (e) {
      toast.error(`Operation failed: ${(e as Error).message}`);
    }
  }

  function renderForm() {
    return (
      <div className="grid gap-4 py-4">
        <div className="grid gap-2">
          <Label>Transport</Label>
          <div className="flex gap-2">
            <Button
              type="button"
              variant={form.transport === "stdio" ? "default" : "outline"}
              onClick={() => setF({ transport: "stdio" })}
            >
              stdio (local)
            </Button>
            <Button
              type="button"
              variant={form.transport === "http" ? "default" : "outline"}
              onClick={() => setF({ transport: "http" })}
            >
              http (remote)
            </Button>
            <Button
              type="button"
              variant={form.transport === "sse" ? "default" : "outline"}
              onClick={() => setF({ transport: "sse" })}
            >
              sse (legacy)
            </Button>
          </div>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="m-name">Name</Label>
          <Input
            id="m-name"
            placeholder="filesystem"
            value={form.name}
            onChange={(e) => setF({ name: e.target.value })}
          />
        </div>
        {form.transport === "stdio" ? (
          <>
            <div className="grid gap-2">
              <Label htmlFor="m-cmd">Command</Label>
              <Input
                id="m-cmd"
                className="font-mono"
                placeholder="npx"
                value={form.command}
                onChange={(e) => setF({ command: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="m-args">Arguments (space-separated)</Label>
              <Input
                id="m-args"
                className="font-mono"
                placeholder="-y @modelcontextprotocol/server-filesystem /data"
                value={form.args}
                onChange={(e) => setF({ args: e.target.value })}
              />
            </div>
          </>
        ) : (
          <div className="grid gap-2">
            <Label htmlFor="m-url">Remote URL</Label>
            <Input
              id="m-url"
              className="font-mono"
              placeholder="https://mcp.example.com/mcp"
              value={form.url}
              onChange={(e) => setF({ url: e.target.value })}
            />
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={form.insecure}
                onCheckedChange={(v) => setF({ insecure: v === true })}
              />
              Skip TLS certificate verification (self-signed certificates)
            </label>
          </div>
        )}
        <div className="grid gap-2">
          <Label htmlFor="m-env">
            {form.transport !== "stdio"
              ? "Request headers (one KEY=VALUE per line, e.g. Authorization=Bearer xxx)"
              : "Environment variables (one KEY=VALUE per line)"}
          </Label>
          <Textarea
            id="m-env"
            className="font-mono"
            placeholder={
              form.transport !== "stdio" ? "Authorization=Bearer xxxx" : "API_KEY=xxxx\nFOO=bar"
            }
            value={form.env}
            onChange={(e) => setF({ env: e.target.value })}
          />
        </div>
      </div>
    );
  }

  function renderTools() {
    return (
      <div className="flex flex-col gap-3 py-4">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground text-sm">{tools.length} tools</span>
          <Button size="sm" variant="outline" disabled={refreshing} onClick={refreshTools}>
            <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> Refresh
          </Button>
        </div>
        {toolsLoading ? (
          <p className="text-muted-foreground text-sm">Loading…</p>
        ) : tools.length === 0 ? (
          <p className="text-muted-foreground text-sm">No tools discovered yet, click Refresh to fetch again.</p>
        ) : (
          <div className="flex flex-col divide-y">
            {tools.map((t) => (
              <div key={t.name} className="py-2.5">
                <code className="font-mono text-sm">{t.name}</code>
                {t.description && (
                  <p className="mt-0.5 text-muted-foreground text-xs leading-relaxed">
                    {t.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="font-semibold text-xl tracking-tight">MCP</h1>
        <p className="text-muted-foreground text-sm">External MCP tool servers · visibility authorized per Agent</p>
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex items-baseline gap-2">
          <h2 className="font-medium text-sm">Common MCP Presets</h2>
          <span className="text-muted-foreground text-xs">
            Click to fill in the config, then review before saving (see each preset's note for dependencies)
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {mcpPresets.map((p) => (
            <button
              key={p.name}
              type="button"
              onClick={() => openPreset(p)}
              className="flex flex-col items-start gap-1 rounded-lg border bg-card p-3 text-left transition hover:border-primary/60 hover:shadow-sm"
            >
              <span className="flex items-center gap-2 font-medium text-sm">
                <ServerIcon className="size-4 text-muted-foreground" /> {p.title}
              </span>
              <span className="line-clamp-2 text-muted-foreground text-xs leading-relaxed">
                {p.description}
              </span>
              {p.requires ? (
                <span className="text-[11px] text-muted-foreground/80">{p.requires}</span>
              ) : null}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <button
          type="button"
          onClick={openAdd}
          className="flex min-h-[116px] flex-col items-center justify-center gap-2 rounded-xl border border-foreground/70 border-dashed text-foreground/70 transition hover:bg-muted/60 hover:shadow-sm"
        >
          <PlusIcon className="size-6" />
          <span className="text-sm">Add MCP</span>
        </button>

        {servers.map((s) => (
          <Card
            key={s.id}
            onClick={() => openEdit(s)}
            className="cursor-pointer gap-3 transition hover:border-primary/60 hover:shadow-sm"
          >
            <CardHeader>
              <div className="flex items-center gap-2">
                <ServerIcon className="size-4 shrink-0 text-muted-foreground" />
                <CardTitle className="truncate text-base">{s.name}</CardTitle>
                <Badge variant="outline" className="uppercase">
                  {s.transport}
                </Badge>
                <div className="ml-auto flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  <Switch
                    checked={s.enabled}
                    onCheckedChange={() => toggleEnabled(s)}
                    aria-label="Enable"
                  />
                  <Button
                    size="icon"
                    variant="outline"
                    aria-label="Delete"
                    onClick={() => setPendingDelete(s)}
                  >
                    <Trash2Icon className="text-destructive" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="grid gap-3">
              <p className="text-muted-foreground text-sm">
                {s.tools && s.tools.length > 0 ? `${s.tools.length} tools` : "No tools discovered yet"}
              </p>
              <div className="grid gap-2" onClick={(e) => e.stopPropagation()}>
                <span className="text-muted-foreground text-xs">Visibility (authorized per Agent)</span>
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {agents.map((a) => (
                    <label key={a.key} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={(visibility[s.id] ?? []).includes(a.id)}
                        onCheckedChange={() => toggleVisibility(s.id, a.id, a.name)}
                      />
                      {a.name}
                    </label>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent
          side="right"
          className="w-full data-[side=right]:sm:max-w-lg"
        >
          <SheetHeader>
            <SheetTitle>{editing ? editing.name : "Add MCP Server"}</SheetTitle>
            <SheetDescription>
              stdio (starts a local process) or http (remote Streamable HTTP)
            </SheetDescription>
          </SheetHeader>

          {editing ? (
            <Tabs
              value={tab}
              onValueChange={(v) => setTab(v as "config" | "tools")}
              className="flex min-h-0 flex-1 flex-col px-4"
            >
              <TabsList>
                <TabsTrigger value="config">Config</TabsTrigger>
                <TabsTrigger value="tools">
                  Tools{tools.length ? ` (${tools.length})` : ""}
                </TabsTrigger>
              </TabsList>
              <TabsContent value="config" className="min-h-0 flex-1 overflow-y-auto">
                {renderForm()}
                <div className="flex gap-2 pt-2 pb-6">
                  <Button onClick={saveForm} disabled={saving}>
                    Save
                  </Button>
                </div>
              </TabsContent>
              <TabsContent value="tools" className="min-h-0 flex-1 overflow-y-auto">
                {renderTools()}
              </TabsContent>
            </Tabs>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
              {renderForm()}
              <div className="pt-2 pb-6">
                <Button onClick={saveForm} disabled={saving}>
                  <PlusIcon /> Add
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ── Deletion confirmation ── */}
      <AlertDialog open={!!pendingDelete} onOpenChange={(o) => { if (!o) setPendingDelete(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete MCP server "{pendingDelete?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              This will remove the server and all of its discovered tools; Agents referencing its tools will lose them immediately. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleting}
              onClick={(e) => { e.preventDefault(); if (pendingDelete) void removeServer(pendingDelete); }}
            >
              {deleting ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
