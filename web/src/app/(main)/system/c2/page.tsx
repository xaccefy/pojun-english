"use client";

import * as React from "react";
import { toast } from "sonner";
import { PlayIcon, RadioTower, SquareIcon, RefreshCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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
import { api } from "@/lib/api";
import type { C2Config, ListenerSession, ListenerView } from "@/lib/types";

const MODE_LABEL: Record<string, string> = {
  direct: "Direct (locally reachable)",
  ssh: "SSH relay managed",
  manual: "Manual forwarding",
};

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export default function C2Page() {
  // ── C2 egress config ──
  const [cfg, setCfg] = React.useState<C2Config | null>(null);
  const [mode, setMode] = React.useState<string>("direct");
  const [host, setHost] = React.useState("");
  const [ssh, setSsh] = React.useState("");
  const [pass, setPass] = React.useState("");
  const [key, setKey] = React.useState("");
  const [iface, setIface] = React.useState("");
  const [hasPass, setHasPass] = React.useState(false);
  const [savingCfg, setSavingCfg] = React.useState(false);

  // ── Listeners ──
  const [listeners, setListeners] = React.useState<ListenerView[]>([]);
  const [name, setName] = React.useState("");
  const [port, setPort] = React.useState("");
  const [starting, setStarting] = React.useState(false);
  const [pendingStop, setPendingStop] = React.useState<ListenerView | null>(null);
  const [stopping, setStopping] = React.useState(false);
  const [expanded, setExpanded] = React.useState<string | null>(null);
  const [refreshing, setRefreshing] = React.useState(false);

  const loadCfg = React.useCallback(async () => {
    try {
      const c = await api.c2Config();
      setCfg(c);
      setMode(c.mode || "direct");
      setHost(c.host || "");
      setSsh(c.ssh || "");
      setKey(c.key || "");
      setIface(c.iface || "");
      setHasPass(c.has_pass);
      setPass("");
    } catch (e) {
      toast.error(`Failed to load C2 config: ${(e as Error).message}`);
    }
  }, []);

  const loadListeners = React.useCallback(async () => {
    setRefreshing(true);
    try {
      const r = await api.listeners();
      setListeners(r.listeners ?? []);
    } catch (e) {
      toast.error(`Failed to load listeners: ${(e as Error).message}`);
    } finally {
      setRefreshing(false);
    }
  }, []);

  React.useEffect(() => {
    void loadCfg();
    void loadListeners();
    // Listener state and sessions keep changing (targets call back at any time); poll every 10s, same cadence as the task list.
    const t = setInterval(() => void loadListeners(), 10_000);
    return () => clearInterval(t);
  }, [loadCfg, loadListeners]);

  async function saveCfg() {
    setSavingCfg(true);
    try {
      const patch: Record<string, string> = { mode };
      if (mode === "manual" || mode === "ssh") patch.host = host;
      if (mode === "ssh") {
        patch.ssh = ssh;
        patch.key = key;
        // Blank password = no change; the ambiguity of entering a space and trimming it isn't worth it — here the convention is
        // blank means unchanged, and the backend's has_pass tells whether one is currently set.
        if (pass !== "") patch.password = pass;
      }
      if (mode === "direct") patch.iface = iface;
      const saved = await api.saveC2Config(patch);
      setCfg(saved);
      setHasPass(saved.has_pass);
      setPass("");
      toast.success("C2 egress config saved");
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSavingCfg(false);
    }
  }

  async function startListener() {
    const p = Number(port);
    const nm = name.trim();
    if (!nm) {
      toast.error("Please enter a listener name");
      return;
    }
    if (!Number.isInteger(p) || p < 1024 || p > 65535) {
      toast.error("Port must be an integer between 1024-65535 (binding low ports is privileged; use external forwarding)");
      return;
    }
    setStarting(true);
    try {
      const r = await api.startListener(nm, p);
      toast.success(`Listener ${r.name} started, connect-back address ${r.connect_back.lhost}:${r.connect_back.lport}`);
      setName("");
      setPort("");
      await loadListeners();
      setExpanded(r.name);
    } catch (e) {
      toast.error(`Failed to start: ${(e as Error).message}`);
    } finally {
      setStarting(false);
    }
  }

  async function stopListener(l: ListenerView) {
    setStopping(true);
    try {
      const r = await api.stopListener(l.name);
      toast.success(`Stopped ${r.stopped} (${r.sessions.length} sessions archived)`);
      setPendingStop(null);
      await loadListeners();
    } catch (e) {
      toast.error(`Failed to stop: ${(e as Error).message}`);
    } finally {
      setStopping(false);
    }
  }

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      {/* ── C2 egress config ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <RadioTower className="size-4" /> C2 egress config
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <p className="text-muted-foreground text-sm">
            Decides where reverse shells / OOB connect: <b>direct</b> = locally reachable (zero config);
            <b>ssh</b> = no public IP on this host + a public relay machine; the platform automatically builds an SSH reverse tunnel (reconnects on drop, follows listener start/stop);
            <b>manual</b> = existing manual forwarding; only displays the relay address. When the agent calls <code>listener_start</code>,
            the connect-back address is resolved from this config — no need to work out the network topology itself.
          </p>
          <div className="grid gap-2 sm:max-w-sm">
            <Label>Egress mode</Label>
            <Select value={mode} onValueChange={setMode}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="direct">direct · locally reachable</SelectItem>
                <SelectItem value="ssh">ssh · public relay managed</SelectItem>
                <SelectItem value="manual">manual · existing manual forwarding</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {(mode === "ssh" || mode === "manual") && (
            <div className="grid gap-2 sm:max-w-sm">
              <Label>Relay public address (LHOST shown to the target)</Label>
              <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="e.g. 1.2.3.4" />
            </div>
          )}
          {mode === "ssh" && (
            <>
              <div className="grid gap-2 sm:max-w-sm">
                <Label>Relay SSH (user@host[:port])</Label>
                <Input value={ssh} onChange={(e) => setSsh(e.target.value)} placeholder="root@1.2.3.4:22" />
              </div>
              <div className="grid gap-2 sm:max-w-sm">
                <Label>SSH password{hasPass ? " (set, leave blank to keep)" : ""}</Label>
                <Input
                  type="password"
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  placeholder={hasPass ? "••••••••" : "Relay SSH password"}
                />
              </div>
              <div className="grid gap-2 sm:max-w-sm">
                <Label>SSH private key path (optional, alternative to password)</Label>
                <Input value={key} onChange={(e) => setKey(e.target.value)} placeholder="/root/.ssh/id_rsa" />
              </div>
            </>
          )}
          {mode === "direct" && (
            <div className="grid gap-2 sm:max-w-sm">
              <Label>Egress interface (optional; leave blank to auto-use the default route's source address)</Label>
              <Input value={iface} onChange={(e) => setIface(e.target.value)} placeholder="e.g. eth0" />
            </div>
          )}
          <div>
            <Button onClick={saveCfg} disabled={savingCfg}>
              {savingCfg ? "Saving…" : "Save config"}
            </Button>
            {cfg && (
              <span className="text-muted-foreground ml-3 text-sm">
                Current: <b>{MODE_LABEL[cfg.mode] ?? cfg.mode}</b>
                {cfg.ssh ? ` · ${cfg.ssh}` : ""}
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ── Listeners ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between text-base">
            <span className="flex items-center gap-2">
              <RadioTower className="size-4" /> Connect-back receiver ({listeners.length})
            </span>
            <Button size="sm" variant="outline" onClick={() => void loadListeners()} disabled={refreshing}>
              <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> Refresh
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid items-end gap-2 sm:grid-cols-[1fr_140px_auto]">
            <div className="grid gap-1">
              <Label>Listener name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. shell-main" />
            </div>
            <div className="grid gap-1">
              <Label>Port (1024-65535)</Label>
              <Input value={port} onChange={(e) => setPort(e.target.value)} placeholder="4444" inputMode="numeric" />
            </div>
            <Button onClick={() => void startListener()} disabled={starting}>
              <PlayIcon /> {starting ? "Starting…" : "Start listener"}
            </Button>
          </div>

          {listeners.length === 0 && (
            <p className="text-muted-foreground text-sm">
              No running listeners. When the agent calls <code>listener_start</code> in a task, it also lands here (start/stop requires human approval).
            </p>
          )}

          {listeners.map((l) => (
            <div key={l.name} className="rounded-lg border">
              <div className="flex flex-wrap items-center gap-2 p-3">
                <Badge variant="secondary">{l.name}</Badge>
                <span className="font-mono text-sm">:{l.port}</span>
                <span className="text-muted-foreground text-sm">Started {fmtTime(l.started_at)}</span>
                <Badge variant={l.sessions.some((s) => s.open) ? "default" : "outline"}>
                  {l.sessions.length} sessions
                </Badge>
                <div className="grow" />
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setExpanded(expanded === l.name ? null : l.name)}
                >
                  {expanded === l.name ? "Hide sessions" : "View sessions"}
                </Button>
                <Button size="sm" variant="outline" className="text-destructive" onClick={() => setPendingStop(l)}>
                  <SquareIcon /> Stop
                </Button>
              </div>
              {expanded === l.name && (
                <div className="border-t">
                  {l.sessions.length === 0 ? (
                    <p className="text-muted-foreground p-3 text-sm">No connect-back sessions yet.</p>
                  ) : (
                    l.sessions.map((s) => <SessionRow key={s.id} s={s} />)
                  )}
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* ── Stop confirmation ── */}
      <AlertDialog open={!!pendingStop} onOpenChange={(o) => { if (!o) setPendingStop(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Stop listener "{pendingStop?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              The port closes immediately; {pendingStop?.sessions.length ?? 0} sessions are archived on stop (data retained and exportable in the stop response).
              In SSH relay mode the managed tunnel is torn down as well.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={stopping}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={stopping}
              onClick={(e) => { e.preventDefault(); if (pendingStop) void stopListener(pendingStop); }}
            >
              {stopping ? "Stopping…" : "Stop"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SessionRow({ s }: { s: ListenerSession }) {
  const [openView, setOpenView] = React.useState(false);
  return (
    <div className="border-b px-3 py-2 last:border-b-0">
      <button
        className="flex w-full flex-wrap items-center gap-2 text-left text-sm"
        onClick={() => setOpenView(!openView)}
      >
        <Badge variant={s.open ? "default" : "secondary"}>{s.open ? "Online" : "Disconnected"}</Badge>
        <span className="font-mono">{s.remote}</span>
        <span className="text-muted-foreground">Connected {fmtTime(s.connected_at)}</span>
        <span className="text-muted-foreground">{fmtBytes(Number(s.bytes_in))}</span>
        <span className="text-muted-foreground grow text-right text-xs">{openView ? "Hide" : "View captured content"}</span>
      </button>
      {openView && (
        <pre className="bg-muted mt-2 max-h-64 overflow-auto rounded p-2 text-xs whitespace-pre-wrap">
          {s.preview || "(no captured content)"}
        </pre>
      )}
    </div>
  );
}
