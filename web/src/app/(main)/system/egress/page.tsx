"use client";

import * as React from "react";

import { CableIcon, PlayIcon, PlusIcon, RefreshCwIcon, SquareIcon, Trash2Icon, UploadCloudIcon } from "lucide-react";
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
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { SSHProvider } from "@/lib/types";

// Execution → SSH jump hosts (v0.7.1): use an authorized host as a SOCKS5 exit.
// Passwords/private keys go only into the credential vault; once started, add the local
// socks5://127.0.0.1:port to the proxy pool.
export default function EgressPage() {
  const [rows, setRows] = React.useState<SSHProvider[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [addOpen, setAddOpen] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [busyId, setBusyId] = React.useState<number | null>(null);
  const [form, setForm] = React.useState({
    name: "",
    host: "",
    port: "22",
    user: "root",
    auth_kind: "key",
    secret: "",
  });

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.sshProviders();
      setRows(r.providers ?? []);
    } catch (e) {
      toast.error(`Load failed: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const add = async () => {
    if (!form.host.trim() || !form.user.trim() || !form.secret.trim()) {
      toast.error("host / user / private key or password are required");
      return;
    }
    setSaving(true);
    try {
      await api.createSSHProvider({
        name: form.name.trim() || undefined,
        host: form.host.trim(),
        port: Number(form.port) || 22,
        user: form.user.trim(),
        auth_kind: form.auth_kind as "key" | "password",
        secret: form.secret,
      });
      toast.success("Jump host registered (secret encrypted into the vault)");
      setAddOpen(false);
      setForm({ name: "", host: "", port: "22", user: "root", auth_kind: "key", secret: "" });
      void load();
    } catch (e) {
      toast.error(`Registration failed: ${String(e)}`);
    } finally {
      setSaving(false);
    }
  };

  const start = async (row: SSHProvider) => {
    if (busyId !== null) return;
    setBusyId(row.id);
    try {
      const r = await api.startSSHProvider(row.id);
      toast.success(`Started: ${r.socks_addr}`);
      void load();
    } catch (e) {
      toast.error(`Start failed: ${String(e)}`);
    } finally {
      setBusyId(null);
    }
  };
  const stop = async (row: SSHProvider) => {
    if (busyId !== null) return;
    setBusyId(row.id);
    try {
      await api.stopSSHProvider(row.id);
      toast.success("Stopped");
      void load();
    } catch (e) {
      toast.error(`Stop failed: ${String(e)}`);
    } finally {
      setBusyId(null);
    }
  };
  const use = async (row: SSHProvider) => {
    if (busyId !== null) return;
    setBusyId(row.id);
    try {
      const r = await api.useSSHProvider(row.id);
      toast.success(`Added to the proxy pool: ${r.socks_addr} (socks5 upstreams allowed)`);
    } catch (e) {
      toast.error(`Adding to the proxy pool failed: ${String(e)}`);
    } finally {
      setBusyId(null);
    }
  };
  const del = async (row: SSHProvider) => {
    if (!window.confirm(`Delete jump host "${row.name}"?`)) return;
    try {
      await api.deleteSSHProvider(row.id);
      toast.success("Deleted");
      void load();
    } catch (e) {
      toast.error(`Delete failed: ${String(e)}`);
    }
  };

  return (
    <div className="space-y-4 p-4 md:p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <CableIcon className="size-5" /> SSH jump hosts
            </CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">
              Use an authorized host as a SOCKS5 exit: once started, add <code>socks5://127.0.0.1:port</code> to the
              proxy pool. Private keys/passwords are stored encrypted in the vault; the API only returns a credential_id.
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="icon" onClick={() => void load()} disabled={loading}>
              <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} />
            </Button>
            <Button onClick={() => setAddOpen(true)}>
              <PlusIcon className="size-4" /> Register jump host
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table className="w-full table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="hidden w-12 sm:table-cell">ID</TableHead>
                <TableHead className="w-auto sm:w-28">Name</TableHead>
                <TableHead className="w-auto sm:w-32">Address</TableHead>
                <TableHead className="hidden w-24 lg:table-cell">User</TableHead>
                <TableHead className="hidden w-20 lg:table-cell">Status</TableHead>
                <TableHead className="hidden w-28 xl:table-cell">Local exit</TableHead>
                <TableHead className="w-28 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                    {loading ? "Loading…" : "No jump hosts yet. Click \"Register jump host\" at the top right and fill in host/port/user plus a private key or password."}
                  </TableCell>
                </TableRow>
              )}
              {rows.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="hidden font-mono text-xs sm:table-cell">#{r.id}</TableCell>
                  <TableCell className="truncate" title={r.name}>{r.name}</TableCell>
                  <TableCell className="truncate font-mono text-xs" title={`${r.host}:${r.port}`}>
                    {r.host}:{r.port}
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs lg:table-cell">{r.user}</TableCell>
                  <TableCell className="hidden lg:table-cell">
                    {r.status === "running" ? <Badge>Running</Badge> : <Badge variant="secondary">Stopped</Badge>}
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs xl:table-cell">{r.socks_addr || "—"}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      {r.status === "running" ? (
                        <>
                          <Button variant="ghost" size="icon" title="Stop" disabled={busyId === r.id} onClick={() => void stop(r)}>
                            <SquareIcon className="size-4" />
                          </Button>
                          <Button variant="ghost" size="icon" title="Add to the proxy pool" disabled={busyId === r.id} onClick={() => void use(r)}>
                            <UploadCloudIcon className="size-4" />
                          </Button>
                        </>
                      ) : (
                        <Button variant="ghost" size="icon" title="Start" disabled={busyId === r.id} onClick={() => void start(r)}>
                          <PlayIcon className="size-4" />
                        </Button>
                      )}
                      <Button variant="ghost" size="icon" title="Delete" disabled={busyId === r.id} onClick={() => void del(r)}>
                        <Trash2Icon className="size-4 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Register an SSH jump host</DialogTitle>
            <DialogDescription>Only register hosts you are authorized to use. Private keys/passwords are stored encrypted in the credential vault.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Name (optional)</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="HK jump host" />
              </div>
              <div className="space-y-1.5">
                <Label>Auth method</Label>
                <Select value={form.auth_kind} onValueChange={(v) => setForm({ ...form, auth_kind: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="key">Private key</SelectItem>
                    <SelectItem value="password">Password</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2 space-y-1.5">
                <Label>Host</Label>
                <Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="1.2.3.4" />
              </div>
              <div className="space-y-1.5">
                <Label>Port</Label>
                <Input value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>User</Label>
              <Input value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label>{form.auth_kind === "key" ? "Private key (PEM)" : "Password"}</Label>
              <Textarea
                rows={form.auth_kind === "key" ? 6 : 2}
                className="font-mono text-xs"
                value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })}
                placeholder={form.auth_kind === "key" ? "-----BEGIN OPENSSH PRIVATE KEY-----" : ""}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => void add()} disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
