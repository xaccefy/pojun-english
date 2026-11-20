"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { api } from "@/lib/api";
import type { HostInstallSources, InstallSourcePreset } from "@/lib/types";

const sourceNames: { id: InstallSourcePreset; label: string }[] = [
  { id: "", label: "System default" },
  { id: "tencent", label: "Tencent Cloud mirror" },
  { id: "tuna", label: "Tsinghua TUNA mirror" },
];

const publicRepoPattern = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/([A-Za-z0-9._-]+)$/;

const packageManagers = [
  ["apt", "APT (Debian / Ubuntu / Kali)"],
  ["pypi", "PyPI (pip / pipx)"],
] as const;

export function InstallSources({
  sources,
  supported,
  onSaved,
}: {
  sources: HostInstallSources;
  supported: boolean;
  onSaved: (sources: HostInstallSources) => void;
}) {
  const [draft, setDraft] = useState(sources);
  const [saving, setSaving] = useState(false);
  const [gitSource, setGitSource] = useState("github");
  const [repoInput, setRepoInput] = useState("");
  const { apt, pypi } = sources;
  useEffect(() => setDraft({ apt, pypi }), [apt, pypi]);

  const repo = repoInput.trim().replace(/\/$/, "");
  const repoName = publicRepoPattern.exec(repo)?.[1];
  const gitPrefix = gitSource === "gh-proxy" ? "https://gh-proxy.cn/github/" : "";
  const cloneURL = repoName && repoName !== "." && repoName !== ".."
    ? `${gitPrefix}${repo}${repo.endsWith(".git") ? "" : ".git"}`
    : "";
  const dirty = draft.apt !== apt || draft.pypi !== pypi;
  // Allow recovering saved selections after a helper downgrade.
  const canSave = supported || (!draft.apt && !draft.pypi);

  async function save() {
    setSaving(true);
    try {
      onSaved(await api.hostenvSaveSources(draft));
      toast.success("Install sources saved");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to save the install sources");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section aria-labelledby="install-sources-heading" className="flex flex-col gap-3 rounded-lg border bg-muted/30 p-3">
      <h2 id="install-sources-heading" className="font-medium text-sm">Install sources</h2>
      <p className="text-muted-foreground text-xs">
        APT and PyPI can each use a different mirror; saving applies to newly created tool-install jobs. The install proxy is set separately.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        {packageManagers.map(([key, label]) => (
          <div key={key} className="flex flex-col gap-1.5">
            <Label htmlFor={`install-source-${key}`} className="text-xs">{label}</Label>
            <NativeSelect
              id={`install-source-${key}`}
              value={draft[key]}
              disabled={saving || (!supported && !draft[key])}
              onChange={(event) => setDraft({ ...draft, [key]: event.target.value as InstallSourcePreset })}
            >
              {sourceNames.map(({ id, label }) => (
                <NativeSelectOption key={id} value={id} disabled={!supported && id !== ""}>{label}</NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
        ))}
        <Button type="button" size="sm" onClick={save} disabled={!dirty || saving || !canSave}>
          {saving ? "Saving…" : "Save install sources"}
        </Button>
      </div>
      {!supported && (
        <p className="text-muted-foreground text-xs">Choosing an APT or PyPI mirror needs an online host helper that supports install-source options.</p>
      )}
      <div className="flex flex-col gap-2 border-t pt-3">
        <div className="flex flex-wrap items-center gap-2">
          <Label htmlFor="install-source-git" className="text-xs">Manual Git download</Label>
          <NativeSelect id="install-source-git" value={gitSource} onChange={(event) => setGitSource(event.target.value)}>
            <NativeSelectOption value="github">GitHub (origin)</NativeSelectOption>
            <NativeSelectOption value="gh-proxy">gh-proxy.cn</NativeSelectOption>
          </NativeSelect>
        </div>
        <Input
          aria-label="public GitHub repository address"
          placeholder="https://github.com/owner/repo.git"
          value={repoInput}
          onChange={(event) => setRepoInput(event.target.value)}
          className="font-mono text-xs"
        />
        {repoInput.trim() && (cloneURL ? (
          <Input aria-label="Git clone address" value={cloneURL} readOnly onFocus={(event) => event.target.select()} className="font-mono text-xs" />
        ) : (
          <p className="text-muted-foreground text-xs">Enter the GitHub HTTPS address of a public repository.</p>
        ))}
        <p className="text-muted-foreground text-xs">Use the generated address for a manual clone. Third-party acceleration works for public repositories only.</p>
      </div>
    </section>
  );
}
