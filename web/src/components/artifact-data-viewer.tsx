"use client";

// ArtifactDataViewer (v0.4.41): an online viewer for data-type evidence (JSON/JSONL/CSV/TSV/
// text). These files used to be download-only with nothing visible on the page — the key gap
// in "pull the data out and show it". Structured data renders as a table (columns = fields,
// rows = records, capped at 100 rows); text renders in a monospace pre; anything beyond the
// cap points at "download original" for the full content.

import * as React from "react";

import { DownloadIcon, Loader2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api } from "@/lib/api";
import type { TaskArtifact } from "@/lib/types";

interface DataPreview {
  type: "json" | "jsonl" | "csv" | "text";
  name: string;
  kind: string;
  bound_finding: number;
  total_rows: number;
  truncated: boolean;
  columns?: string[];
  rows?: unknown[][];
  text?: string;
  total_size: number;
}

export function useArtifactDataPreview(taskId: string, artifact: TaskArtifact | null, open: boolean) {
  const [data, setData] = React.useState<DataPreview | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    if (!open || !artifact) {
      setData(null);
      setError("");
      return;
    }
    let disposed = false;
    setLoading(true);
    api
      .artifactDataPreview(taskId, artifact.id)
      .then((d) => {
        if (!disposed) setData(d);
      })
      .catch((e) => {
        if (!disposed) setError((e as Error).message);
      })
      .finally(() => {
        if (!disposed) setLoading(false);
      });
    return () => {
      disposed = true;
    };
  }, [artifact, open, taskId]);

  return { data, loading, error };
}

export function ArtifactDataCells({ data, loading, error }: { data: DataPreview | null; loading: boolean; error: string }) {
  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-10 text-muted-foreground text-sm">
        <Loader2Icon className="size-4 animate-spin" /> Loading…
      </div>
    );
  }
  if (error) {
    return <p className="py-6 text-center text-destructive text-sm">{error}</p>;
  }
  if (!data) return null;

  if (data.type === "json" || data.type === "csv" || data.type === "jsonl") {
    const columns = data.columns ?? [];
    return (
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2 text-muted-foreground text-xs">
          <span>
            {data.total_rows} rows{data.truncated ? " (first 100 previewed)" : ""}
          </span>
          <span>· {columns.length} columns</span>
        </div>
        <div className="max-h-[58vh] overflow-auto rounded-md border">
          <table className="w-full border-collapse text-xs">
            <thead className="sticky top-0 bg-muted">
              <tr>
                <th className="border-b px-2 py-1.5 text-left font-medium text-muted-foreground">#</th>
                {columns.map((c) => (
                  <th key={c} className="border-b px-2 py-1.5 text-left font-medium whitespace-nowrap">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(data.rows ?? []).map((row, i) => (
                <tr key={i} className="hover:bg-muted/40">
                  <td className="border-b px-2 py-1 text-muted-foreground tabular-nums">{i + 1}</td>
                  {columns.map((c, ci) => (
                    <td key={c} className="max-w-[20rem] truncate border-b px-2 py-1 font-mono" title={String(row[ci] ?? "")}>
                      {row[ci] === null || row[ci] === undefined ? "—" : String(row[ci])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="text-muted-foreground text-xs">{data.total_rows} rows{data.truncated ? " (first 200 previewed)" : ""}</div>
      <pre className="max-h-[58vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap">
        {data.text}
      </pre>
    </div>
  );
}

export function ArtifactDataViewerDialog({
  taskId,
  artifact,
  open,
  onClose,
}: {
  taskId: string;
  artifact: TaskArtifact | null;
  open: boolean;
  onClose: () => void;
}) {
  const { data, loading, error } = useArtifactDataPreview(taskId, artifact, open);
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="flex max-h-[85vh] flex-col sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="break-all pr-6 text-base">{artifact?.note || artifact?.name}</DialogTitle>
          <DialogDescription className="break-all">
            {artifact?.name}
            {data ? ` · ${data.type.toUpperCase()} · ${(data.total_size / 1024).toFixed(0)}KB` : ""}
          </DialogDescription>
        </DialogHeader>
        <ArtifactDataCells data={data} loading={loading} error={error} />
        {artifact ? (
          <div className="flex justify-end">
            <Button size="sm" variant="outline" asChild>
              <a href={`${api.artifactUrl(taskId, artifact.id)}?download=1`}>
                <DownloadIcon data-icon="inline-start" /> Download original
              </a>
            </Button>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
