"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpRightIcon, ChevronLeftIcon, ChevronRightIcon, Loader2Icon, PlayIcon, SquareIcon } from "lucide-react";

import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { Finding, FindingsPage, RetestState } from "@/lib/types";

const PAGE_SIZE = 20;

function findingLabel(finding: Finding) {
  return finding.name?.trim() || finding.vulnclass.trim() || "Uncategorised";
}

// Badge text for the latest retest status (part of the v0.4.27 bulk retest work).
function retestBadge(state: RetestState | undefined): { text: string; className: string } | null {
  if (!state) return null;
  if (state.status === "pending" || state.status === "running") {
    return { text: "Retesting", className: "bg-sky-500/15 text-sky-600 dark:text-sky-400" };
  }
  switch (state.verdict) {
    case "fixed":
      return { text: "Fixed", className: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" };
    case "reproduced":
      return { text: "Reproduced", className: "bg-red-500/15 text-red-600 dark:text-red-400" };
    case "inconclusive":
      return { text: "Inconclusive", className: "bg-amber-500/15 text-amber-600 dark:text-amber-400" };
    default:
      return null;
  }
}

export function RetestsTab({ taskId }: { taskId: string }) {
  const [page, setPage] = React.useState(1);
  const [data, setData] = React.useState<FindingsPage | null>(null);
  const [selectedId, setSelectedId] = React.useState("");
  const [error, setError] = React.useState("");
  const [refreshVersion, setRefreshVersion] = React.useState(0);
  const refresh = React.useCallback(() => setRefreshVersion((version) => version + 1), []);

  // Bulk retest (v0.4.27): candidates = this task's pending critical/high findings with no
  // retest in flight. Started one at a time (only one retest conversation runs at once) and
  // can be stopped at any point.
  const [candidates, setCandidates] = React.useState(0);
  const [states, setStates] = React.useState<Record<number, RetestState>>({});
  const [batchRunning, setBatchRunning] = React.useState(false);
  const [batchDone, setBatchDone] = React.useState(0);
  const [batchTotal, setBatchTotal] = React.useState(0);
  const cancelBatch = React.useRef(false);

  React.useEffect(() => {
    let disposed = false;
    api
      .retestCandidates(taskId, ["critical", "high"])
      .then((r) => {
        if (disposed) return;
        setCandidates(r.candidates.length);
        setStates(Object.fromEntries(r.states.map((s) => [s.finding_id, s])));
      })
      .catch(() => {});
    return () => {
      disposed = true;
    };
  }, [taskId, refreshVersion]);

  const runBatch = React.useCallback(async () => {
    if (batchRunning) return;
    setBatchRunning(true);
    cancelBatch.current = false;
    try {
      const r = await api.retestCandidates(taskId, ["critical", "high"]);
      const queue = r.candidates;
      setStates(Object.fromEntries(r.states.map((s) => [s.finding_id, s])));
      setBatchTotal(queue.length);
      setBatchDone(0);
      for (let i = 0; i < queue.length; i += 1) {
        if (cancelBatch.current) break;
        const c = queue[i];
        try {
          await api.startFindingRetest(String(c.id), "");
          setStates((prev) => ({ ...prev, [c.id]: { finding_id: c.id, status: "running", verdict: "" } }));
        } catch {
          // A single failure (e.g. the retest Agent is disabled) does not abort the batch;
          // continue with the next one.
        }
        setBatchDone(i + 1);
        await new Promise((resolve) => setTimeout(resolve, 1500)); // gap between conversation starts to avoid a burst
      }
      refresh();
    } finally {
      setBatchRunning(false);
    }
  }, [batchRunning, refresh, taskId]);

  // Only this task's own findings, including those without graph nodes.
  // Fetch history only for the selection, and wait for each poll to finish.
  React.useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function load() {
      try {
        const result = await api.findingsPage({ task: taskId, page, pageSize: PAGE_SIZE, sort: "time" });
        if (disposed) return;
        const lastPage = Math.max(1, Math.ceil(result.total / PAGE_SIZE));
        if (page > lastPage) {
          setPage(lastPage);
          return;
        }
        setData(result);
        setSelectedId((current) =>
          result.items.some((finding) => finding.id === current) ? current : (result.items[0]?.id ?? ""),
        );
        setError("");
      } catch (e) {
        if (!disposed) setError((e as Error).message);
      } finally {
        if (!disposed) timer = setTimeout(() => void load(), 3000);
      }
    }
    void refreshVersion; // Refresh triage immediately after a retest completes.
    void load();
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [taskId, page, refreshVersion]);

  const loaded = data?.page === page;
  const findings = loaded ? data.items : [];
  const selected = findings.find((finding) => finding.id === selectedId);

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>
            Failed to load the task's findings: {error}
            <Button variant="outline" size="sm" onClick={refresh}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}
      {/* Bulk retest bar (v0.4.27): queue the pending critical/high findings into retests one by one. */}
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="text-sm">
            {batchRunning ? (
              <span className="flex items-center gap-2">
                <Loader2Icon className="size-4 animate-spin" />
                Bulk retest running: {batchDone}/{batchTotal} (critical/high, serial)
              </span>
            ) : (
              <span className="text-muted-foreground">
                Awaiting retest (critical/high with no retest in flight): <span className="text-foreground font-medium">{candidates}</span>
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {batchRunning ? (
              <Button variant="outline" size="sm" onClick={() => (cancelBatch.current = true)}>
                <SquareIcon data-icon="inline-start" />
                Stop queueing
              </Button>
            ) : (
              <Button size="sm" disabled={candidates === 0} onClick={() => void runBatch()}>
                <PlayIcon data-icon="inline-start" />
                Bulk retest
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(16rem,22rem)_minmax(0,1fr)]">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>Select a finding{data ? ` · ${data.total}` : ""}</CardTitle>
            <CardDescription>View retest records for this task's findings, or start a new retest.</CardDescription>
          </CardHeader>
          <CardContent className="flex max-h-[32rem] flex-col overflow-y-auto">
            {!loaded && !error ? <Skeleton className="h-24 w-full" /> : null}
            {findings.map((finding, index) => (
              <React.Fragment key={finding.id}>
                {index > 0 ? <Separator className="my-1" /> : null}
                <Button
                  variant={finding.id === selectedId ? "secondary" : "ghost"}
                  className="h-auto w-full shrink-0 flex-col items-start gap-2 whitespace-normal py-3 text-left"
                  aria-label={`Select finding: ${findingLabel(finding)}`}
                  aria-pressed={finding.id === selectedId}
                  onClick={() => setSelectedId(finding.id)}
                >
                  <span className="line-clamp-2 break-words">{findingLabel(finding)}</span>
                  <span className="flex flex-wrap items-center gap-2">
                    <StatusBadge domain="severity" value={finding.severity} dot />
                    <StatusBadge domain="finding" value={finding.status} dot />
                    {(() => {
                      const badge = retestBadge(states[Number(finding.finding_id || finding.id)]);
                      if (!badge) return null;
                      return (
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${badge.className}`}>
                          {badge.text}
                        </span>
                      );
                    })()}
                  </span>
                </Button>
              </React.Fragment>
            ))}
            {loaded && findings.length === 0 ? (
              <Empty>
                <EmptyHeader>
                  <EmptyTitle>No findings to retest yet</EmptyTitle>
                  <EmptyDescription>Once this task has findings, you can start a retest here by hand.</EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : null}
          </CardContent>
          {data && data.total > PAGE_SIZE ? (
            <CardFooter className="justify-between gap-2">
              <Button
                variant="outline"
                size="icon-sm"
                aria-label="Previous page of findings"
                disabled={page === 1}
                onClick={() => setPage(page - 1)}
              >
                <ChevronLeftIcon />
              </Button>
              <span className="text-muted-foreground text-xs">
                Page {page} / {Math.ceil(data.total / PAGE_SIZE)}
              </span>
              <Button
                variant="outline"
                size="icon-sm"
                aria-label="Next page of findings"
                disabled={page * PAGE_SIZE >= data.total}
                onClick={() => setPage(page + 1)}
              >
                <ChevronRightIcon />
              </Button>
            </CardFooter>
          ) : null}
        </Card>
        {selected ? (
          <div className="flex min-w-0 flex-col gap-4">
            <div className="flex flex-col gap-2">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <h2 className="min-w-0 flex-1 break-words font-medium">{findingLabel(selected)}</h2>
                <Button asChild variant="ghost" size="sm">
                  <Link href={`/function/findings/detail?id=${selected.finding_id || selected.id}`}>
                    Finding details <ArrowUpRightIcon data-icon="inline-end" />
                  </Link>
                </Button>
              </div>
              <p className="line-clamp-3 break-words text-muted-foreground text-sm">{selected.summary}</p>
            </div>
            <FindingRetestPanel
              key={selected.id}
              findingId={selected.finding_id || selected.id}
              findingName={findingLabel(selected)}
              onCompleted={refresh}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}
