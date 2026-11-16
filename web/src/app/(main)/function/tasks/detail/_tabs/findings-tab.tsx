"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowDownIcon, ArrowUpIcon, ArrowUpRightIcon, ChevronRightIcon } from "lucide-react";
import { toast } from "sonner";

import { EvidenceView } from "@/components/evidence-view";
import { StatusBadge } from "@/components/status-badge";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { api } from "@/lib/api";
import { useStoredSortPreference } from "@/lib/sort-preference";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

type FindingSortField = "time";

const FINDING_SORT_FIELDS: readonly FindingSortField[] = ["time"];
const FINDING_SORT_PREFERENCE_KEY = "pojun_task_findings_sort";

function findingLabel(finding: Finding): string {
  if (finding.name?.trim()) return finding.name;
  if (finding.vulnclass?.trim()) return finding.vulnclass;
  return "Uncategorised";
}

const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function Row({
  f,
  contextTaskId,
  onStatus,
}: {
  f: Finding;
  contextTaskId: string;
  onStatus: (f: Finding, next: FindingStatus) => void;
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="border-b last:border-b-0">
      <div className="flex w-full flex-col gap-2 px-4 py-3 text-sm hover:bg-accent/40 sm:flex-row sm:items-center sm:gap-3">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex min-w-0 flex-1 items-center gap-3 text-left"
        >
          <ChevronRightIcon
            className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
          />
          <StatusBadge domain="severity" value={f.severity} dot />
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate font-medium">{findingLabel(f)}</span>
              {f.inherited && f.source_task_id && (
                <Badge variant="outline" className="shrink-0">
                  From #{f.source_task_id} · read-only
                </Badge>
              )}
            </div>
            <span className="truncate text-muted-foreground text-xs">{f.summary}</span>
          </div>
        </button>
        <div className="flex flex-wrap items-center gap-2 pl-7 sm:pl-0">
        <Badge variant="outline">Traffic evidence {f.traffic_count ?? 0}</Badge>
        {f.assets && f.assets.length > 0 && (
          <div className="hidden shrink-0 flex-wrap justify-end gap-1 sm:flex">
            {f.assets.slice(0, 2).map((a) => (
              <code
                key={a.id}
                className="max-w-[10rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                title={`${a.type} · ${a.label}`}
              >
                {a.label}
              </code>
            ))}
            {f.assets.length > 2 && <span className="text-muted-foreground text-xs">+{f.assets.length - 2}</span>}
          </div>
        )}
        {f.finding_id && !f.inherited ? (
          <Select value={f.status} onValueChange={(v) => onStatus(f, v as FindingStatus)}>
            <SelectTrigger size="sm" className="h-7 w-28 shrink-0 border-none px-1 shadow-none focus-visible:ring-0">
              <StatusBadge domain="finding" value={f.status} dot />
            </SelectTrigger>
            <SelectContent position="popper" align="end">
              <SelectGroup>
                {FINDING_STATUSES.map((st) => (
                  <SelectItem key={st} value={st}>
                    {statusMeta("finding", st).label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        ) : (
          <StatusBadge domain="finding" value={f.status} dot />
        )}
        <span className="hidden shrink-0 text-muted-foreground text-xs md:block">
          {new Date(f.ts).toLocaleString("zh-CN")}
        </span>
        {f.finding_id && (
          <Link
            href={
              f.inherited
                ? `/function/findings/detail?id=${f.finding_id}&context_task=${contextTaskId}`
                : `/function/findings/detail?id=${f.finding_id}`
            }
            className="inline-flex shrink-0 items-center gap-0.5 text-muted-foreground text-xs hover:text-primary"
            title="View finding details"
          >
            Details
            <ArrowUpRightIcon className="size-3" />
          </Link>
        )}
        </div>
      </div>
      {open && (
        <div className="bg-muted/30 px-4 pb-4 pl-11">
          {f.finding_id ? (
            <>
              {/* The message viewer goes straight into the inline expansion (user feedback: it
                  used to require jumping to the finding detail page, and only an evidence JSON blob
                  was shown here; now expanding shows the request/response messages). */}
              <div className="mb-3">
                <FindingTrafficPanel
                  findingId={String(f.finding_id)}
                  contextTask={contextTaskId}
                  readOnly={f.inherited}
                  onChanged={() => {}}
                />
              </div>
              <details className="group">
                <summary className="cursor-pointer font-medium text-muted-foreground text-xs select-none group-open:mb-1">
                  Raw evidence / PoC (click to collapse)
                </summary>
                <EvidenceView text={f.evidence} className="mt-1 max-h-72 overflow-y-auto" />
              </details>
            </>
          ) : (
            <>
              <div className="mb-1 font-medium text-muted-foreground text-xs">Evidence / PoC</div>
              <pre className="overflow-auto whitespace-pre-wrap rounded-md border bg-background p-3 font-mono text-xs">
                {f.evidence}
              </pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export function FindingsTab({ taskId }: { taskId: string }) {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [sortPreference, setSortPreference] = useStoredSortPreference(
    FINDING_SORT_PREFERENCE_KEY,
    FINDING_SORT_FIELDS,
    "time",
    "desc",
  );

  React.useEffect(() => {
    let active = true;
    const load = () => {
      api
        .findings(taskId)
        .then((fs) => {
          if (active) setFindings(fs);
        })
        .catch(() => {
          // Keep the last successful snapshot during transient refresh failures.
        });
    };
    load();
    const t = setInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [taskId]);

  const onStatus = React.useCallback(async (f: Finding, next: FindingStatus) => {
    if (f.inherited || !f.finding_id || next === f.status) return;
    const prev = f.status;
    setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: next } : x)));
    try {
      await api.setFindingStatus(f.finding_id, next);
      toast.success(`Marked as "${statusMeta("finding", next).label}"`);
    } catch (e) {
      setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: prev } : x)));
      toast.error(`Update failed: ${(e as Error).message}`);
    }
  }, []);

  // This task's findings and the [inherited] ones must be kept apart.
  //
  // Why: a derived task inherits **every finished finding** of its source task — measured,
  // task 4's endpoint returned 273 records, 214 of them inherited (from task 3) and only 59
  // reported by task 4 itself. They used to be flattened into one list, with the inherited
  // ones distinguished only by the small "from #3 · read-only" line under the title — and
  // both tasks' names start with the same school name and get truncated, so by eye there was
  // no telling which was reported here and which was inherited.
  //
  // Inheritance itself is useful (less duplicate work, reusable conclusions) and the backend
  // logic is untouched; this only fixes **splitting the front-end view by task**: inherited
  // findings collapse into their own group, closed by default.
  const sortedFindings = React.useMemo(
    () =>
      findings
        .filter((f) => f.task_id === taskId || f.inherited)
        .sort((a, b) => {
          const compared = Date.parse(a.ts) - Date.parse(b.ts);
          if (compared !== 0) return sortPreference.direction === "asc" ? compared : -compared;
          return b.id.localeCompare(a.id, undefined, { numeric: true });
        }),
    [findings, taskId, sortPreference.direction],
  );
  const ownItems = React.useMemo(() => sortedFindings.filter((f) => !f.inherited), [sortedFindings]);
  // Inherited ones are grouped by source task.
  const inheritedGroups = React.useMemo(() => {
    const bySource = new Map<string, Finding[]>();
    for (const f of sortedFindings) {
      if (!f.inherited) continue;
      const src = String(f.source_task_id ?? "");
      const list = bySource.get(src);
      if (list) list.push(f);
      else bySource.set(src, [f]);
    }
    return [...bySource.entries()].map(([sourceTaskId, items]) => ({ sourceTaskId, items }));
  }, [sortedFindings]);
  const [expandedInherited, setExpandedInherited] = React.useState<Record<string, boolean>>({});

  return (
    <Card className="overflow-hidden py-0">
      <CardContent className="px-0">
        <div className="flex items-center border-b px-4 py-2 text-muted-foreground text-xs">
          <span className="min-w-0 flex-1">Finding</span>
          <button
            type="button"
            className="inline-flex items-center gap-1 outline-none focus-visible:underline"
            aria-label={`Found time is currently ${sortPreference.direction === "asc" ? "ascending" : "descending"}; click to switch direction`}
            onClick={() =>
              setSortPreference((current) => ({
                field: "time",
                direction: current.direction === "asc" ? "desc" : "asc",
              }))
            }
          >
            <span>Found at</span>
            {sortPreference.direction === "asc" ? (
              <ArrowUpIcon className="size-3.5" />
            ) : (
              <ArrowDownIcon className="size-3.5" />
            )}
          </button>
        </div>
        {ownItems.map((f) => (
          <Row key={f.id} f={f} contextTaskId={taskId} onStatus={onStatus} />
        ))}
        {/* Inherited findings (from other tasks) collapse into their own group, closed by default. */}
        {inheritedGroups.map((group) => {
          const expanded = expandedInherited[group.sourceTaskId] ?? false;
          return (
            <div key={`inh-${group.sourceTaskId}`}>
              <button
                type="button"
                onClick={() =>
                  setExpandedInherited((prev) => ({
                    ...prev,
                    [group.sourceTaskId]: !expanded,
                  }))
                }
                className="flex w-full items-center gap-2 border-b bg-muted/30 px-4 py-2 text-left text-xs text-muted-foreground hover:bg-accent/40"
                aria-expanded={expanded}
              >
                <ChevronRightIcon
                  className={cn("size-3.5 shrink-0 transition-transform", expanded && "rotate-90")}
                />
                <span className="min-w-0 flex-1 truncate">
                  Historical findings from task #{group.sourceTaskId} ({group.items.length} · read-only)
                </span>
              </button>
              {expanded &&
                group.items.map((f) => (
                  <Row key={f.id} f={f} contextTaskId={taskId} onStatus={onStatus} />
                ))}
            </div>
          );
        })}
        {ownItems.length === 0 && inheritedGroups.length === 0 && (
          <p className="px-4 py-8 text-center text-muted-foreground text-sm">No confirmed findings in this task or its directly related tasks yet.</p>
        )}
      </CardContent>
    </Card>
  );
}
