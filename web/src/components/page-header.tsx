"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

interface PageHeaderProps {
  title: string;
  description?: React.ReactNode;
  /** Page-level primary/secondary actions, right-aligned; wraps on narrow screens. */
  actions?: React.ReactNode;
  /** View switcher below the title (tabs etc.). */
  tabs?: React.ReactNode;
  className?: string;
}

/**
 * Unified page header: title/description on the left, primary actions on the right, tabs on their own
 * row. High-traffic pages adopt it first; new pages must use it so title hierarchy and action placement
 * don't drift between pages.
 */
export function PageHeader({ title, description, actions, tabs, className }: PageHeaderProps) {
  return (
    <div className={cn("shrink-0 space-y-3", className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="font-semibold text-xl tracking-tight">{title}</h1>
          {description ? (
            <p className="mt-0.5 max-w-3xl text-muted-foreground text-xs leading-relaxed">{description}</p>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {tabs ? <div className="min-w-0">{tabs}</div> : null}
    </div>
  );
}

interface FilterBarProps {
  /** First row: filter conditions. */
  children: React.ReactNode;
  /** Second row: sort/export/bulk actions; not rendered when empty. */
  actions?: React.ReactNode;
  className?: string;
}

/**
 * Unified filter area: the condition row is separated from the action row so filter controls don't push
 * sort/export onto a lone line. The container only handles layout, never filter state.
 */
export function FilterBar({ children, actions, className }: FilterBarProps) {
  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
      {actions ? <div className="flex flex-wrap items-center justify-between gap-2">{actions}</div> : null}
    </div>
  );
}
