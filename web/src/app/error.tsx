"use client";

import * as React from "react";

import Link from "next/link";

import { CircleAlertIcon, RotateCcwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";

// Route-level error boundary.
//
// There used to be no error.tsx: any client-side exception (an old WebView missing an
// API, the backend returning an unexpected shape, a render throwing somewhere) just
// turned into Next's default
// "Application error: a client-side exception has occurred", so users could not see the
// cause and debugging was guesswork. Here we show the message and the first few stack
// lines directly — easy to screenshot on a phone, and far more useful than a blank page.
type ErrorProps = {
  error: Error & { digest?: string };
  reset: () => void;
};

function detailOf(error: Error & { digest?: string }): string {
  const parts = [error?.name, error?.message].filter(Boolean);
  const head = parts.join(": ") || String(error);
  const stack = (error?.stack ?? "")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .slice(0, 6)
    .join("\n");
  const digest = error?.digest ? `\n\ndigest: ${error.digest}` : "";
  return stack ? `${head}\n\n${stack}${digest}` : `${head}${digest}`;
}

export default function AppError({ error, reset }: ErrorProps) {
  React.useEffect(() => {
    // Also log to the console so it is available when debugging a phone or when a user
    // attaches it to feedback.
    console.error("[pojun] page render failed:", error);
  }, [error]);

  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 p-6 text-center">
      <CircleAlertIcon className="size-8 text-destructive" />
      <div className="grid gap-1">
        <h1 className="font-semibold text-lg">This page hit an error</h1>
        <p className="max-w-md text-muted-foreground text-sm">
          The page threw while rendering. The information below helps locate the cause
          (screenshot it directly to report).
        </p>
      </div>
      <pre className="max-h-64 w-full max-w-2xl overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-3 text-start font-mono text-xs">
        {detailOf(error)}
      </pre>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <Button size="sm" onClick={() => reset()}>
          <RotateCcwIcon data-icon="inline-start" /> Retry
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            // A static export has no server-side routing, so a hard navigation is more
            // reliable than router.push.
            window.location.href = "/";
          }}
        >
          Back to home
        </Button>
        <Button asChild size="sm" variant="ghost">
          <Link href="/function/tasks">Task list</Link>
        </Button>
      </div>
    </div>
  );
}
