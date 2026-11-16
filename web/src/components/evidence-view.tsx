"use client";

import * as React from "react";

import { CopyIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// EvidenceView renders the free-form evidence text an agent writes (curl commands + #
// section comments + JSON responses mixed together) as readable blocks (user feedback: one
// big pre blob was too crude). Presentation-layer parsing only, no data changes:
//   - lines starting with '# '  → section heading (primary colour, separated by top margin)
//   - ``` fences                → code block
//   - long lines starting with '{' → try to pretty-print as JSON (unchanged if parse fails);
//                                   very long ones collapse to 12 lines by default
//   - everything else           → monospace paragraph (curl commands kept verbatim)
export function EvidenceView({ text, className }: { text: string; className?: string }) {
  const blocks = React.useMemo(() => parseEvidence(text ?? ""), [text]);
  const [copied, setCopied] = React.useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* silent when the clipboard is unavailable */
    }
  };

  return (
    <div className={cn("relative", className)}>
      <Button
        variant="ghost"
        size="icon-sm"
        className="absolute top-1 right-1 z-10"
        aria-label="Copy the raw evidence"
        title="Copy raw text"
        onClick={() => void copy()}
      >
        <CopyIcon className={copied ? "text-primary" : undefined} />
      </Button>
      <div className="flex flex-col gap-2 font-mono text-xs">
        {blocks.map((b, i) => {
          if (b.kind === "title") {
            return (
              <div
                key={i}
                className="mt-2 mb-1 border-primary/40 border-l-2 pl-2 font-semibold text-foreground first:mt-0"
                >
                {b.text}
              </div>
            );
          }
          if (b.kind === "json") {
            return <JsonBlock key={i} raw={b.text} />;
          }
          if (b.kind === "code") {
            return (
              <pre
                key={i}
                className="overflow-x-auto rounded border bg-muted/60 px-2 py-1.5 whitespace-pre-wrap"
              >
                {b.text}
              </pre>
            );
          }
          if (b.kind === "list") {
            return (
              <div key={i} className="flex gap-1.5">
                <span className="text-muted-foreground select-none">•</span>
                <span className="whitespace-pre-wrap">{b.text}</span>
              </div>
            );
          }
          return (
            <div key={i} className="whitespace-pre-wrap">
              {b.text}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function JsonBlock({ raw }: { raw: string }) {
  const pretty = React.useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }, [raw]);
  const [expanded, setExpanded] = React.useState(false);
  const lines = pretty.split("\n");
  const clipped = !expanded && lines.length > 12;
  return (
    <div className="rounded border bg-muted/60">
      <pre
        className={cn(
          "overflow-auto px-2 py-1.5 whitespace-pre",
          clipped ? "max-h-72 overflow-y-auto" : "",
        )}
      >
        {clipped ? lines.slice(0, 12).join("\n") + "\n…" : pretty}
      </pre>
      {lines.length > 12 && (
        <button
          type="button"
          className="text-muted-foreground hover:text-foreground w-full border-t px-2 py-1 text-left text-[11px]"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Collapse JSON" : `Expand JSON (${lines.length} lines)`}
        </button>
      )}
    </div>
  );
}

type Block = { kind: "title" | "json" | "code" | "list" | "text"; text: string };

export function parseEvidence(text: string): Block[] {
  const lines = (text ?? "").replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let buf: string[] = [];
  let inFence = false;

  const flushText = () => {
    if (buf.length) {
      blocks.push({ kind: "text", text: buf.join("\n") });
      buf = [];
    }
  };

  for (const ln of lines) {
    const trimmed = ln.trim();
    if (trimmed.startsWith("```")) {
      flushText();
      inFence = !inFence;
      continue;
    }
    if (inFence) {
      blocks.push({ kind: "code", text: ln });
      continue;
    }
    // JSON lines (starting with { or [ and parseable → their own pretty-printed block;
    // multi-line JSON falls back to verbatim when parsing fails)
    if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && trimmed.length > 40) {
      flushText();
      blocks.push({ kind: "json", text: trimmed });
      continue;
    }
    if (/^#{1,4}\s/.test(trimmed)) {
      flushText();
      blocks.push({ kind: "title", text: trimmed.replace(/^#+\s*/, "") });
      continue;
    }
    if (/^[-*]\s/.test(trimmed)) {
      flushText();
      blocks.push({ kind: "list", text: trimmed.replace(/^[-*]\s*/, "") });
      continue;
    }
    if (trimmed === "") {
      flushText();
      continue;
    }
    buf.push(ln);
  }
  flushText();
  return blocks;
}
