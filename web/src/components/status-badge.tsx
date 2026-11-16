import { cn } from "@/lib/utils";
import {
  statusMeta,
  toneClasses,
  toneDot,
  type StatusDomain,
  type Tone,
} from "@/lib/status";

export function StatusBadge({
  domain,
  value,
  dot = false,
  className,
  title,
}: {
  domain: StatusDomain;
  value: string;
  dot?: boolean;
  className?: string;
  /** Hover tooltip. Used to put "why this status" on the badge (e.g. why an intent was
   * interrupted). */
  title?: string;
}) {
  const meta = statusMeta(domain, value);
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 font-medium text-xs",
        toneClasses[meta.tone],
        className,
      )}
    >
      {dot && (
        <span className={cn("size-1.5 rounded-full", toneDot[meta.tone])} />
      )}
      {meta.label}
    </span>
  );
}

export function ToneDot({ tone }: { tone: Tone }) {
  return <span className={cn("size-2 rounded-full", toneDot[tone])} />;
}
