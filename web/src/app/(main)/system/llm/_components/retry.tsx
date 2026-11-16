"use client";

// Shared components for LLM retry configuration: the "attempts + interval" for each of the five layers.
//
// The five layers from inside to outside: connect (SDK) → empty response (SDK) → same-provider safe window → rotation circuit breaker → intent rerun.
// The first three layers follow the endpoint, so each model profile can override the global defaults; the last two are process-level, with only one global copy.
//
// All inputs follow the same "leave blank = not configured" semantics, consistent with the backend db.RetryRule:
//   attempts   blank/0 = use built-in default | -1 = disable this retry layer | >0 = use this count
//   interval   blank/0 = use this layer's original exponential backoff | >0 = use this fixed millisecond interval instead

import * as React from "react";

import { Loader2Icon, SaveIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { LLMRetryOverride, LLMRetryPolicy, LLMRetryRule } from "@/lib/types";

export const ZERO_RULE: LLMRetryRule = { attempts: 0, interval_ms: 0 };
export const ZERO_OVERRIDE: LLMRetryOverride = {
  connect: ZERO_RULE,
  empty: ZERO_RULE,
  stream: ZERO_RULE,
};
const ZERO_POLICY: LLMRetryPolicy = {
  ...ZERO_OVERRIDE,
  breaker: ZERO_RULE,
  intent: ZERO_RULE,
};

type LayerMeta = {
  title: string;
  /** Where this retry layer happens and who executes it */
  where: string;
  /** What kind of errors reach this layer — down to the status code, don't make people guess */
  trigger: string;
  /** Errors that look similar but do NOT go through this layer, so filling in a value with no effect isn't mistaken for a bug */
  skips?: string;
  desc: string;
  attemptsLabel: string;
  /** Default value when attempts is left blank, used as placeholder */
  defAttempts: number;
  /** Default strategy when interval is left blank, used as placeholder */
  defInterval: string;
  /** Meaning of filling -1 for attempts */
  offHint: string;
};

export const RETRY_LAYERS = {
  connect: {
    title: "Connection retry",
    where: "SDK · before getting a 200",
    trigger:
      "Cannot connect or no 200 yet: network-layer errors such as connection reset / read-write timeout / DNS failure, plus HTTP 408, 429, 500, 502, 503, 504.",
    skips: "All other status codes (400 / 401 / 403 / 404 / 413 / 422, etc.) are deterministic rejections — resending fails the same way, so they are thrown upward directly.",
    desc: "Resends the same request as-is. Once the stream has started (a 200 has been received), mid-stream disconnections are no longer handled by this layer.",
    attemptsLabel: "Retry count",
    defAttempts: 3,
    defInterval: "0.5s→1s→2s exponential (capped at 8s)",
    offHint: "-1 = no retries at all, throw immediately on failure",
  },
  empty: {
    title: "Empty response retry",
    where: "SDK · openai format only",
    trigger:
      "HTTP 200 with finish_reason a normal stop, but the entire response has no content block at all — empty gateway frames, dropped thinking-field frames, and sampling hiccups all look like this.",
    skips: "Content truncated due to max_tokens doesn't count (solve that by raising the output limit; resending will just hit it again).",
    desc: "Resends the whole prompt, so it's relatively expensive on long contexts; don't set the count too high.",
    attemptsLabel: "Retry count",
    defAttempts: 2,
    defInterval: "0.5s→1s→2s exponential (capped at 8s)",
    offHint: "-1 = hand off empty responses as-is directly",
  },
  stream: {
    title: "Same-provider safe window retry",
    where: "This project · before any output is delivered",
    trigger:
      "Problems occur only after the stream is established (a 200 received): mid-stream disconnection, provider overloaded, in-stream 429 / 5xx error events — and not a single token has been handed to the caller yet.",
    skips:
      "Quota exhausted (402 / insufficient_quota, handled by rotation switching profiles), context too long (413 / context length, handled by compaction), 400 / 401 / 403 / 404 / 422 deterministic rejections — none are retried.",
    desc: "Replays the same request on the same profile. Since no output has been delivered yet, replay won't duplicate model output or tool execution.",
    attemptsLabel: "Retry count",
    defAttempts: 2,
    defInterval: "0.5s→1s exponential (capped at 4s)",
    offHint: "-1 = hand broken streams directly to the outer intent rerun",
  },
  breaker: {
    title: "Rotation circuit breaker",
    where: "This project · process-level, one global copy",
    trigger:
      "Circuit breaks when transient failures (429, 5xx, network errors) accumulate consecutively to the threshold; deterministic failures such as insufficient balance (402), invalid key (401 / 403), and model not found (404) ignore the threshold and break on the first occurrence.",
    skips: "A single success resets the counter, so an occasionally flaky profile won't slowly accumulate toward a break.",
    desc: "After breaking, it enters cooldown; during cooldown, rotation skips this profile entirely. State is persisted to the database and survives restarts.",
    attemptsLabel: "Consecutive failures before break",
    defAttempts: 3,
    defInterval: "1min→5min→30min ladder",
    offHint: "-1 = transient failures never break the circuit (deterministic failures still break it)",
  },
  intent: {
    title: "Intent rerun",
    where: "This project · process-level, one global copy",
    trigger:
      "The earlier layers all failed to catch it: the worker ends with model_error — either all inner retries were exhausted, or the stream broke only after it had started delivering output (at that point replay isn't safe, so the whole thing must be redone).",
    skips: "Quota exhaustion is already handled by rotation switching profiles, so it isn't rerun here; when the task is paused / terminated / entering wrap-up, it yields immediately without consuming backoff time.",
    desc: "Reruns the entire intent from scratch. It's the outermost layer, so one rerun means the counts of the inner layers get multiplied again.",
    attemptsLabel: "Rerun count",
    defAttempts: 2,
    defInterval: "Fixed 3s",
    offHint: "-1 = no rerun, the intent is marked blocked directly",
  },
} satisfies Record<string, LayerMeta>;

type LayerKey = keyof typeof RETRY_LAYERS;

/** Human-readable milliseconds, only for echoing next to the input so people don't have to count zeros. */
function humanMs(ms: number) {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${Number((ms / 1000).toFixed(2))}s`;
  return `${Number((ms / 60_000).toFixed(2))}min`;
}

/** Controlled numeric input: empty string ↔ 0, intermediate states ("-", "1e") stay local as-is without disturbing the parent. */
function NumField({
  id,
  value,
  onChange,
  placeholder,
  min,
}: {
  id: string;
  value: number;
  onChange: (n: number) => void;
  placeholder: string;
  min: number;
}) {
  const [text, setText] = React.useState(value === 0 ? "" : String(value));
  // Follow along when the parent swaps in a whole new set of values (policy loaded, profile switched); this won't trigger while typing,
  // because at that point value already equals the parsed result of the local text.
  React.useEffect(() => {
    const incoming = value === 0 ? "" : String(value);
    setText((cur) => (Number(cur || 0) === value ? cur : incoming));
  }, [value]);
  return (
    <Input
      id={id}
      type="number"
      min={min}
      className="w-28 shrink-0"
      value={text}
      placeholder={placeholder}
      onChange={(e) => {
        setText(e.target.value);
        const n = Number(e.target.value);
        onChange(e.target.value.trim() === "" || !Number.isFinite(n) ? 0 : Math.trunc(n));
      }}
    />
  );
}

/** The two knobs for one retry layer. idPrefix keeps label htmlFor unique when this appears multiple times on a page. */
export function RetryRuleFields({
  layer,
  idPrefix,
  value,
  onChange,
  compact,
}: {
  layer: LayerKey;
  idPrefix: string;
  value: LLMRetryRule;
  onChange: (r: LLMRetryRule) => void;
  /** true = compact version in the profile drawer: drops the expanded explanation, keeping only the "what errors reach this layer" line */
  compact?: boolean;
}) {
  const meta = RETRY_LAYERS[layer];
  const human = humanMs(value.interval_ms);
  return (
    <div className={compact ? "grid gap-2" : "grid gap-3 rounded-lg border p-3"}>
      <div className="grid gap-0.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <Label className="text-sm">{meta.title}</Label>
          <span className="text-muted-foreground text-xs">{meta.where}</span>
        </div>
        {/* Which errors reach this layer, down to the status code — if you fill in the knob but see no effect, chances are the errors don't fall into this layer at all. */}
        <p className="text-muted-foreground text-xs">
          <span className="font-medium text-foreground">Trigger</span>: {meta.trigger}
        </p>
        {!compact && meta.skips && (
          <p className="text-muted-foreground text-xs">
            <span className="font-medium text-foreground">Skips this layer</span>: {meta.skips}
          </p>
        )}
        {!compact && <p className="text-muted-foreground text-xs">{meta.desc}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-n`} className="text-muted-foreground text-xs">
            {meta.attemptsLabel}
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-n`}
            min={-1}
            value={value.attempts}
            placeholder={`Default ${meta.defAttempts}`}
            onChange={(n) => onChange({ ...value, attempts: n })}
          />
        </div>
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-ms`} className="text-muted-foreground text-xs">
            Interval ms
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-ms`}
            min={0}
            value={value.interval_ms}
            placeholder="Default backoff"
            onChange={(n) => onChange({ ...value, interval_ms: n })}
          />
          <span className="text-muted-foreground text-xs">{human ? `Fixed ${human}` : meta.defInterval}</span>
        </div>
      </div>
      {!compact && <p className="text-muted-foreground text-xs">Leave blank = use default; {meta.offHint}.</p>}
    </div>
  );
}

/** The three-layer override in the model profile drawer (the three layers that follow the endpoint). */
export function ProfileRetryFields({
  value,
  onChange,
}: {
  value: LLMRetryOverride;
  onChange: (o: LLMRetryOverride) => void;
}) {
  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="grid gap-0.5">
        <Label className="text-sm">Retry overrides</Label>
        <p className="text-muted-foreground text-xs">
          Applies only to this profile, overriding the global defaults in "Retry & Backoff". Each field left blank = follow global; attempts set to -1 = turn off this retry layer;
          if interval is filled, a fixed interval replaces exponential backoff. The circuit breaker and intent rerun are process-level and can only be adjusted on the global page.
        </p>
      </div>
      {(["connect", "empty", "stream"] as const).map((k) => (
        <div key={k} className="border-t pt-3 first:border-t-0 first:pt-0">
          <RetryRuleFields
            compact
            layer={k}
            idPrefix="pf"
            value={value[k]}
            onChange={(r) => onChange({ ...value, [k]: r })}
          />
        </div>
      ))}
    </div>
  );
}

/** The "Retry & Backoff" tab: global default values for the five layers. */
export function RetryPolicyPanel() {
  const [policy, setPolicy] = React.useState<LLMRetryPolicy>(ZERO_POLICY);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const p = await api.llmRetryPolicy();
      setPolicy({ ...ZERO_POLICY, ...p });
    } catch (e) {
      toast.error(`Failed to load retry policy: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function save() {
    if (saving) return;
    setSaving(true);
    try {
      // The backend clamps out-of-range values back into range and returns them; refresh directly from the returned value so what you see is what's stored.
      const saved = await api.saveLLMRetryPolicy(policy);
      setPolicy({ ...ZERO_POLICY, ...saved });
      toast.success("Saved and effective immediately (the current in-flight call still uses the old parameters)");
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  const set = (k: LayerKey) => (r: LLMRetryRule) => setPolicy((p) => ({ ...p, [k]: r }));

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-dashed p-10 text-muted-foreground text-sm">
        <Loader2Icon className="size-4 animate-spin" /> Loading retry policy…
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      <div className="rounded-lg border bg-muted/30 p-3 text-muted-foreground text-xs leading-relaxed">
        A failed model call passes through five retry layers in sequence, from inside to outside:
        <span className="text-foreground"> connect → empty response → same-provider safe window → rotation circuit breaker → intent rerun</span>
        . Inner layers must be exhausted before the outer ones get a turn, so the counts are
        {" "}<span className="text-foreground">multiplied</span>
        — max out every layer and a single hiccup can burn dozens of requests.
        Leave everything blank to use the current defaults, exactly matching behavior before this page existed. The first three layers can be overridden individually in each model profile.
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(Object.keys(RETRY_LAYERS) as LayerKey[]).map((k) => (
          <RetryRuleFields key={k} layer={k} idPrefix="gl" value={policy[k]} onChange={set(k)} />
        ))}
      </div>

      <div className="flex gap-2">
        <Button onClick={save} disabled={saving}>
          {saving ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
          Save
        </Button>
        <Button variant="outline" onClick={() => setPolicy(ZERO_POLICY)} disabled={saving}>
          Reset all to defaults
        </Button>
      </div>
    </div>
  );
}
