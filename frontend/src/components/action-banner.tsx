import { useState } from "react";
import { AlertTriangle, Check, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SeverityChip, type Severity } from "@/components/severity-chip";
import { PILL_CLASS, cn } from "@/lib/utils";
import type { PendingAction } from "@/api/types";

/**
 * The confirmation gate, as a UI.
 *
 * Everything rendered here comes from the server's own `summary`, built at
 * proposal time from the same validated arguments that will execute. Nothing
 * is recomputed client-side, and Confirm posts the action id **and nothing
 * else** — the arguments never leave the server. That is what makes this
 * banner binding rather than decorative: a tampered client cannot show one
 * mute and apply another, because it has no say in what gets applied.
 *
 * `affected_count` is deliberately prominent. A bulk check mute can touch
 * hundreds of resources, and the difference between confirming 1 and
 * confirming 340 is the whole decision.
 */
export function ActionBanner({
  action,
  onConfirm,
  onDiscard,
  busy,
  resolved,
}: {
  action: PendingAction;
  onConfirm: (id: number) => void;
  onDiscard: (id: number) => void;
  busy?: boolean;
  resolved?: "applied" | "discarded";
}) {
  const [expanded, setExpanded] = useState(false);
  const s = action.summary;
  const bulk = s.affected_count > 1;

  if (resolved) {
    return (
      <div
        className={cn(
          "rounded-lg border px-4 py-3 text-sm",
          resolved === "applied"
            ? "border-status-pass-line bg-status-pass-bg text-status-pass-text"
            : "border-hairline bg-subtle text-ink-secondary",
        )}
      >
        {resolved === "applied"
          ? `Applied — ${s.action.toLowerCase()} (${s.affected_count} ${
              s.affected_count === 1 ? "finding" : "findings"
            }).`
          : "Discarded — nothing was changed."}
      </div>
    );
  }

  return (
    <div
      className={cn(
        // Border-only at rest, per the design system: a bulk action is
        // signalled by the border and the count pill, both of which carry a
        // text label of their own rather than relying on a fill.
        "rounded-lg border bg-panel p-4",
        bulk ? "border-sev-high-line" : "border-hairline",
      )}
    >
      <div className="flex items-start gap-3">
        <AlertTriangle
          className={cn("mt-0.5 size-4 shrink-0", bulk ? "text-sev-high-text" : "text-ink-muted")}
          aria-hidden
        />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-ink">
            {s.action}
            {bulk && (
              <span className={cn(PILL_CLASS, "ml-2 bg-sev-high-bg text-sev-high-text ring-sev-high-line")}>
                {s.affected_count} findings
              </span>
            )}
          </p>

          <dl className="mt-2 grid gap-x-4 gap-y-1 text-xs sm:grid-cols-[auto_1fr]">
            {s.check_title && (
              <>
                <dt className="text-ink-muted">Check</dt>
                <dd className="text-ink">
                  {s.check_title}{" "}
                  {s.severity && <SeverityChip severity={s.severity as Severity} />}
                </dd>
              </>
            )}
            {s.check_id && (
              <>
                <dt className="text-ink-muted">Check id</dt>
                <dd className="font-mono text-[11px] text-ink">{s.check_id}</dd>
              </>
            )}
            {s.resource_name && (
              <>
                <dt className="text-ink-muted">Resource</dt>
                <dd className="font-mono text-[11px] text-ink">{s.resource_name}</dd>
              </>
            )}
            {s.mute_reason && (
              <>
                <dt className="text-ink-muted">Reason</dt>
                <dd className="text-ink">{s.mute_reason.replace(/_/g, " ")}</dd>
              </>
            )}
            {s.note && (
              <>
                <dt className="text-ink-muted">Note</dt>
                <dd className="text-ink">{s.note}</dd>
              </>
            )}
          </dl>

          {s.sample_resources && s.sample_resources.length > 0 && (
            <div className="mt-2">
              <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                className="text-xs text-brand underline-offset-2 hover:underline"
              >
                {expanded ? "Hide" : "Show"} affected resources
              </button>
              {expanded && (
                <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-ink-secondary">
                  {s.sample_resources.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                  {s.affected_count > s.sample_resources.length && (
                    <li className="italic">
                      …and {s.affected_count - s.sample_resources.length} more
                    </li>
                  )}
                </ul>
              )}
            </div>
          )}

          <p className="mt-3 text-xs text-ink-muted">
            Nothing has changed yet. This is recorded in the audit log under your name
            once confirmed.
          </p>

          <div className="mt-3 flex gap-2">
            <Button size="sm" onClick={() => onConfirm(action.id)} disabled={busy}>
              <Check className="size-3.5" aria-hidden />
              Confirm
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => onDiscard(action.id)}
              disabled={busy}
            >
              <X className="size-3.5" aria-hidden />
              Discard
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
