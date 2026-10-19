import { cn, PILL_CLASS } from "@/lib/utils";
import { MUTE_REASON_LABELS, type MuteReason } from "@/components/overlay-rail";

/**
 * The report's resource table Status column reads either "Open" or
 * "Accepted Risk — {mute_reason}" — `_resource_table()`'s own two literal
 * shapes (backend/app/services/report_render.py). Deliberately not a reuse
 * of `StatusBadge`: that component's vocabulary
 * (PASS/FAIL/MANUAL/RESOURCE_DOES_NOT_EXIST) is a different one than
 * "Open"/"Accepted Risk", so forcing a fit there would be wrong.
 */
export function ReportResourceStatus({ text }: { text: string }) {
  const acceptedMatch = /^Accepted Risk — (.+)$/.exec(text);
  if (acceptedMatch) {
    const reason = acceptedMatch[1] as MuteReason;
    const label = MUTE_REASON_LABELS[reason] ?? acceptedMatch[1];
    return (
      <span className={cn(PILL_CLASS, "bg-notice-bg text-notice ring-notice-line")}>
        Accepted risk — {label}
      </span>
    );
  }
  if (text === "Open") {
    return (
      <span className={cn(PILL_CLASS, "bg-status-fail-bg text-status-fail ring-status-fail-line")}>
        Open
      </span>
    );
  }
  return <span className="text-ink-secondary">{text}</span>;
}
