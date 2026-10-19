import { cn } from "@/lib/utils";
import { formatRelative } from "@/lib/format";

export type MuteReason =
  | "risk_accepted"
  | "false_positive"
  | "compensating_control"
  | "remediation_in_progress"
  | "not_applicable";

export const MUTE_REASON_LABELS: Record<MuteReason, string> = {
  risk_accepted: "Risk accepted",
  false_positive: "False positive",
  compensating_control: "Compensating control",
  remediation_in_progress: "Remediation in progress",
  not_applicable: "Not applicable",
};

/**
 * The human layer of a finding.
 *
 * This is the component the product exists for. A mute is a *judgement*, not
 * a status: a finding can be failing and muted at the same time, and the
 * failing part must stay fully legible. So this renders as an annotation
 * sitting ON the machine reading rather than replacing it — the row above
 * keeps its severity and status exactly as the scanner reported them.
 *
 * Visually it is matte on purpose. Scanner-derived data in this interface
 * carries chroma and luminance; human-authored data does not. That is the
 * whole reason a reader can tell, at a glance and without clicking, what the
 * scanner measured versus what a colleague decided — which is precisely the
 * distinction a customer will challenge.
 */
export function OverlayRail({
  reason,
  note,
  author,
  mutedAt,
  className,
}: {
  reason: MuteReason;
  note?: string | null;
  author?: string | null;
  mutedAt?: string | null;
  className?: string;
}) {
  return (
    <div
      className={cn(
        // The rail itself: a hairline, not a colour. No glow, no fill.
        "border-l-2 border-strong pl-3 py-1",
        "text-ink-secondary",
        className,
      )}
    >
      <p className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
        <span className="font-medium text-ink-secondary">Muted</span>
        <span aria-hidden className="text-ink-muted">
          ·
        </span>
        <span>{MUTE_REASON_LABELS[reason]}</span>
        {author && (
          <>
            <span aria-hidden className="text-ink-muted">
              ·
            </span>
            <span className="text-ink-muted">{author}</span>
          </>
        )}
        {mutedAt && (
          <>
            <span aria-hidden className="text-ink-muted">
              ·
            </span>
            <span className="text-ink-muted">{formatRelative(mutedAt)}</span>
          </>
        )}
      </p>
      {note && (
        // Proportional type, not mono — this sentence was written by a
        // person, and the register change is the signal.
        <p className="mt-1 text-xs leading-relaxed text-ink-muted italic">“{note}”</p>
      )}
    </div>
  );
}
