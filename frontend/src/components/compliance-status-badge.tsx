import { Ban, Check, CircleHelp, X } from "lucide-react";
import { cn, PILL_CLASS } from "@/lib/utils";
import type { ComplianceRequirementStatus } from "@/api/types";

/** Reuses the same reserved status palette `status-badge.tsx` defines for
 *  findings (`bg-status-*`) — a requirement's rollup status is the same
 *  kind of fact (pass/fail/needs-review) at a different granularity, so it
 *  should read as visually the same category of thing, not a competing
 *  palette. `not_assessed` borrows the "gone" tint (muted/neutral) since
 *  both mean "no usable signal," just for different reasons. */
const REQUIREMENT_STATUS_META: Record<
  ComplianceRequirementStatus,
  { label: string; icon: typeof Check; className: string }
> = {
  pass: { label: "Passed", icon: Check, className: "bg-status-pass-bg text-status-pass ring-status-pass-line" },
  fail: { label: "Failed", icon: X, className: "bg-status-fail-bg text-status-fail ring-status-fail-line" },
  needs_review: {
    label: "Needs review",
    icon: CircleHelp,
    className: "bg-status-manual-bg text-status-manual ring-status-manual-line",
  },
  not_assessed: {
    label: "Not assessed",
    icon: Ban,
    className: "bg-status-gone-bg text-status-gone ring-status-gone-line",
  },
};

export function ComplianceStatusBadge({
  status,
  className,
}: {
  status: ComplianceRequirementStatus;
  className?: string;
}) {
  // Falls back rather than crashing the whole report table on an
  // unrecognised value — the backend schema is now a Literal of exactly
  // these four strings, but a network layer or a future status this
  // component hasn't been updated for shouldn't take the page down.
  const meta = REQUIREMENT_STATUS_META[status] ?? {
    label: status,
    icon: CircleHelp,
    className: "bg-subtle text-ink-muted ring-hairline",
  };
  const Icon = meta.icon;
  return (
    <span
      className={cn(PILL_CLASS, meta.className, className)}
    >
      <Icon className="size-3.5 shrink-0" aria-hidden />
      {meta.label}
    </span>
  );
}
