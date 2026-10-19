import { Ban, Check, CircleHelp, X } from "lucide-react";
import { cn, PILL_CLASS } from "@/lib/utils";

export type FindingStatus = "PASS" | "FAIL" | "MANUAL" | "RESOURCE_DOES_NOT_EXIST";

/** Status is a reserved palette — these colours are never reused for
 *  anything else in the app. Glyph plus label plus colour, so the badge
 *  still reads correctly in greyscale, in print, and for a colourblind
 *  reader. `FAIL` and `critical` are necessarily both red; they are told
 *  apart by sitting in different columns with different shapes, and by
 *  saying what they are. */
const STATUS_META: Record<
  FindingStatus,
  { label: string; icon: typeof Check; className: string }
> = {
  PASS: {
    label: "Passed",
    icon: Check,
    className: "bg-status-pass-bg text-status-pass ring-status-pass-line",
  },
  FAIL: {
    label: "Failed",
    icon: X,
    className: "bg-status-fail-bg text-status-fail ring-status-fail-line",
  },
  MANUAL: {
    label: "Needs review",
    icon: CircleHelp,
    className: "bg-status-manual-bg text-status-manual ring-status-manual-line",
  },
  RESOURCE_DOES_NOT_EXIST: {
    label: "Resource gone",
    icon: Ban,
    className: "bg-status-gone-bg text-status-gone ring-status-gone-line",
  },
};

export function StatusBadge({
  status,
  className,
}: {
  status: FindingStatus;
  className?: string;
}) {
  const meta = STATUS_META[status];
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
