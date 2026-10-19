import { Check, Clock, LoaderCircle, TriangleAlert } from "lucide-react";
import { cn, PILL_CLASS } from "@/lib/utils";

/** The four states a report row can be in. Deliberately smaller than
 *  `ScanState`: a scan distinguishes several terminal failures because each
 *  needs a different response from the reader, whereas a report either exists
 *  or does not — the *reason* it failed is in `error_message`, and there is
 *  one action either way, which is to request another. */
export type ReportStatus = "queued" | "generating" | "completed" | "failed";

const REPORT_META: Record<
  ReportStatus,
  { label: string; icon: typeof Check; className: string; spin?: boolean }
> = {
  queued: {
    label: "Queued",
    icon: Clock,
    className: "bg-subtle text-ink-secondary ring-hairline",
  },
  generating: {
    label: "Generating",
    icon: LoaderCircle,
    className: "bg-brand-50 text-brand ring-brand-200",
    spin: true,
  },
  completed: {
    label: "Completed",
    icon: Check,
    className: "bg-status-pass-bg text-status-pass ring-status-pass-line",
  },
  failed: {
    label: "Failed",
    icon: TriangleAlert,
    className: "bg-status-fail-bg text-status-fail ring-status-fail-line",
  },
};

/** True while there is still something to poll for. */
export function isReportActive(status: ReportStatus): boolean {
  return status === "queued" || status === "generating";
}

export function ReportState({ status }: { status: ReportStatus }) {
  const meta = REPORT_META[status];
  if (!meta) return null;
  const Icon = meta.icon;
  return (
    <span className={cn(PILL_CLASS, meta.className)}>
      <Icon className={cn("size-3", meta.spin && "animate-spin")} aria-hidden />
      {meta.label}
    </span>
  );
}
