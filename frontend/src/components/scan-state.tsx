import { Ban, Check, CircleAlert, Clock, Download, LoaderCircle, TriangleAlert, X } from "lucide-react";
import { cn, PILL_CLASS } from "@/lib/utils";

/** Every state in the planned `scan_status` enum. Terminal failures are
 *  distinguished from one another rather than collapsed into "failed",
 *  because each distinct failure must be recognisable in the interface — a
 *  schema mismatch and an ungranted impersonation need
 *  completely different responses from the person reading the screen. */
export type ScanStatus =
  | "queued"
  | "running"
  | "importing"
  | "succeeded"
  | "failed"
  | "timeout"
  | "schema_mismatch"
  | "import_failed"
  | "cancelled";

const SCAN_META: Record<
  ScanStatus,
  { label: string; icon: typeof Check; className: string; spin?: boolean }
> = {
  queued: {
    label: "Queued",
    icon: Clock,
    className: "bg-subtle text-ink-secondary ring-hairline",
  },
  running: {
    label: "Running",
    icon: LoaderCircle,
    className: "bg-brand-50 text-brand ring-brand-200",
    spin: true,
  },
  importing: {
    label: "Importing",
    icon: Download,
    className: "bg-brand-50 text-brand ring-brand-200",
    spin: true,
  },
  succeeded: {
    label: "Succeeded",
    icon: Check,
    className: "bg-status-pass-bg text-status-pass ring-status-pass-line",
  },
  failed: {
    label: "Failed",
    icon: X,
    className: "bg-status-fail-bg text-status-fail ring-status-fail-line",
  },
  timeout: {
    label: "Timed out",
    icon: Clock,
    className: "bg-status-manual-bg text-status-manual ring-status-manual-line",
  },
  schema_mismatch: {
    label: "Schema mismatch",
    icon: TriangleAlert,
    className: "bg-status-manual-bg text-status-manual ring-status-manual-line",
  },
  import_failed: {
    label: "Import failed",
    icon: CircleAlert,
    className: "bg-status-fail-bg text-status-fail ring-status-fail-line",
  },
  cancelled: {
    label: "Cancelled",
    icon: Ban,
    className: "bg-subtle text-ink-secondary ring-hairline",
  },
};

export const SCAN_STATUS_ORDER = Object.keys(SCAN_META) as ScanStatus[];
export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = Object.fromEntries(
  SCAN_STATUS_ORDER.map((status) => [status, SCAN_META[status].label]),
) as Record<ScanStatus, string>;

export function isScanActive(status: ScanStatus): boolean {
  return status === "queued" || status === "running" || status === "importing";
}

export function ScanState({
  status,
  className,
}: {
  status: ScanStatus;
  className?: string;
}) {
  const meta = SCAN_META[status];
  const Icon = meta.icon;
  return (
    <span
      className={cn(PILL_CLASS, meta.className, className)}
    >
      {/* The one place motion is spent in this app. Suppressed wholesale by
          the reduced-motion block in index.css. */}
      <Icon className={cn("size-3.5 shrink-0", meta.spin && "animate-spin")} aria-hidden />
      {meta.label}
    </span>
  );
}

/** A bare pulsing dot, for a table cell where a full badge is too heavy but
 *  "is this still moving?" still needs answering. */
export function ScanPulse({ status }: { status: ScanStatus }) {
  const active = isScanActive(status);
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block size-2 rounded-full",
        active ? "bg-brand pulse-live" : "bg-strong",
      )}
    />
  );
}
