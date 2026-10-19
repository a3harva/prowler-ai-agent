import { cn, PILL_CLASS } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

/** Ordinal, worst first — the order the findings table sorts by. */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

/**
 * A tinted pill with a text label.
 *
 * Four warm steps cannot clear the categorical colour-difference floor on a
 * light ground — no palette can, which is why every console that renders
 * severity this way labels it too. Colour is reinforcement here, never the
 * only channel, and each pill's text clears 4.5:1 against its own tint.
 */
const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical ring-sev-critical-line",
  high: "bg-sev-high-bg text-sev-high ring-sev-high-line",
  medium: "bg-sev-medium-bg text-sev-medium ring-sev-medium-line",
  low: "bg-sev-low-bg text-sev-low ring-sev-low-line",
  informational:
    "bg-sev-informational-bg text-sev-informational ring-sev-informational-line",
};

export function SeverityChip({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cn(PILL_CLASS, SEVERITY_STYLES[severity], className)}
    >
      <span
        aria-hidden
        className="size-1.5 rounded-full bg-current opacity-70"
      />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

/** The leading rail on a finding row — severity as a vertical bar, which is
 *  how the eye scans a long list for the worst thing first. */
export function SeverityRail({ severity }: { severity: Severity }) {
  return (
    <span
      aria-hidden
      className="block w-1 self-stretch rounded-full"
      style={{ backgroundColor: `var(--color-sev-${severity})` }}
    />
  );
}
