import { SEVERITY_ORDER, type Severity } from "@/components/severity-chip";
import { cn } from "@/lib/utils";

/**
 * A distribution rendered as a bar, in CSS, with no charting library.
 *
 * At the scale this product deals in — a handful of severity buckets, one
 * compliance percentage — a chart library would be several hundred kilobytes
 * to draw a rectangle. The console idiom (a filled track against an empty
 * one) is also more legible in a dense table row than a miniature chart.
 */
export function MeterBar({
  value,
  max,
  color = "var(--color-brand)",
  label,
  className,
}: {
  value: number;
  max: number;
  color?: string;
  label?: string;
  className?: string;
}) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return (
    <div
      className={cn("flex items-center gap-2", className)}
      role="meter"
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={label}
    >
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-track">
        <div
          className="h-full rounded-full transition-[width] duration-300 ease-out"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="w-10 shrink-0 text-right font-mono text-xs text-ink-secondary tabular-nums">
        {value}
      </span>
    </div>
  );
}

/** Severity distribution — the ordinal ramp read top to bottom, worst first,
 *  which is the order the work should be done in. */
export function SeverityDistribution({
  counts,
  className,
}: {
  counts: Partial<Record<Severity, number>>;
  className?: string;
}) {
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s] ?? 0));

  return (
    <div className={cn("space-y-2", className)}>
      {SEVERITY_ORDER.map((severity) => (
        <div key={severity} className="flex items-center gap-3">
          <span className="eyebrow w-24 shrink-0 font-mono">{severity}</span>
          <MeterBar
            className="flex-1"
            value={counts[severity] ?? 0}
            max={max}
            color={`var(--color-sev-${severity})`}
            label={`${severity} findings`}
          />
        </div>
      ))}
    </div>
  );
}
