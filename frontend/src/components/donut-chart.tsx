import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export interface DonutSlice {
  key: string;
  label: string;
  value: number;
  /** A `var(--color-…)` reference — always a token from an already-validated
   *  ramp (severity or status), never a hand-picked hex. */
  color: string;
}

/**
 * A part-to-whole ring with a hero number at the center.
 *
 * Donuts are the deprioritized form for part-to-whole in this app's own
 * dataviz convention (a stacked bar reads more precisely) — this exists
 * because the dashboard it serves was specified against a reference with
 * exactly this shape. What's non-negotiable regardless of form: colors are
 * reused, validated tokens (severity/status), never invented; a 2px surface
 * gap separates every segment the same way a stacked bar's segments would;
 * every segment gets a hover tooltip with its exact value, not color alone;
 * and a legend below always carries the identity a reader can't get from
 * the ring at a glance.
 */
export function DonutChart({
  slices,
  centerValue,
  centerLabel,
  size = 152,
  thickness = 14,
  className,
}: {
  slices: DonutSlice[];
  centerValue: string | number;
  centerLabel: string;
  size?: number;
  thickness?: number;
  className?: string;
}) {
  const total = slices.reduce((sum, s) => sum + s.value, 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const GAP_PX = 2; // the same surface gap a stacked bar's segments get

  let elapsed = 0;

  return (
    <div className={cn("flex flex-col items-center gap-4", className)}>
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={centerLabel}>
          <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
            {/* Unfilled track — only visible where nothing is plotted
                (the empty-state, or slices that don't sum to the total). */}
            <circle
              cx={size / 2} cy={size / 2} r={radius}
              fill="none" stroke="var(--color-track)" strokeWidth={thickness}
            />
            {total > 0 &&
              slices
                .filter((slice) => slice.value > 0)
                .map((slice) => {
                  const fraction = slice.value / total;
                  const dash = fraction * circumference;
                  const dashOffset = -elapsed;
                  elapsed += dash;
                  return (
                    <Tooltip key={slice.key}>
                      <TooltipTrigger asChild>
                        <circle
                          cx={size / 2} cy={size / 2} r={radius}
                          fill="none"
                          stroke={slice.color}
                          strokeWidth={thickness}
                          strokeDasharray={`${Math.max(dash - GAP_PX, 0)} ${circumference}`}
                          strokeDashoffset={dashOffset}
                          strokeLinecap="round"
                          tabIndex={0}
                          className="cursor-default outline-none focus-visible:opacity-80"
                        />
                      </TooltipTrigger>
                      <TooltipContent side="top">
                        {slice.label}: {slice.value} ({Math.round(fraction * 100)}%)
                      </TooltipContent>
                    </Tooltip>
                  );
                })}
          </g>
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="display-number">{centerValue}</span>
          <span className="text-xs text-ink-muted">{centerLabel}</span>
        </div>
      </div>

      {/* Legend — the dependable identity channel; every slice appears here
          even ones too thin to read a tooltip off comfortably. */}
      <ul className="flex flex-wrap justify-center gap-x-4 gap-y-1.5">
        {slices.map((slice) => (
          <li key={slice.key} className="flex items-center gap-1.5 text-xs text-ink-secondary">
            <span
              aria-hidden
              className="size-2 shrink-0 rounded-full"
              style={{ backgroundColor: slice.color }}
            />
            {slice.label}
            <span className="font-mono text-ink-muted">{slice.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
