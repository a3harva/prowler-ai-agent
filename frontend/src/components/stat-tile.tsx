import { Panel } from "@/components/app-shell";
import { cn } from "@/lib/utils";

/** A single number in a `Panel`. `tone="warning"` is the emphasis card — the
 *  metric the screen most wants attention on (failing findings, failed
 *  requirements) — rendered on a brand-blue-tinted ground with a blue
 *  numeral, matching the reference's "failing" tile. This is deliberate,
 *  not a slip in the "blue never encodes state" rule: emphasis is a
 *  different signal than state, and the tile still carries no severity or
 *  pass/fail colour of its own. Shared by the Findings table page's header
 *  row, the Findings Overview page, and the Compliance report — moved here
 *  so none of them has to duplicate it. */
export function StatTile({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: number;
  tone?: "neutral" | "warning";
}) {
  const emphasis = tone === "warning" && value > 0;
  return (
    <Panel
      className={cn(
        "space-y-1",
        emphasis && "border-brand-200 bg-gradient-to-br from-brand-100 to-panel",
      )}
    >
      <p className={cn("text-sm font-medium", emphasis ? "text-brand" : "text-ink-secondary")}>
        {label}
      </p>
      <p className={cn("display-number", emphasis && "text-brand")}>{value}</p>
    </Panel>
  );
}
