import { SEVERITY_RANK, type Severity } from "@/components/severity-chip";
import { cn } from "@/lib/utils";

export interface TreemapBlock {
  key: string;
  label: string;
  count: number;
  /** Highest-ranked severity present for this block — the block's fill
   *  color, same "worst wins" rule `groupByCheck` uses. */
  dominantSeverity: Severity;
}

/** A single-level, flex-sized block layout — not a nested squarified
 *  treemap. Area (via `flex-grow`) encodes count, color encodes dominant
 *  severity, reusing the same `-line` tokens `SeverityChip`/`DonutChart`
 *  already use. Deliberately this simple: the app installs no chart
 *  library, and a single dimension (service) doesn't need
 *  a real treemap algorithm to lay out honestly. */
export function TreemapChart({
  blocks,
  onSelect,
}: {
  blocks: TreemapBlock[];
  onSelect?: (block: TreemapBlock) => void;
}) {
  const sorted = [...blocks].sort((a, b) => b.count - a.count);
  const total = sorted.reduce((sum, b) => sum + b.count, 0);

  return (
    <div className="flex flex-wrap gap-1" role="list">
      {sorted.map((block) => {
        const share = total > 0 ? block.count / total : 0;
        const Tag = onSelect ? "button" : "div";
        return (
          <Tag
            key={block.key}
            role="listitem"
            type={onSelect ? "button" : undefined}
            onClick={onSelect ? () => onSelect(block) : undefined}
            className={cn(
              "flex min-w-[92px] flex-col justify-end gap-0.5 rounded-md px-3 py-2.5 text-left transition-opacity",
              onSelect && "cursor-pointer hover:opacity-85",
            )}
            style={{
              flexGrow: Math.max(block.count, 1),
              flexBasis: `${Math.max(share * 100, 10)}%`,
              backgroundColor: `var(--color-sev-${block.dominantSeverity}-line)`,
              minHeight: 72,
            }}
          >
            <span className="truncate text-xs font-medium text-ink">{block.label}</span>
            <span className="font-display text-lg font-medium tabular-nums text-ink">
              {block.count}
            </span>
          </Tag>
        );
      })}
    </div>
  );
}

export function dominantSeverityOf(severities: Severity[]): Severity {
  return severities.reduce((worst, severity) =>
    SEVERITY_RANK[severity] > SEVERITY_RANK[worst] ? severity : worst,
  );
}
