import { SEVERITY_ORDER, SEVERITY_LABEL, type Severity } from "@/components/severity-chip";
import type { ServiceSeverityCell } from "@/lib/findings-aggregates";

const MAX_ROWS = 12;

/** Service × severity matrix. Cell colour is the severity's own `-line`
 *  token at an opacity scaled by count, normalized against the
 *  **matrix-wide** max (not per-row/per-column) — a global max keeps "this
 *  is the worst cell in the whole grid" a meaningful comparison across
 *  services, which a per-column normalization would blur. Rows are capped
 *  at the busiest `MAX_ROWS` services so the grid stays a glance, not a
 *  scroll, even with many services touched. */
export function FindingsHeatmap({
  cells,
  onSelect,
}: {
  cells: ServiceSeverityCell[];
  onSelect?: (service: string, severity: Severity) => void;
}) {
  const totalsByService = new Map<string, number>();
  for (const cell of cells) {
    totalsByService.set(cell.service, (totalsByService.get(cell.service) ?? 0) + cell.count);
  }
  const services = [...totalsByService.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([service]) => service);
  const shownServices = services.slice(0, MAX_ROWS);
  const hiddenCount = services.length - shownServices.length;

  const byServiceSeverity = new Map<string, number>();
  let max = 0;
  for (const cell of cells) {
    byServiceSeverity.set(`${cell.service} ${cell.severity}`, cell.count);
    if (cell.count > max) max = cell.count;
  }

  return (
    <div>
      <div
        className="grid gap-1"
        style={{ gridTemplateColumns: `120px repeat(${SEVERITY_ORDER.length}, 1fr)` }}
      >
        <div />
        {SEVERITY_ORDER.map((severity) => (
          <div
            key={severity}
            className="eyebrow pb-1 text-center"
          >
            {SEVERITY_LABEL[severity]}
          </div>
        ))}

        {shownServices.map((service) => (
          <RowCells
            key={service}
            service={service}
            max={max}
            byServiceSeverity={byServiceSeverity}
            onSelect={onSelect}
          />
        ))}
      </div>
      {hiddenCount > 0 && (
        <p className="mt-2 text-xs text-ink-muted">
          +{hiddenCount} more service{hiddenCount === 1 ? "" : "s"} — see the table below.
        </p>
      )}
    </div>
  );
}

function RowCells({
  service,
  max,
  byServiceSeverity,
  onSelect,
}: {
  service: string;
  max: number;
  byServiceSeverity: Map<string, number>;
  onSelect?: (service: string, severity: Severity) => void;
}) {
  return (
    <>
      <div className="flex items-center truncate text-xs text-ink-secondary" title={service}>
        {service}
      </div>
      {SEVERITY_ORDER.map((severity) => {
        const count = byServiceSeverity.get(`${service} ${severity}`) ?? 0;
        const intensity = max > 0 ? count / max : 0;
        // The shading ramp lives on the background (color-mix against the
        // panel surface), not on the element's own opacity — opacity would
        // dim the cell's number along with its fill, making low-count cells
        // unreadable.
        const mixPct = Math.round(25 + intensity * 75);
        const Tag = onSelect && count > 0 ? "button" : "div";
        return (
          <Tag
            key={severity}
            type={onSelect && count > 0 ? "button" : undefined}
            onClick={onSelect && count > 0 ? () => onSelect(service, severity) : undefined}
            className="flex h-9 items-center justify-center rounded-md text-xs font-semibold tabular-nums text-ink"
            style={{
              backgroundColor:
                count > 0
                  ? `color-mix(in oklab, var(--color-sev-${severity}-line) ${mixPct}%, var(--color-panel))`
                  : "var(--color-track)",
              cursor: onSelect && count > 0 ? "pointer" : undefined,
            }}
          >
            {count > 0 ? count : <span className="text-ink-muted">—</span>}
          </Tag>
        );
      })}
    </>
  );
}
