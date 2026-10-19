import type { Finding } from "@/api/types";
import { SEVERITY_LABEL, SEVERITY_ORDER, SEVERITY_RANK, type Severity } from "@/components/severity-chip";
import type { DonutSlice } from "@/components/donut-chart";
import type { FindingStatus } from "@/components/status-badge";

export interface FindingStats {
  total: number;
  failing: number;
  passing: number;
  muted: number;
}

/** One pass over `findings`, not four separate `.filter().length` scans —
 *  same single-loop convention as `groupByCheck`/`groupByServiceSeverity`
 *  below, so the stat tiles compute the same way everything else in this
 *  module does. */
export function computeFindingStats(findings: Finding[]): FindingStats {
  const stats: FindingStats = { total: 0, failing: 0, passing: 0, muted: 0 };
  for (const finding of findings) {
    stats.total += 1;
    if (finding.status === "FAIL") stats.failing += 1;
    if (finding.status === "PASS") stats.passing += 1;
    if (finding.muted) stats.muted += 1;
  }
  return stats;
}

/** One row per `check_id` — many findings collapse into one "how bad is
 *  this check" summary, the same event→issue relationship Sentry uses for
 *  errors. `worstSeverity` picks the highest-ranked severity seen for the
 *  check (via the same `SEVERITY_RANK` the findings table sorts by), not
 *  an average — a check that's mostly low severity but critical on one
 *  resource is still a critical check to look at first. */
export interface CheckGroup {
  checkId: string;
  checkTitle: string;
  worstSeverity: Severity;
  services: string[];
  failing: number;
  passing: number;
  muted: number;
  total: number;
}

export function groupByCheck(findings: Finding[]): CheckGroup[] {
  const groups = new Map<string, CheckGroup>();
  for (const finding of findings) {
    let group = groups.get(finding.check_id);
    if (!group) {
      group = {
        checkId: finding.check_id,
        checkTitle: finding.check_title,
        worstSeverity: finding.severity as Severity,
        services: [],
        failing: 0,
        passing: 0,
        muted: 0,
        total: 0,
      };
      groups.set(finding.check_id, group);
    }
    const severity = finding.severity as Severity;
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[group.worstSeverity]) {
      group.worstSeverity = severity;
    }
    if (!group.services.includes(finding.service_name)) {
      group.services.push(finding.service_name);
    }
    if (finding.status === "FAIL") group.failing += 1;
    if (finding.status === "PASS") group.passing += 1;
    if (finding.muted) group.muted += 1;
    group.total += 1;
  }
  return [...groups.values()];
}

/** One entry per (service, severity) combination actually present — the
 *  shared source for both the treemap (rolled up further to per-service
 *  totals) and the heatmap (used directly as matrix cells). */
export interface ServiceSeverityCell {
  service: string;
  severity: Severity;
  count: number;
}

export function groupByServiceSeverity(findings: Finding[]): ServiceSeverityCell[] {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const key = `${finding.service_name}::${finding.severity}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()].map(([key, count]) => {
    const [service, severity] = key.split("::");
    return { service, severity: severity as Severity, count };
  });
}

export function buildSeveritySlices(findings: Finding[]): DonutSlice[] {
  const counts: Partial<Record<Severity, number>> = {};
  for (const finding of findings) {
    const severity = finding.severity as Severity;
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return SEVERITY_ORDER.map((severity) => ({
    key: severity,
    label: SEVERITY_LABEL[severity],
    value: counts[severity] ?? 0,
    color: `var(--color-sev-${severity})`,
  }));
}

export const STATUS_ORDER: FindingStatus[] = ["FAIL", "PASS", "MANUAL", "RESOURCE_DOES_NOT_EXIST"];
export const STATUS_COLOR_VAR: Record<FindingStatus, string> = {
  FAIL: "var(--color-status-fail)",
  PASS: "var(--color-status-pass)",
  MANUAL: "var(--color-status-manual)",
  RESOURCE_DOES_NOT_EXIST: "var(--color-status-gone)",
};
export const STATUS_LABEL: Record<FindingStatus, string> = {
  FAIL: "Failed",
  PASS: "Passed",
  MANUAL: "Needs review",
  RESOURCE_DOES_NOT_EXIST: "Resource gone",
};

export function buildStatusSlices(findings: Finding[]): DonutSlice[] {
  const counts: Partial<Record<FindingStatus, number>> = {};
  for (const finding of findings) {
    const status = finding.status as FindingStatus;
    counts[status] = (counts[status] ?? 0) + 1;
  }
  return STATUS_ORDER.map((status) => ({
    key: status,
    label: STATUS_LABEL[status],
    value: counts[status] ?? 0,
    color: STATUS_COLOR_VAR[status],
  }));
}
