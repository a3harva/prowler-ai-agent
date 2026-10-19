import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { BellOff, Compass, Download, Layers, LoaderCircle, ShieldAlert, ShieldQuestion } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable, MutedCell } from "@/components/data-table";
import { CopyableUid } from "@/components/copyable-uid";
import { EmptyState } from "@/components/states";
import { SeverityChip, SEVERITY_ORDER, SEVERITY_RANK, type Severity } from "@/components/severity-chip";
import { StatusBadge, type FindingStatus } from "@/components/status-badge";
import { FacetedFilter, type FacetOption } from "@/components/faceted-filter";
import { MuteFindingDialog, MUTE_REASONS } from "@/components/mute-finding-dialog";
import { OverlayRail, MUTE_REASON_LABELS, type MuteReason } from "@/components/overlay-rail";
import { useStatus } from "@/components/status-region";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import { Textarea } from "@/components/ui/textarea";
import { apiClient, errorMessage } from "@/api/client";
import type { Finding } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useFindings, useMuteByCheck, useOrganizations, useProjects } from "@/hooks/queries";
import { DEFAULT_STATUS_FILTER, decodeMutedParam, decodeStatusParam } from "@/lib/findings-status";
import { STATUS_COLOR_VAR, STATUS_LABEL, STATUS_ORDER } from "@/lib/findings-aggregates";

/** Builds the query string the backend's `_finding_filters` dependency
 *  expects — one function so the export request can never drift from the
 *  facet state actually driving the on-screen table (`services/findings.py`
 *  runs both list and export through the identical filter builder). */
function buildFilterParams({
  projectId,
  severityFilter,
  statusFilter,
  serviceFilter,
  subserviceFilter,
  regionFilter,
  resourceTypeFilter,
  mutedFilter,
  muteReasonFilter,
  checkFilter,
  search,
}: {
  projectId: string;
  severityFilter: Set<string>;
  statusFilter: Set<string>;
  serviceFilter: Set<string>;
  subserviceFilter: Set<string>;
  regionFilter: Set<string>;
  resourceTypeFilter: Set<string>;
  mutedFilter: Set<string>;
  muteReasonFilter: Set<string>;
  checkFilter: Set<string>;
  search: string;
}): URLSearchParams {
  const params = new URLSearchParams();
  if (projectId) params.set("project_id", projectId);
  severityFilter.forEach((v) => params.append("severity", v));
  statusFilter.forEach((v) => params.append("status", v));
  serviceFilter.forEach((v) => params.append("service_name", v));
  subserviceFilter.forEach((v) => params.append("subservice_name", v));
  regionFilter.forEach((v) => params.append("region", v));
  resourceTypeFilter.forEach((v) => params.append("resource_type", v));
  mutedFilter.forEach((v) => params.append("muted", v));
  muteReasonFilter.forEach((v) => params.append("mute_reason", v));
  checkFilter.forEach((v) => params.append("check_id", v));
  if (search.trim()) params.set("search", search.trim());
  return params;
}

/** Row count for the export success toast — a plain `split("\n").length`
 *  would overcount whenever a field (e.g. `status_extended`) legitimately
 *  contains an embedded newline inside a quoted CSV value, so this walks
 *  the text respecting quotes instead. */
function countCsvDataRows(csvText: string): number {
  let rows = 0;
  let inQuotes = false;
  const trimmed = csvText.replace(/\r\n/g, "\n").replace(/\n$/, "");
  for (let i = 0; i < trimmed.length; i++) {
    const char = trimmed[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === "\n" && !inQuotes) {
      rows++;
    }
  }
  // Each newline outside quotes is one line break between rows; with the
  // header as the first line, the number of breaks equals the data row count.
  return trimmed.length === 0 ? 0 : rows;
}

function MuteByCheckDialog({
  projectId,
  checkId,
  checkTitle,
  count,
  onOpenChange,
}: {
  projectId: number;
  checkId: string;
  checkTitle: string;
  count: number;
  onOpenChange: (open: boolean) => void;
}) {
  const muteByCheck = useMuteByCheck();
  const status = useStatus();

  const [reason, setReason] = useState("");
  const [note, setNote] = useState("");

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!reason) return;
    try {
      const result = await muteByCheck.mutateAsync({
        project_id: projectId,
        check_id: checkId,
        mute_reason: reason,
        note: note.trim() || null,
      });
      const mutedCount = result.data.muted_count;
      status.succeed(`Muted ${mutedCount} finding${mutedCount === 1 ? "" : "s"} for ${checkId}.`);
      onOpenChange(false);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't mute that category."));
    }
  };

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Mute entire category</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <p className="text-sm font-medium text-ink">{checkTitle}</p>
            <p className="font-mono text-xs text-ink-muted">{checkId}</p>
            <p className="text-sm text-ink-secondary">
              Mutes every currently unmuted finding for this check in this project —{" "}
              <span className="font-medium text-ink">{count}</span> right now. Findings already
              muted individually are left untouched. Each one stays separately unmutable
              afterwards, e.g. to re-flag CMEK on one specific table later.
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="mute-check-reason">Reason</Label>
            <Combobox
              id="mute-check-reason"
              value={reason}
              onValueChange={setReason}
              options={MUTE_REASONS.map((value) => ({
                value,
                label: MUTE_REASON_LABELS[value],
              }))}
              placeholder="Select a reason"
              className="w-full"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="mute-check-note">Note</Label>
            <Textarea
              id="mute-check-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Context for the next person who looks at this — a ticket reference, why it's safe…"
            />
          </div>
          <DialogFooter>
            <Button type="submit" disabled={muteByCheck.isPending || !reason}>
              {muteByCheck.isPending && <LoaderCircle className="size-3.5 animate-spin" aria-hidden />}
              Mute {count} finding{count === 1 ? "" : "s"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function Findings() {
  const { permissions } = useAuth();
  const projects = useProjects();
  const organizations = useOrganizations();
  const [searchParams] = useSearchParams();

  const [organizationId, setOrganizationId] = useState<string>("");
  // Lets "View findings" from a scan's detail page land pre-filtered — read
  // once on mount, the Selects below own it from then on.
  const [projectId, setProjectId] = useState<string>(searchParams.get("project") ?? "");
  const [mutingFinding, setMutingFinding] = useState<Finding | null>(null);
  const [mutingCheck, setMutingCheck] = useState<{ checkId: string; checkTitle: string; count: number } | null>(
    null,
  );
  const [exporting, setExporting] = useState(false);
  const status = useStatus();

  const [severityFilter, setSeverityFilter] = useState<Set<string>>(
    () => new Set(searchParams.get("severity") ? [searchParams.get("severity")!] : []),
  );
  // Defaults to Failed-only (see lib/findings-status.ts) — this is a
  // triage tool, and passing findings are noise against that job the
  // moment there's more than a handful of them. `decodeStatusParam` is
  // also what the Findings Overview page's drill-down links are encoded
  // against, via `encodeStatusParam` — the two are exact inverses, kept
  // in one shared module after the two sides briefly disagreeing about
  // what "no status param" meant produced a real bug.
  const [statusFilter, setStatusFilter] = useState<Set<string>>(() =>
    decodeStatusParam(searchParams.get("status")),
  );
  const [serviceFilter, setServiceFilter] = useState<Set<string>>(
    () => new Set(searchParams.get("service") ? [searchParams.get("service")!] : []),
  );
  const [regionFilter, setRegionFilter] = useState<Set<string>>(new Set());
  // Read from the URL like severity/service/check, not defaulted empty. The
  // Findings Overview drills through with `muted=false` when it is hiding muted
  // findings; before this was wired up that param was silently dropped, so a
  // count clicked on the overview landed on a table showing a different number.
  const [mutedFilter, setMutedFilter] = useState<Set<string>>(
    () => decodeMutedParam(searchParams.get("muted")),
  );
  const [subserviceFilter, setSubserviceFilter] = useState<Set<string>>(new Set());
  const [resourceTypeFilter, setResourceTypeFilter] = useState<Set<string>>(new Set());
  const [muteReasonFilter, setMuteReasonFilter] = useState<Set<string>>(new Set());
  // Arrives pre-selected from the Findings Overview page's rollup table
  // ("View" on one check) or the Compliance Report's drill-through (one or
  // more `?check=` params — a requirement can map to several checks) —
  // folded into the same faceted-filter shape as every other dimension
  // rather than kept as a separate exact-match state, so it composes with
  // the others instead of overriding them.
  const [checkFilter, setCheckFilter] = useState<Set<string>>(
    () => new Set(searchParams.getAll("check")),
  );
  // Lifted out of DataTable (rather than left as its internal state) so the
  // export request can be built from exactly the text the user is looking
  // at — see buildFilterParams.
  const [search, setSearch] = useState("");
  const anyFacetActive =
    severityFilter.size > 0 ||
    statusFilter.size > 0 ||
    serviceFilter.size > 0 ||
    subserviceFilter.size > 0 ||
    regionFilter.size > 0 ||
    resourceTypeFilter.size > 0 ||
    mutedFilter.size > 0 ||
    muteReasonFilter.size > 0 ||
    checkFilter.size > 0;
  // A true clear — every facet including Status goes to fully unfiltered.
  // Used by the toolbar's "Reset" and the empty-state's "Clear filters",
  // both of which exist specifically to escape a filtered dead-end (most
  // pointedly: a project with zero *failing* findings would otherwise
  // land on "no findings match" with a Clear-filters button that just
  // re-applied the same Failed-only default and produced the same empty
  // result again).
  const clearAllFacets = () => {
    setSeverityFilter(new Set());
    setStatusFilter(new Set());
    setServiceFilter(new Set());
    setSubserviceFilter(new Set());
    setRegionFilter(new Set());
    setResourceTypeFilter(new Set());
    setMutedFilter(new Set());
    setMuteReasonFilter(new Set());
    setCheckFilter(new Set());
  };
  // A project switch invalidates whatever the facets were counting over —
  // stale selections would otherwise silently hide every row. Distinct
  // from clearAllFacets: this is "start fresh on the new project," which
  // means landing on the same Failed-only default a first visit gets, not
  // on "show every status."
  const selectProject = (value: string) => {
    setProjectId(value);
    setSeverityFilter(new Set());
    setStatusFilter(new Set(DEFAULT_STATUS_FILTER));
    setServiceFilter(new Set());
    setSubserviceFilter(new Set());
    setRegionFilter(new Set());
    setResourceTypeFilter(new Set());
    setMutedFilter(new Set());
    setMuteReasonFilter(new Set());
    setCheckFilter(new Set());
    setSearch("");
  };

  // Findings only ever fetch once a specific project is chosen — loading
  // and rendering every finding across every visible project by default
  // was the actual weight behind the page feeling like it hung on
  // selection; scoping the fetch to one project (rarely more than a few
  // hundred rows) keeps every render small regardless of how many projects
  // the account can see.
  const findings = useFindings(projectId ? Number(projectId) : undefined);

  // "View findings" from a scan detail page only knows the project, not
  // its organization — fill the org select in once projects have loaded,
  // so the project select isn't left disabled under a value it can't show
  // as editable.
  useEffect(() => {
    if (projectId && !organizationId && projects.data) {
      const project = projects.data.find((p) => String(p.id) === projectId);
      if (project) setOrganizationId(String(project.gcp_organization_id));
    }
  }, [projectId, organizationId, projects.data]);

  const departmentIdForProject = useMemo(() => {
    const orgToDepartment = new Map((organizations.data ?? []).map((o) => [o.id, o.department_id]));
    return new Map(
      (projects.data ?? []).map((p) => [p.id, orgToDepartment.get(p.gcp_organization_id)]),
    );
  }, [projects.data, organizations.data]);

  const projectsInOrganization = useMemo(
    () =>
      (projects.data ?? []).filter(
        (p) => !organizationId || String(p.gcp_organization_id) === organizationId,
      ),
    [projects.data, organizationId],
  );

  const selectedProject = (projects.data ?? []).find((p) => String(p.id) === projectId);

  const totalCount = findings.data?.length ?? 0;

  // Facet option lists carry a count over the full project — filtering the
  // rows below never changes what the other facets offer to pick from.
  const severityOptions: FacetOption[] = useMemo(() => {
    const counts: Partial<Record<Severity, number>> = {};
    for (const finding of findings.data ?? []) {
      const severity = finding.severity as Severity;
      counts[severity] = (counts[severity] ?? 0) + 1;
    }
    return SEVERITY_ORDER.filter((severity) => counts[severity]).map((severity) => ({
      value: severity,
      label: severity[0].toUpperCase() + severity.slice(1),
      count: counts[severity],
      icon: (
        <span
          aria-hidden
          className="size-2 shrink-0 rounded-full"
          style={{ backgroundColor: `var(--color-sev-${severity})` }}
        />
      ),
    }));
  }, [findings.data]);

  const statusOptions: FacetOption[] = useMemo(() => {
    const counts: Partial<Record<FindingStatus, number>> = {};
    for (const finding of findings.data ?? []) {
      const status = finding.status as FindingStatus;
      counts[status] = (counts[status] ?? 0) + 1;
    }
    return STATUS_ORDER.filter((status) => counts[status]).map((status) => ({
      value: status,
      label: STATUS_LABEL[status],
      count: counts[status],
      icon: (
        <span
          aria-hidden
          className="size-2 shrink-0 rounded-full"
          style={{ backgroundColor: STATUS_COLOR_VAR[status] }}
        />
      ),
    }));
  }, [findings.data]);

  const serviceOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of findings.data ?? []) {
      counts.set(finding.service_name, (counts.get(finding.service_name) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [findings.data]);

  const regionOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of findings.data ?? []) {
      counts.set(finding.region, (counts.get(finding.region) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [findings.data]);

  const subserviceOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of findings.data ?? []) {
      if (!finding.subservice_name) continue;
      counts.set(finding.subservice_name, (counts.get(finding.subservice_name) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [findings.data]);

  const resourceTypeOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of findings.data ?? []) {
      counts.set(finding.resource_type, (counts.get(finding.resource_type) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [findings.data]);

  const checkOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, { label: string; count: number }>();
    for (const finding of findings.data ?? []) {
      const existing = counts.get(finding.check_id);
      counts.set(finding.check_id, {
        label: finding.check_title,
        count: (existing?.count ?? 0) + 1,
      });
    }
    return [...counts.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .map(([value, { label, count }]) => ({ value, label, count }));
  }, [findings.data]);

  const mutedOptions: FacetOption[] = useMemo(() => {
    const muted = (findings.data ?? []).filter((f) => f.muted).length;
    const notMuted = (findings.data ?? []).length - muted;
    return [
      { value: "true", label: "Muted", count: muted },
      { value: "false", label: "Not muted", count: notMuted },
    ].filter((option) => option.count > 0);
  }, [findings.data]);

  const muteReasonOptions: FacetOption[] = useMemo(() => {
    const counts: Partial<Record<MuteReason, number>> = {};
    for (const finding of findings.data ?? []) {
      if (!finding.muted || !finding.mute_reason) continue;
      const reason = finding.mute_reason as MuteReason;
      counts[reason] = (counts[reason] ?? 0) + 1;
    }
    return MUTE_REASONS.filter((reason) => counts[reason]).map((reason) => ({
      value: reason,
      label: MUTE_REASON_LABELS[reason],
      count: counts[reason],
    }));
  }, [findings.data]);

  // Powers the "Mute all N" bulk action on the Check column — a count over
  // the whole project's currently-unmuted findings, not the filtered view,
  // since muting a category is a project-wide decision regardless of what
  // facets happen to be narrowing the table right now.
  const unmutedCountByCheck = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of findings.data ?? []) {
      if (finding.muted) continue;
      counts.set(finding.check_id, (counts.get(finding.check_id) ?? 0) + 1);
    }
    return counts;
  }, [findings.data]);

  const filteredFindings = useMemo(() => {
    return (findings.data ?? []).filter((finding) => {
      if (severityFilter.size > 0 && !severityFilter.has(finding.severity)) return false;
      if (statusFilter.size > 0 && !statusFilter.has(finding.status)) return false;
      if (serviceFilter.size > 0 && !serviceFilter.has(finding.service_name)) return false;
      if (subserviceFilter.size > 0 && !subserviceFilter.has(finding.subservice_name ?? "")) return false;
      if (regionFilter.size > 0 && !regionFilter.has(finding.region)) return false;
      if (resourceTypeFilter.size > 0 && !resourceTypeFilter.has(finding.resource_type)) return false;
      if (mutedFilter.size > 0 && !mutedFilter.has(String(finding.muted))) return false;
      if (muteReasonFilter.size > 0 && !muteReasonFilter.has(finding.mute_reason ?? "")) return false;
      if (checkFilter.size > 0 && !checkFilter.has(finding.check_id)) return false;
      return true;
    });
  }, [
    findings.data,
    severityFilter,
    statusFilter,
    serviceFilter,
    subserviceFilter,
    regionFilter,
    resourceTypeFilter,
    mutedFilter,
    muteReasonFilter,
    checkFilter,
  ]);

  // Hits the backend export endpoint with exactly the filters currently
  // narrowing the table — server-side, sharing `services/findings.py`'s
  // one query builder with the list endpoint, so the file can never drift
  // from what's on screen. Deliberately not a TanStack Query mutation:
  // this triggers a browser download as a side effect, not a cache update.
  const handleExport = async () => {
    if (!projectId) return;
    setExporting(true);
    try {
      const params = buildFilterParams({
        projectId,
        severityFilter,
        statusFilter,
        serviceFilter,
        subserviceFilter,
        regionFilter,
        resourceTypeFilter,
        mutedFilter,
        muteReasonFilter,
        checkFilter,
        search,
      });
      const response = await apiClient.get(`/findings/export?${params.toString()}`, {
        responseType: "blob",
      });
      const blob = response.data as Blob;
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `findings-${selectedProject?.project_id ?? projectId}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      // Counted from the file itself, not `filteredFindings.length` — that
      // memo doesn't apply the free-text search box (DataTable applies that
      // client-side, on top of it), so it would overstate the count against
      // what was actually written whenever a search term is active.
      const rowCount = countCsvDataRows(await blob.text());
      status.succeed(`Exported ${rowCount} finding${rowCount === 1 ? "" : "s"}.`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't export findings."));
    } finally {
      setExporting(false);
    }
  };

  const columns: ColumnDef<Finding, any>[] = [
    {
      accessorKey: "severity",
      header: "Severity",
      enableGlobalFilter: false,
      sortingFn: (a, b) =>
        SEVERITY_RANK[b.original.severity as Severity] - SEVERITY_RANK[a.original.severity as Severity],
      cell: ({ row }) => <SeverityChip severity={row.original.severity as Severity} />,
    },
    {
      accessorKey: "status",
      header: "Status",
      enableGlobalFilter: false,
      cell: ({ row }) => <StatusBadge status={row.original.status as FindingStatus} />,
    },
    {
      accessorKey: "check_title",
      header: "Check",
      cell: ({ row }) => {
        const finding = row.original;
        const departmentId = departmentIdForProject.get(finding.project_id);
        const unmutedCount = unmutedCountByCheck.get(finding.check_id) ?? 0;
        // Only worth offering once there's more than one unmuted finding to
        // fold together — for a lone finding this is exactly the per-row
        // Mute button already in the actions column.
        const canBulkMute = unmutedCount > 1 && permissions.canEdit(departmentId);
        return (
          <div className="max-w-md space-y-1.5">
            <div>
              <Link
                to={`/findings/${finding.id}`}
                className="text-sm text-ink underline-offset-2 hover:text-brand hover:underline"
              >
                {finding.check_title}
              </Link>
              <p className="font-mono text-[11px] text-ink-muted">{finding.check_id}</p>
            </div>
            {finding.muted && finding.mute_reason && (
              <OverlayRail reason={finding.mute_reason as MuteReason} note={finding.note} />
            )}
            {canBulkMute && (
              <button
                type="button"
                onClick={() =>
                  setMutingCheck({
                    checkId: finding.check_id,
                    checkTitle: finding.check_title,
                    count: unmutedCount,
                  })
                }
                className="inline-flex items-center gap-1 text-xs text-brand transition-colors hover:text-brand-hover"
              >
                <Layers className="size-3" aria-hidden />
                Mute all {unmutedCount} for this check
              </button>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "service_name",
      header: "Service",
      enableGlobalFilter: false,
      cell: ({ row }) => (
        <MutedCell>
          {row.original.service_name}
          {row.original.subservice_name ? ` / ${row.original.subservice_name}` : ""}
        </MutedCell>
      ),
    },
    {
      accessorKey: "region",
      header: "Region",
      enableGlobalFilter: false,
      cell: ({ row }) => <MutedCell>{row.original.region}</MutedCell>,
    },
    {
      accessorKey: "resource_name",
      header: "Resource",
      cell: ({ row }) => (
        <div className="max-w-xs space-y-0.5">
          <p className="truncate text-sm text-ink" title={row.original.resource_name}>
            {row.original.resource_name}
          </p>
          <p className="truncate font-mono text-[11px] text-ink-muted" title={row.original.resource_type}>
            {row.original.resource_type}
          </p>
          <CopyableUid value={row.original.resource_uid} max={36} />
        </div>
      ),
    },
    {
      id: "actions",
      header: "",
      enableSorting: false,
      cell: ({ row }) => {
        const finding = row.original;
        const departmentId = departmentIdForProject.get(finding.project_id);
        if (!permissions.canEdit(departmentId)) return null;
        return (
          <div className="flex justify-end">
            <Button variant="ghost" size="sm" onClick={() => setMutingFinding(finding)}>
              {finding.muted ? (
                <>
                  <BellOff className="size-3.5" aria-hidden />
                  Edit mute
                </>
              ) : (
                "Mute"
              )}
            </Button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="findings"
        description="Every check the scanner ran, per resource. Choose an organization and project to see its findings."
        actions={
          projectId && (
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={handleExport} disabled={exporting || totalCount === 0}>
                {exporting ? (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Download className="size-3.5" aria-hidden />
                )}
                Export
              </Button>
              <Button variant="outline" size="sm" asChild>
                <Link to={`/findings-overview?project=${projectId}`}>
                  <Compass className="size-3.5" aria-hidden />
                  Overview
                </Link>
              </Button>
            </div>
          )
        }
      />

      <Panel>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="space-y-1.5">
            <Label htmlFor="findings-organization">Organization</Label>
            <Combobox
              id="findings-organization"
              value={organizationId}
              onValueChange={(value) => {
                setOrganizationId(value);
                selectProject("");
              }}
              options={(organizations.data ?? []).map((organization) => ({
                value: String(organization.id),
                label: organization.name,
              }))}
              placeholder="Select an organization"
              searchPlaceholder="Search organizations…"
              emptyMessage="No organizations match."
              className="w-full"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="findings-project">Project</Label>
            <Combobox
              id="findings-project"
              value={projectId}
              onValueChange={selectProject}
              disabled={!organizationId}
              options={projectsInOrganization.map((project) => ({
                value: String(project.id),
                label: project.project_id,
              }))}
              placeholder={organizationId ? "Select a project" : "Choose an organization first"}
              searchPlaceholder="Search projects…"
              emptyMessage="No projects match."
              className="w-full"
            />
            {organizationId && projectsInOrganization.length === 0 && (
              <p className="text-xs text-ink-muted">No projects registered under this organization yet.</p>
            )}
          </div>
        </div>
      </Panel>

      {!projectId ? (
        <Panel padded={false}>
          <EmptyState
            icon={ShieldQuestion}
            title="Choose a project to see its findings"
            description="Pick an organization and project above — findings load scoped to that one project."
          />
        </Panel>
      ) : (
        <>
          <DataTable
            columns={columns}
            data={filteredFindings}
            isLoading={findings.isLoading}
            error={findings.error}
            errorMessage={errorMessage(findings.error, "Couldn't load findings.")}
            onRetry={() => findings.refetch()}
            searchPlaceholder="Search by resource name or check title…"
            globalFilter={search}
            onGlobalFilterChange={setSearch}
            pageSize={50}
            toolbar={
              totalCount > 0 && (
                <div className="flex flex-wrap items-center gap-2">
                  <FacetedFilter
                    title="Severity"
                    options={severityOptions}
                    selected={severityFilter}
                    onChange={setSeverityFilter}
                  />
                  <FacetedFilter
                    title="Status"
                    options={statusOptions}
                    selected={statusFilter}
                    onChange={setStatusFilter}
                  />
                  <FacetedFilter
                    title="Service"
                    options={serviceOptions}
                    selected={serviceFilter}
                    onChange={setServiceFilter}
                  />
                  {subserviceOptions.length > 0 && (
                    <FacetedFilter
                      title="Subservice"
                      options={subserviceOptions}
                      selected={subserviceFilter}
                      onChange={setSubserviceFilter}
                    />
                  )}
                  <FacetedFilter
                    title="Region"
                    options={regionOptions}
                    selected={regionFilter}
                    onChange={setRegionFilter}
                  />
                  <FacetedFilter
                    title="Resource type"
                    options={resourceTypeOptions}
                    selected={resourceTypeFilter}
                    onChange={setResourceTypeFilter}
                  />
                  <FacetedFilter
                    title="Check"
                    options={checkOptions}
                    selected={checkFilter}
                    onChange={setCheckFilter}
                  />
                  <FacetedFilter
                    title="Muted"
                    options={mutedOptions}
                    selected={mutedFilter}
                    onChange={setMutedFilter}
                  />
                  {muteReasonOptions.length > 0 && (
                    <FacetedFilter
                      title="Mute reason"
                      options={muteReasonOptions}
                      selected={muteReasonFilter}
                      onChange={setMuteReasonFilter}
                    />
                  )}
                  {anyFacetActive && (
                    <Button variant="ghost" size="sm" onClick={clearAllFacets}>
                      Reset
                    </Button>
                  )}
                </div>
              )
            }
            empty={
              anyFacetActive ? (
                <EmptyState
                  icon={ShieldQuestion}
                  title="No findings match these filters"
                  description="Nothing in this project matches the selected severity, status, service or region."
                  action={
                    <Button variant="outline" size="sm" onClick={clearAllFacets}>
                      Clear filters
                    </Button>
                  }
                />
              ) : (
                <EmptyState
                  icon={ShieldAlert}
                  title="No findings yet"
                  description={`${selectedProject?.project_id ?? "This project"} hasn't completed a scan yet, or its scan hasn't produced findings.`}
                />
              )
            }
          />
        </>
      )}

      {mutingFinding && (
        <MuteFindingDialog
          finding={mutingFinding}
          onOpenChange={(open) => !open && setMutingFinding(null)}
        />
      )}

      {mutingCheck && projectId && (
        <MuteByCheckDialog
          projectId={Number(projectId)}
          checkId={mutingCheck.checkId}
          checkTitle={mutingCheck.checkTitle}
          count={mutingCheck.count}
          onOpenChange={(open) => !open && setMutingCheck(null)}
        />
      )}
    </div>
  );
}
