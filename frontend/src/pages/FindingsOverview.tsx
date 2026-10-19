import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { ArrowRight, ShieldAlert, ShieldQuestion } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable, MutedCell } from "@/components/data-table";
import { EmptyState } from "@/components/states";
import { StatTile } from "@/components/stat-tile";
import { SeverityChip, type Severity } from "@/components/severity-chip";
import { DonutChart } from "@/components/donut-chart";
import { TreemapChart, dominantSeverityOf, type TreemapBlock } from "@/components/treemap-chart";
import { FindingsHeatmap } from "@/components/findings-heatmap";
import {
  buildSeveritySlices,
  buildStatusSlices,
  computeFindingStats,
  groupByCheck,
  groupByServiceSeverity,
  type CheckGroup,
} from "@/lib/findings-aggregates";
import { errorMessage } from "@/api/client";
import { useFindings, useOrganizations, useProjects } from "@/hooks/queries";
import { NON_PASS_STATUSES, encodeMutedParam, encodeStatusParam } from "@/lib/findings-status";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import { Switch } from "@/components/ui/switch";

export default function FindingsOverview() {
  const projects = useProjects();
  const organizations = useOrganizations();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [organizationId, setOrganizationId] = useState<string>("");
  const [projectId, setProjectId] = useState<string>(searchParams.get("project") ?? "");

  const selectProject = (value: string) => setProjectId(value);

  // Same discipline as the Findings table page: never fetch unscoped.
  // Aggregation itself is cheap even at thousands of rows, but an
  // unscoped fetch across every visible project is exactly what made the
  // table page feel like it hung — this reuses that fix rather than
  // reopening it.
  const findings = useFindings(projectId ? Number(projectId) : undefined);

  useEffect(() => {
    if (projectId && !organizationId && projects.data) {
      const project = projects.data.find((p) => String(p.id) === projectId);
      if (project) setOrganizationId(String(project.gcp_organization_id));
    }
  }, [projectId, organizationId, projects.data]);

  const projectsInOrganization = useMemo(
    () =>
      (projects.data ?? []).filter(
        (p) => !organizationId || String(p.gcp_organization_id) === organizationId,
      ),
    [projects.data, organizationId],
  );

  const selectedProject = (projects.data ?? []).find((p) => String(p.id) === projectId);

  const rows = findings.data ?? [];

  // Two exclusions, one scope. Both default to hidden, and both govern *every*
  // number on this page — tiles, donuts, rollup, treemap and heatmap alike.
  //
  // Tiles and donuts used to summarize the whole project regardless of the
  // passing toggle, on the reasoning that a summary should summarize. In
  // practice can make headline counts disagree with everything beneath them.
  // One scope, applied once, is the only arrangement where the numbers on this
  // page agree with each other.
  const [includePassing, setIncludePassing] = useState(false);
  const [includeMuted, setIncludeMuted] = useState(false);

  const scopedRows = useMemo(
    () =>
      rows.filter(
        (f) => (includePassing || f.status !== "PASS") && (includeMuted || !f.muted),
      ),
    [rows, includePassing, includeMuted],
  );

  // What each toggle would actually reveal, for the tiles that report the
  // exclusions. This has to apply the *other* toggle's filter too — otherwise
  // "muted — excluded: N" counts every muted row regardless of whether
  // includePassing is also off, so flipping "Show muted" alone can reveal
  // fewer than N rows (any that are muted AND passing stay hidden).
  const excluded = useMemo(
    () => ({
      passing: rows.filter((f) => f.status === "PASS" && (includeMuted || !f.muted)).length,
      muted: rows.filter((f) => f.muted && (includePassing || f.status !== "PASS")).length,
    }),
    [rows, includePassing, includeMuted],
  );

  const stats = useMemo(() => computeFindingStats(scopedRows), [scopedRows]);
  const severitySlices = useMemo(() => buildSeveritySlices(scopedRows), [scopedRows]);
  const statusSlices = useMemo(() => buildStatusSlices(scopedRows), [scopedRows]);
  const checkGroups = useMemo(() => groupByCheck(scopedRows), [scopedRows]);
  const serviceSeverityCells = useMemo(() => groupByServiceSeverity(scopedRows), [scopedRows]);

  const treemapBlocks: TreemapBlock[] = useMemo(() => {
    const byService = new Map<string, { count: number; severities: Severity[] }>();
    for (const cell of serviceSeverityCells) {
      const entry = byService.get(cell.service) ?? { count: 0, severities: [] };
      entry.count += cell.count;
      entry.severities.push(cell.severity);
      byService.set(cell.service, entry);
    }
    return [...byService.entries()].map(([service, { count, severities }]) => ({
      key: service,
      label: service,
      count,
      dominantSeverity: dominantSeverityOf(severities),
    }));
  }, [serviceSeverityCells]);

  // Mirrors scopedRows' own "everything except PASS" filter exactly via
  // the shared lib/findings-status.ts encoding — not just FAIL. Without
  // this, a check made up of e.g. only MANUAL findings would show a real
  // count here but land on the Table page's default FAIL-only filter and
  // render as empty, the count the user just clicked appearing to vanish.
  const goToTable = (params: Record<string, string>) => {
    const statusScope = includePassing ? new Set<string>() : new Set(NON_PASS_STATUSES);
    const query = new URLSearchParams({
      project: projectId,
      status: encodeStatusParam(statusScope),
      ...params,
    });
    // The muted scope travels too, for the same reason the status scope does:
    // clicking a count of 12 and landing on a table of 400 is the bug this
    // encoding exists to prevent. Only sent when narrowing — the table's own
    // default is already "no muted filter", so an unfiltered link says nothing.
    const mutedParam = encodeMutedParam(includeMuted);
    if (mutedParam !== null) query.set("muted", mutedParam);
    navigate(`/findings?${query.toString()}`);
  };

  const columns: ColumnDef<CheckGroup, any>[] = [
    {
      accessorKey: "worstSeverity",
      header: "Worst severity",
      cell: ({ row }) => <SeverityChip severity={row.original.worstSeverity} />,
    },
    {
      accessorKey: "checkTitle",
      header: "Check",
      cell: ({ row }) => (
        <div className="max-w-md">
          <p className="text-sm text-ink">{row.original.checkTitle}</p>
          <p className="font-mono text-[11px] text-ink-muted">{row.original.checkId}</p>
        </div>
      ),
    },
    {
      accessorKey: "services",
      header: "Services",
      cell: ({ row }) => {
        const services = row.original.services;
        return (
          <MutedCell>
            {services.length <= 2 ? services.join(", ") : `${services.length} services`}
          </MutedCell>
        );
      },
    },
    {
      accessorKey: "failing",
      header: "Failing / total",
      cell: ({ row }) => (
        <span className="tabular-nums text-ink">
          {row.original.failing} <span className="text-ink-muted">/ {row.original.total}</span>
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={() => goToTable({ check: row.original.checkId })}
            className="inline-flex items-center gap-1 text-sm text-brand transition-colors hover:text-brand-hover"
          >
            View <ArrowRight className="size-3.5" aria-hidden />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="findings overview"
        description="A navigable view over one project's findings — grouped by check, by service, and by service × severity — instead of scrolling the full list."
      />

      <Panel>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="space-y-1.5">
            <Label htmlFor="overview-organization">Organization</Label>
            <Combobox
              id="overview-organization"
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
            <Label htmlFor="overview-project">Project</Label>
            <Combobox
              id="overview-project"
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
            title="Choose a project to see its findings overview"
            description="Pick an organization and project above — the rollup, treemap and heatmap load scoped to that one project."
          />
        </Panel>
      ) : findings.isLoading ? (
        <Panel padded={false}>
          <EmptyState icon={ShieldQuestion} title="Loading…" />
        </Panel>
      ) : rows.length === 0 ? (
        <Panel padded={false}>
          <EmptyState
            icon={ShieldAlert}
            title="No findings yet"
            description={`${selectedProject?.project_id ?? "This project"} hasn't completed a scan yet, or its scan hasn't produced findings.`}
          />
        </Panel>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* The first two describe what is in scope; the last two describe
                what a toggle is holding back. Without that split, the default
                view (passing and muted both hidden) would show two tiles
                permanently reading 0 — they count exactly what is excluded. The
                labels flip with the toggles, so a tile never claims to be
                something it is not. */}
            <StatTile label={includePassing && includeMuted ? "total findings" : "in scope"} value={stats.total} />
            <StatTile label="failing" value={stats.failing} tone="warning" />
            <StatTile
              label={includePassing ? "passing" : "passing — excluded"}
              value={includePassing ? stats.passing : excluded.passing}
            />
            <StatTile
              label={includeMuted ? "muted" : "muted — excluded"}
              value={includeMuted ? stats.muted : excluded.muted}
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel>
              <p className="card-title mb-4">by severity</p>
              <DonutChart slices={severitySlices} centerValue={stats.total} centerLabel="findings" />
            </Panel>
            <Panel>
              <p className="card-title mb-4">by status</p>
              <DonutChart slices={statusSlices} centerValue={stats.total} centerLabel="findings" />
            </Panel>
          </div>

          <div className="flex items-center justify-between gap-3 rounded-lg border border-hairline bg-panel px-4 py-3">
            <div>
              <p className="text-sm font-medium text-ink">
                Showing {scopedRows.length} of {rows.length} findings
              </p>
              <p className="text-xs text-ink-muted">
                Passing findings and muted findings are hidden by default — a mute records a
                decision not to act. Both switches govern every number on this page, including
                the tiles and donuts above.
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-sm text-ink-secondary">
                Show passing
                <Switch checked={includePassing} onCheckedChange={setIncludePassing} />
              </label>
              <label className="flex items-center gap-2 text-sm text-ink-secondary">
                Show muted
                <Switch checked={includeMuted} onCheckedChange={setIncludeMuted} />
              </label>
            </div>
          </div>

          <Panel>
            <p className="card-title mb-1">by service</p>
            <p className="mb-4 text-xs text-ink-muted">
              Block size is finding count, colour is the worst severity present. Click a block to
              see those findings.
            </p>
            <TreemapChart blocks={treemapBlocks} onSelect={(block) => goToTable({ service: block.key })} />
          </Panel>

          <Panel>
            <p className="card-title mb-1">service × severity</p>
            <p className="mb-4 text-xs text-ink-muted">
              Shading is relative to the busiest cell in this grid. Click a cell to see those
              findings.
            </p>
            <FindingsHeatmap
              cells={serviceSeverityCells}
              onSelect={(service, severity) => goToTable({ service, severity })}
            />
          </Panel>

          <Panel padded={false}>
            <div className="p-4 pb-0 sm:p-5 sm:pb-0">
              <p className="card-title">by check</p>
              <p className="mb-1 text-xs text-ink-muted">
                {checkGroups.length} distinct check{checkGroups.length === 1 ? "" : "s"} across{" "}
                {scopedRows.length} finding{scopedRows.length === 1 ? "" : "s"}, worst-failing
                first.
              </p>
            </div>
            <div className="p-4 sm:p-5">
              <DataTable
                columns={columns}
                data={checkGroups}
                initialSorting={[{ id: "failing", desc: true }]}
                searchPlaceholder="Search checks…"
                pageSize={25}
              />
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
