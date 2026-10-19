import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { ArrowRight, ShieldCheck, ShieldQuestion } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable } from "@/components/data-table";
import { ComplianceStatusBadge } from "@/components/compliance-status-badge";
import { EmptyState } from "@/components/states";
import { MeterBar } from "@/components/meter-bar";
import { StatTile } from "@/components/stat-tile";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import { Switch } from "@/components/ui/switch";
import { errorMessage } from "@/api/client";
import type { ComplianceRequirementResult } from "@/api/types";
import { useComplianceFrameworks, useComplianceReport, useOrganizations, useProjects } from "@/hooks/queries";

/**
 * An Editor (and a Viewer, because this is read-only) picks a project and a
 * framework and gets a requirement-level rollup from the shared rulebook.
 * Every count here is a live query against current findings
 * - nothing precomputed, so a new scan's results show up on the very next
 * load with no refresh step of its own.
 */
export default function ComplianceReport() {
  const organizations = useOrganizations();
  const projects = useProjects();
  const [searchParams] = useSearchParams();

  const [organizationId, setOrganizationId] = useState("");
  const [projectId, setProjectId] = useState(searchParams.get("project") ?? "");
  // Framework identity is (framework, framework_name) together, not
  // `framework` alone is not distinct-version-safe
  // (CIS 2.0/3.0/4.0/5.0 all share framework="CIS"). Held as an index into
  // `frameworks.data` rather than an encoded string: the list's own
  // fallback framework derivation (services/compliance.py, for any file
  // missing a FRAMEWORK column) takes an arbitrary prefix of a
  // REQUIREMENTS_ID with no guarantee it's free of whatever character a
  // string encoding would need as a separator, so indexing sidesteps that
  // entirely instead of picking a separator and hoping.
  const [frameworkIndex, setFrameworkIndex] = useState("");
  const [includeMuted, setIncludeMuted] = useState(false);

  const frameworks = useComplianceFrameworks(projectId ? Number(projectId) : undefined);
  const selectedFramework =
    frameworkIndex && frameworks.data ? frameworks.data[Number(frameworkIndex)] : undefined;
  const report = useComplianceReport(
    projectId ? Number(projectId) : undefined,
    selectedFramework?.framework,
    selectedFramework?.framework_name,
    includeMuted,
  );

  useEffect(() => {
    if (projectId && !organizationId && projects.data) {
      const project = projects.data.find((p) => String(p.id) === projectId);
      if (project) setOrganizationId(String(project.gcp_organization_id));
    }
  }, [projectId, organizationId, projects.data]);

  // The frameworks list is ordered most-used-first by the backend already
  // - pick the first one as soon as it loads for a project, rather than
  // making every visit start on an empty state.
  useEffect(() => {
    if (!frameworkIndex && frameworks.data && frameworks.data.length > 0) {
      setFrameworkIndex("0");
    }
  }, [frameworkIndex, frameworks.data]);

  const projectsInOrganization = useMemo(
    () =>
      (projects.data ?? []).filter(
        (p) => !organizationId || String(p.gcp_organization_id) === organizationId,
      ),
    [projects.data, organizationId],
  );

  const selectProject = (value: string) => {
    setProjectId(value);
    setFrameworkIndex("");
    setIncludeMuted(false);
  };

  const summary = report.data?.summary;

  const columns: ColumnDef<ComplianceRequirementResult, any>[] = [
    {
      accessorKey: "requirement_id",
      header: "Requirement",
      cell: ({ row }) => (
        <div className="max-w-xl space-y-1">
          <p className="font-mono text-xs text-ink">{row.original.requirement_id}</p>
          {row.original.requirement_description && (
            <p className="text-sm text-ink-secondary">{row.original.requirement_description}</p>
          )}
        </div>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => <ComplianceStatusBadge status={row.original.status} />,
    },
    {
      id: "checks",
      header: "Checks",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="font-mono text-xs text-ink-muted">
          {row.original.check_ids.length} check{row.original.check_ids.length === 1 ? "" : "s"}
        </span>
      ),
    },
    {
      id: "drilldown",
      header: "",
      enableSorting: false,
      cell: ({ row }) => {
        if (!projectId) return null;
        const params = new URLSearchParams();
        params.set("project", projectId);
        for (const checkId of row.original.check_ids) params.append("check", checkId);
        return (
          <div className="flex justify-end">
            <Link
              to={`/findings?${params.toString()}`}
              className="inline-flex items-center gap-1 text-xs text-brand transition-colors hover:text-brand-hover"
            >
              View findings
              <ArrowRight className="size-3" aria-hidden />
            </Link>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="compliance report"
        description="Pick a project and framework to see how it scores, computed live against current findings, joined through the loaded rulebook."
      />

      <Panel>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div className="space-y-1.5">
            <Label htmlFor="report-organization">Organization</Label>
            <Combobox
              id="report-organization"
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
            <Label htmlFor="report-project">Project</Label>
            <Combobox
              id="report-project"
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
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="report-framework">Framework</Label>
            <Combobox
              id="report-framework"
              value={frameworkIndex}
              onValueChange={setFrameworkIndex}
              disabled={!projectId}
              options={(frameworks.data ?? []).map((option, index) => ({
                value: String(index),
                label: option.framework_name,
              }))}
              placeholder={projectId ? "Select a framework" : "Choose a project first"}
              searchPlaceholder="Search frameworks…"
              emptyMessage="No frameworks match."
              className="w-full"
            />
            {projectId && frameworks.data && frameworks.data.length === 0 && (
              <p className="text-xs text-ink-muted">No rulebook loaded yet. An admin can load one under Compliance.</p>
            )}
          </div>
        </div>
      </Panel>

      {!projectId || !selectedFramework ? (
        <Panel padded={false}>
          <EmptyState
            icon={ShieldQuestion}
            title="Choose a project and framework"
            description="Pick an organization, project and framework above to see the compliance report."
          />
        </Panel>
      ) : report.isLoading ? (
        <Panel padded={false}>
          <EmptyState icon={ShieldQuestion} title="Loading..." description="Computing the report." />
        </Panel>
      ) : report.error ? (
        <Panel>
          <p className="text-sm text-status-fail">{errorMessage(report.error, "Couldn't load the report.")}</p>
        </Panel>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <Panel className="space-y-2 sm:col-span-2 lg:col-span-1">
              <p className="text-sm font-medium text-ink-secondary">score</p>
              <p className="display-number">
                {summary?.score_percent === null || summary?.score_percent === undefined
                  ? "—"
                  : `${summary.score_percent}%`}
              </p>
              {summary && (
                <MeterBar
                  value={summary.score_percent ?? 0}
                  max={100}
                  color="var(--color-status-pass)"
                  label="compliance score"
                />
              )}
            </Panel>
            <StatTile label="passed" value={summary?.passed ?? 0} />
            <StatTile label="failed" value={summary?.failed ?? 0} tone="warning" />
            <StatTile label="needs review" value={summary?.needs_review ?? 0} />
            <StatTile label="not assessed" value={summary?.not_assessed ?? 0} />
          </div>

          <div className="flex items-center justify-between gap-3 rounded-lg border border-hairline bg-panel px-4 py-3">
            <div>
              <p className="text-sm font-medium text-ink">Muted findings are excluded from the score</p>
              <p className="text-xs text-ink-muted">
                A mute is a triage decision, not evidence of compliance. Include them to see what the
                score would be without any suppression.
              </p>
            </div>
            <label className="flex shrink-0 items-center gap-2 text-sm text-ink-secondary">
              Include muted
              <Switch checked={includeMuted} onCheckedChange={setIncludeMuted} />
            </label>
          </div>

          <DataTable
            columns={columns}
            data={report.data?.requirements}
            searchPlaceholder="Search requirements..."
            pageSize={50}
            empty={
              <EmptyState
                icon={ShieldCheck}
                title="No requirements in this framework"
                description="The loaded rulebook has no requirements for this framework."
              />
            }
          />
        </>
      )}
    </div>
  );
}
