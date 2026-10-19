import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Download, FileText, LoaderCircle, Sparkles } from "lucide-react";
import type { ColumnDef } from "@tanstack/react-table";
import { PageHeader, Panel } from "@/components/app-shell";
import { Combobox } from "@/components/combobox";
import { DataTable } from "@/components/data-table";
import { ReportState, type ReportStatus } from "@/components/report-state";
import { EmptyState } from "@/components/states";
import { useStatus } from "@/components/status-region";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { apiClient, errorMessage } from "@/api/client";
import type { Report, ReportMode } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrganizations, useProjects, useReports, useSubmitReport } from "@/hooks/queries";
import { formatTimestamp } from "@/lib/format";
import { cn, PILL_CLASS } from "@/lib/utils";

/** How the two pipelines are described to someone choosing between them.
 *
 *  The wording is careful about one thing: both modes cover the *same*
 *  findings. The backend's ledger guarantees identical check sections and
 *  identical counts, so the choice is about depth of analysis and how long it
 *  takes, never about coverage. Saying "more thorough" without that would
 *  imply the standard report leaves something out. */
const MODES: { value: ReportMode; label: string; hint: string; blurb: string }[] = [
  {
    value: "standard",
    label: "Standard",
    // `hint` is rendered small and monospaced by Combobox, so it holds the
    // one-glance fact. The sentence goes under the control instead.
    hint: "~2 min",
    blurb: "One writing pass per pillar.",
  },
  {
    value: "deep",
    label: "Deep analysis",
    hint: "~10 min",
    blurb:
      "An agent investigates the findings first, then correlates them into themes and a sequenced remediation plan. Same findings and the same counts — more analysis.",
  },
];

/**
 * Trigger page for the AI assessment report. Deliberately a selector and a
 * button rather than a chat interface — the request has a handful of inputs and
 * no conversation to have about them.
 *
 * One project per report is a hard product constraint, not a UI simplification,
 * so the project control is single-select with no "all projects" option.
 */
export default function Reports() {
  const { permissions } = useAuth();
  const organizations = useOrganizations();
  const projects = useProjects();
  const reports = useReports();
  const submitReport = useSubmitReport();
  const status = useStatus();

  const [organizationId, setOrganizationId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [downloadingId, setDownloadingId] = useState<number | null>(null);
  // Defaults to excluded: a mute is a decision not to remediate, so it is out of
  // scope for a remediation report. This prevents non-actionable findings from
  // dominating the document by default.
  const [includeMuted, setIncludeMuted] = useState(false);
  // Standard is the default and stays the default. Deep costs more model calls
  // and more time, so it is opted into rather than out of.
  const [mode, setMode] = useState<ReportMode>("standard");
  const [instructions, setInstructions] = useState("");

  const projectsInOrganization = useMemo(
    () =>
      (projects.data ?? []).filter(
        (p) => !organizationId || String(p.gcp_organization_id) === organizationId,
      ),
    [projects.data, organizationId],
  );

  const departmentIdForProject = useMemo(() => {
    const orgToDepartment = new Map((organizations.data ?? []).map((o) => [o.id, o.department_id]));
    return new Map(
      (projects.data ?? []).map((p) => [p.id, orgToDepartment.get(p.gcp_organization_id)]),
    );
  }, [projects.data, organizations.data]);

  const projectNameFor = (id: number) =>
    (projects.data ?? []).find((p) => p.id === id)?.project_id ?? `Project #${id}`;

  // Generating a customer-facing document is the same weight as triggering a
  // scan, so it takes Editor. A Viewer never sees the control at all.
  const canSubmit =
    projectId !== "" && permissions.canEdit(departmentIdForProject.get(Number(projectId)));
  const canSubmitAny =
    permissions.isGlobalAdmin ||
    (projects.data ?? []).some((p) => permissions.canEdit(departmentIdForProject.get(p.id)));

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!projectId) return;
    try {
      const response = await submitReport.mutateAsync({
        project_id: Number(projectId),
        include_muted: includeMuted,
        mode,
        // Only meaningful in deep mode — the standard pipeline has no stage
        // that would read it, so sending it there would be a stored value
        // nothing acts on.
        instructions: mode === "deep" ? instructions.trim() || null : null,
      });
      status.succeed(
        `Report queued — reference ${response.data.task_reference_id}. It'll appear below when it's ready.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't queue that report."));
    }
  };

  // Not a TanStack mutation: this triggers a browser download as a side
  // effect, not a cache update — same reasoning as the findings CSV export.
  const handleDownload = async (report: Report) => {
    setDownloadingId(report.id);
    try {
      const response = await apiClient.get(`/reports/${report.id}/download`, {
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(response.data as Blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${report.task_reference_id}.md`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      status.succeed(`Downloaded ${report.task_reference_id}.md`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't download that report."));
    } finally {
      setDownloadingId(null);
    }
  };

  const columns: ColumnDef<Report, any>[] = [
    {
      accessorKey: "task_reference_id",
      header: "Reference",
      cell: ({ row }) => (
        <span className="font-mono text-xs text-ink">{row.original.task_reference_id}</span>
      ),
    },
    {
      accessorKey: "project_id",
      header: "Project",
      cell: ({ row }) => (
        <span className="font-mono text-xs">{projectNameFor(row.original.project_id)}</span>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => <ReportState status={row.original.status as ReportStatus} />,
    },
    {
      accessorKey: "mode",
      header: "Mode",
      cell: ({ row }) =>
        // Provenance, not state — so it borrows the pill geometry but stays in
        // the neutral palette. Brand blue is reserved for navigation and
        // action, and the severity/status colours mean something else.
        row.original.mode === "deep" ? (
          <span className={cn(PILL_CLASS, "bg-subtle text-ink-secondary ring-1 ring-hairline")}>
            Deep
          </span>
        ) : (
          <span className="text-sm text-ink-muted">Standard</span>
        ),
    },
    {
      accessorKey: "created_at",
      header: "Requested",
      cell: ({ row }) => (
        <span className="text-sm text-ink-secondary">
          {formatTimestamp(row.original.created_at)}
        </span>
      ),
    },
    {
      id: "detail",
      header: "",
      enableSorting: false,
      cell: ({ row }) => {
        const report = row.original;
        if (report.status === "failed") {
          return (
            <span className="text-sm text-status-fail" title={report.error_message ?? undefined}>
              {report.error_message ?? "Generation failed"}
            </span>
          );
        }
        if (report.status !== "completed") return null;
        return (
          <div className="flex justify-end gap-1">
            <Button variant="ghost" size="sm" asChild>
              <Link to={`/reports/${report.id}`}>
                <FileText className="size-3.5" aria-hidden />
                View
              </Link>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleDownload(report)}
              disabled={downloadingId === report.id}
            >
              {downloadingId === report.id ? (
                <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
              ) : (
                <Download className="size-3.5" aria-hidden />
              )}
              Download
            </Button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="assessment reports"
        description="An AI-written assessment of one project's findings, organised by the Google Cloud Well-Architected Framework. Remediation steps come from the scanner itself, not the model."
      />

      {canSubmitAny && (
        <Panel>
          <form onSubmit={handleSubmit} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="space-y-1.5">
              <Label htmlFor="report-organization">Organization</Label>
              <Combobox
                id="report-organization"
                value={organizationId}
                onValueChange={(value) => {
                  setOrganizationId(value);
                  setProjectId("");
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
                onValueChange={setProjectId}
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
            <div className="space-y-1.5 sm:col-span-2 lg:col-span-2">
              <Label htmlFor="report-mode">Analysis</Label>
              <Combobox
                id="report-mode"
                value={mode}
                onValueChange={(value) => setMode(value as ReportMode)}
                options={MODES.map((m) => ({
                  value: m.value,
                  label: m.label,
                  hint: m.hint,
                }))}
                placeholder="Select an analysis mode"
                className="w-full"
              />
              <p className="text-xs text-ink-muted">
                {MODES.find((m) => m.value === mode)?.blurb}
              </p>
            </div>
            {mode === "deep" && (
              <div className="space-y-1.5 sm:col-span-2 lg:col-span-4">
                <Label htmlFor="report-instructions">
                  What should the analysis focus on?{" "}
                  <span className="font-normal text-ink-muted">(optional)</span>
                </Label>
                <Textarea
                  id="report-instructions"
                  value={instructions}
                  onChange={(event) => setInstructions(event.target.value)}
                  maxLength={4000}
                  rows={3}
                  placeholder="e.g. The customer cares most about data exfiltration paths — lead with those, and keep the language non-technical."
                />
                <p className="text-xs text-ink-muted">
                  Steers emphasis and tone. Every finding is covered either way — this cannot
                  narrow what the report includes.
                </p>
              </div>
            )}
            <div className="flex items-end sm:col-span-2 lg:col-span-4">
              {/* Same control and wording as the Compliance Report's own muted
                  switch, so the two screens do not describe muting differently. */}
              <label className="mr-4 flex items-center gap-2 pb-2 text-sm text-ink-secondary">
                <Switch checked={includeMuted} onCheckedChange={setIncludeMuted} />
                Include muted findings
              </label>
              <Button type="submit" disabled={submitReport.isPending || !canSubmit}>
                {submitReport.isPending ? (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Sparkles className="size-3.5" aria-hidden />
                )}
                Generate report
              </Button>
            </div>
          </form>
        </Panel>
      )}

      <DataTable
        columns={columns}
        data={reports.data ?? []}
        isLoading={reports.isLoading}
        error={reports.error}
        errorMessage={errorMessage(reports.error, "Couldn't load reports.")}
        onRetry={() => reports.refetch()}
        searchPlaceholder="Search by reference…"
        empty={
          <EmptyState
            icon={FileText}
            title="No reports yet"
            description="Pick a project above and generate one. A report needs a succeeded scan to draw on."
          />
        }
      />
    </div>
  );
}
