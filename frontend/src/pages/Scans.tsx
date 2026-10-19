import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { LoaderCircle, Play, Radar } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable, MutedCell } from "@/components/data-table";
import { CopyableUid } from "@/components/copyable-uid";
import { FacetedFilter, type FacetOption } from "@/components/faceted-filter";
import { EmptyState } from "@/components/states";
import { useStatus } from "@/components/status-region";
import {
  ScanState,
  SCAN_STATUS_LABEL,
  SCAN_STATUS_ORDER,
  isScanActive,
  type ScanStatus,
} from "@/components/scan-state";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import { errorMessage } from "@/api/client";
import type { Scan } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { formatDuration, formatRelative, formatTimestamp } from "@/lib/format";
import {
  useCancelScan,
  useDepartmentNames,
  useOrganizations,
  useProjects,
  useScans,
  useSubmitScan,
} from "@/hooks/queries";

export default function Scans() {
  const { permissions } = useAuth();
  const navigate = useNavigate();
  const scans = useScans();
  const projects = useProjects();
  const organizations = useOrganizations();
  const departments = useDepartmentNames();
  const status = useStatus();

  // A project only carries `gcp_organization_id`, so the department it
  // belongs to — what actually gates who may scan it — has to be derived by
  // joining through its organization.
  const departmentIdForProject = useMemo(() => {
    const orgToDepartment = new Map((organizations.data ?? []).map((o) => [o.id, o.department_id]));
    return new Map(
      (projects.data ?? [])
        .filter((p) => !p.deleted)
        .map((p) => [p.id, orgToDepartment.get(p.gcp_organization_id)]),
    );
  }, [projects.data, organizations.data]);

  const editableDepartmentIds = useMemo(() => {
    if (permissions.isGlobalAdmin) return new Set((departments.data ?? []).map((d) => d.id));
    return new Set(permissions.grantedDepartmentIds.filter((id) => permissions.canEdit(id)));
  }, [permissions, departments.data]);

  const [departmentId, setDepartmentId] = useState<string>("");
  const [projectId, setProjectId] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<Set<string>>(new Set());

  const statusOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const scan of scans.data ?? []) {
      counts.set(scan.status, (counts.get(scan.status) ?? 0) + 1);
    }
    return SCAN_STATUS_ORDER.filter((status) => counts.get(status)).map((status) => ({
      value: status,
      label: SCAN_STATUS_LABEL[status],
      count: counts.get(status),
    }));
  }, [scans.data]);

  const filteredScans = useMemo(() => {
    if (statusFilter.size === 0) return scans.data;
    return (scans.data ?? []).filter((scan) => statusFilter.has(scan.status));
  }, [scans.data, statusFilter]);

  const scannableProjects = (projects.data ?? []).filter(
    (p) => !p.deleted && String(departmentIdForProject.get(p.id)) === departmentId,
  );

  const submitScan = useSubmitScan();
  const cancelScan = useCancelScan();
  const [cancellingId, setCancellingId] = useState<number | null>(null);

  const handleCancel = async (scan: Scan) => {
    setCancellingId(scan.id);
    try {
      await cancelScan.mutateAsync(scan.id);
      status.succeed(`Cancelled scan #${scan.id}.`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't cancel that scan."));
    } finally {
      setCancellingId(null);
    }
  };

  const canSubmitAny = editableDepartmentIds.size > 0;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!projectId) return;
    try {
      const response = await submitScan.mutateAsync({ project_id: Number(projectId) });
      setDepartmentId("");
      setProjectId("");
      status.succeed("Scan submitted — it runs in the background even if you leave this page.");
      navigate(`/scans/${response.data.id}`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't submit that scan."));
    }
  };

  const columns: ColumnDef<Scan, any>[] = [
    {
      accessorKey: "id",
      header: "Scan",
      cell: ({ row }) => <span className="font-mono text-xs text-ink">#{row.original.id}</span>,
    },
    {
      accessorKey: "project_id",
      header: "Project",
      cell: ({ row }) => {
        const project = (projects.data ?? []).find((p) => p.id === row.original.project_id);
        return project ? (
          <CopyableUid value={project.project_id} max={32} />
        ) : (
          <MutedCell>Project #{row.original.project_id}</MutedCell>
        );
      },
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <ScanState status={row.original.status as ScanStatus} />
          {row.original.stale && (
            <span className="text-xs text-status-manual">stalled?</span>
          )}
        </div>
      ),
    },
    {
      accessorKey: "triggered_at",
      header: "Triggered",
      cell: ({ row }) => (
        <div className="text-sm text-ink-secondary">
          <p>{formatTimestamp(row.original.triggered_at)}</p>
          <p className="text-xs text-ink-muted">{formatRelative(row.original.triggered_at)}</p>
        </div>
      ),
    },
    {
      id: "duration",
      header: "Duration",
      cell: ({ row }) => (
        <MutedCell>{formatDuration(row.original.started_at, row.original.completed_at)}</MutedCell>
      ),
    },
    {
      id: "actions",
      header: "",
      enableSorting: false,
      cell: ({ row }) => {
        const scan = row.original;
        const departmentId = departmentIdForProject.get(scan.project_id);
        const canCancel = isScanActive(scan.status as ScanStatus) && permissions.canEdit(departmentId);
        return (
          <div className="flex justify-end gap-1">
            {canCancel && (
              <Button
                variant="ghost"
                size="sm"
                className="text-status-fail hover:text-status-fail"
                onClick={() => handleCancel(scan)}
                disabled={cancellingId === scan.id}
              >
                {cancellingId === scan.id && (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                )}
                Cancel
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={() => navigate(`/scans/${scan.id}`)}>
              View
            </Button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="scans"
        description="Trigger a Prowler scan against an onboarded project and watch it run."
      />

      {canSubmitAny && (
        <Panel className="space-y-4">
          <form onSubmit={handleSubmit} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="space-y-1.5">
              <Label htmlFor="scan-department">Department</Label>
              <Combobox
                id="scan-department"
                value={departmentId}
                onValueChange={(value) => {
                  setDepartmentId(value);
                  setProjectId("");
                }}
                options={(departments.data ?? []) .filter((d) => editableDepartmentIds.has(d.id)).map((department) => ({
                  value: String(department.id),
                  label: department.name,
                }))}
                placeholder="Select a department"
                searchPlaceholder="Search departments…"
                emptyMessage="No departments match."
                className="w-full"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="scan-project">Project</Label>
              <Combobox
                id="scan-project"
                value={projectId}
                onValueChange={setProjectId}
                disabled={!departmentId}
                options={scannableProjects.map((project) => ({
                  value: String(project.id),
                  label: project.project_id,
                }))}
                placeholder={departmentId ? "Select a project" : "Choose a department first"}
                searchPlaceholder="Search projects…"
                emptyMessage="No projects match."
                className="w-full"
              />
              {departmentId && scannableProjects.length === 0 && (
                <p className="text-xs text-ink-muted">
                  No onboarded projects under this department yet.
                </p>
              )}
            </div>
            <div className="flex items-end sm:col-span-2 lg:col-span-2">
              <Button type="submit" disabled={submitScan.isPending || !projectId}>
                {submitScan.isPending ? (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Play className="size-3.5" aria-hidden />
                )}
                Run scan
              </Button>
            </div>
          </form>
        </Panel>
      )}

      <DataTable
        columns={columns}
        data={filteredScans}
        isLoading={scans.isLoading}
        error={scans.error}
        errorMessage={errorMessage(scans.error, "Couldn't load scans.")}
        onRetry={() => scans.refetch()}
        searchPlaceholder="Search scans…"
        toolbar={
          statusOptions.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <FacetedFilter
                title="Status"
                options={statusOptions}
                selected={statusFilter}
                onChange={setStatusFilter}
              />
              {statusFilter.size > 0 && (
                <Button variant="ghost" size="sm" onClick={() => setStatusFilter(new Set())}>
                  Reset
                </Button>
              )}
            </div>
          )
        }
        empty={
          statusFilter.size > 0 ? (
            <EmptyState
              icon={Radar}
              title="No scans match this filter"
              description="Nothing in this list matches the selected status."
              action={
                <Button variant="outline" size="sm" onClick={() => setStatusFilter(new Set())}>
                  Clear filter
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={Radar}
              title="No scans yet"
              description={
                canSubmitAny
                  ? "Submit one above against an onboarded project."
                  : "Nothing has run under the departments you can access."
              }
            />
          )
        }
      />
    </div>
  );
}
