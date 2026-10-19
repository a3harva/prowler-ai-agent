import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, LoaderCircle, RefreshCw, TriangleAlert } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { CopyableUid } from "@/components/copyable-uid";
import { ErrorState } from "@/components/states";
import { ScanState, isScanActive, type ScanStatus } from "@/components/scan-state";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/components/status-region";
import { errorMessage } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { formatDuration, formatTimestamp } from "@/lib/format";
import { useCancelScan, useOrganizations, useProjects, useScan, useScanLog } from "@/hooks/queries";
import { cn, PILL_CLASS } from "@/lib/utils";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="eyebrow">{label}</p>
      <div className="text-sm text-ink">{children}</div>
    </div>
  );
}

export default function ScanDetail() {
  const params = useParams<{ id: string }>();
  const scanId = params.id ? Number(params.id) : undefined;
  const scan = useScan(scanId);
  const projects = useProjects();
  const organizations = useOrganizations();
  const [showLog, setShowLog] = useState(false);
  const log = useScanLog(scanId, showLog);
  const { permissions } = useAuth();
  const cancelScan = useCancelScan();
  const statusRegion = useStatus();

  const project = (projects.data ?? []).find((p) => p.id === scan.data?.project_id);
  const organization = (organizations.data ?? []).find((o) => o.id === project?.gcp_organization_id);

  const handleCancel = async () => {
    if (!scan.data) return;
    try {
      await cancelScan.mutateAsync(scan.data.id);
      statusRegion.succeed(`Cancelled scan #${scan.data.id}.`);
    } catch (error) {
      statusRegion.fail(errorMessage(error, "Couldn't cancel that scan."));
    }
  };

  if (scan.isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <LoaderCircle className="size-5 animate-spin text-ink-muted" aria-hidden />
      </div>
    );
  }

  if (scan.error || !scan.data) {
    return (
      <Panel padded={false}>
        <ErrorState
          message={errorMessage(scan.error, "Couldn't load this scan.")}
          onRetry={() => scan.refetch()}
        />
      </Panel>
    );
  }

  const status = scan.data.status as ScanStatus;
  const active = isScanActive(status);
  const failed = status === "failed" || status === "timeout" || status === "import_failed" || status === "schema_mismatch";
  const cancelled = status === "cancelled";

  return (
    <div className="space-y-6">
      <Link
        to="/scans"
        className="inline-flex items-center gap-1.5 text-sm text-ink-secondary transition-colors duration-150 hover:text-ink"
      >
        <ArrowLeft className="size-3.5" aria-hidden />
        scans
      </Link>

      <PageHeader
        title={`scan #${scan.data.id}`}
        description={project ? `Ran against ${project.project_id}` : undefined}
        actions={
          <div className="flex items-center gap-2">
            {active && organization && permissions.canEdit(organization.department_id) && (
              <Button
                variant="outline"
                size="sm"
                className="text-status-fail hover:text-status-fail"
                onClick={handleCancel}
                disabled={cancelScan.isPending}
              >
                {cancelScan.isPending && <LoaderCircle className="size-3.5 animate-spin" aria-hidden />}
                Cancel scan
              </Button>
            )}
            {status === "succeeded" && project && (
              <Button variant="outline" size="sm" asChild>
                <Link to={`/findings?project=${project.id}`}>View findings</Link>
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => scan.refetch()} disabled={scan.isFetching}>
              <RefreshCw className={scan.isFetching ? "size-3.5 animate-spin" : "size-3.5"} aria-hidden />
              Refresh
            </Button>
          </div>
        }
      />

      {/* Auto-polls every 3s while active (see useScan) — this is a manual
          escape hatch for when that stalls, not the only way to refresh. */}

      <Panel className="space-y-5">
        <div className="flex flex-wrap items-center gap-3">
          <ScanState status={status} />
          {active && (
            <span className="text-xs text-ink-muted">
              Updating automatically — safe to close this tab, the scan keeps running.
            </span>
          )}
          {scan.data.stale && (
            <span className={cn(PILL_CLASS, "bg-status-manual-bg text-status-manual ring-status-manual-line")}>
              <TriangleAlert className="size-3.5" aria-hidden />
              No update in a while — the worker that owned this may have restarted
            </span>
          )}
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Project">
            {project ? <CopyableUid value={project.project_id} max={32} /> : "—"}
          </Field>
          <Field label="Organization">{organization?.name ?? "—"}</Field>
          <Field label="Triggered">{formatTimestamp(scan.data.triggered_at)}</Field>
          <Field label="Started">{formatTimestamp(scan.data.started_at)}</Field>
          <Field label="Completed">{formatTimestamp(scan.data.completed_at)}</Field>
          <Field label="Duration">{formatDuration(scan.data.started_at, scan.data.completed_at)}</Field>
          <Field label="Exit code">{scan.data.exit_code ?? "—"}</Field>
        </div>
      </Panel>

      {(failed || cancelled) && scan.data.error_message && (
        <Panel className="space-y-2 border-status-fail-line bg-status-fail-bg/40">
          <p className="text-sm font-medium text-status-fail">{cancelled ? "Cancelled" : "Why it failed"}</p>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-panel p-3 font-mono text-xs text-ink">
            {scan.data.error_message}
          </pre>
        </Panel>
      )}

      <Panel className="space-y-3">
        <div className="flex items-center justify-between">
          <p className="card-title">scanner output</p>
          <Button variant="outline" size="sm" onClick={() => setShowLog((v) => !v)}>
            {showLog ? "Hide full log" : "View full log"}
          </Button>
        </div>
        {showLog && (
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md bg-subtle p-3 font-mono text-xs text-ink-secondary">
            {log.isLoading ? "Loading…" : log.data?.log || "No output captured yet."}
          </pre>
        )}
      </Panel>
    </div>
  );
}
