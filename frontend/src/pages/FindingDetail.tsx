import { Link, useParams } from "react-router-dom";
import { ArrowLeft, BellOff, LoaderCircle } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { CopyableUid } from "@/components/copyable-uid";
import { ErrorState } from "@/components/states";
import { SeverityChip, type Severity } from "@/components/severity-chip";
import { StatusBadge, type FindingStatus } from "@/components/status-badge";
import { OverlayRail, type MuteReason } from "@/components/overlay-rail";
import { MuteFindingDialog } from "@/components/mute-finding-dialog";
import { Button } from "@/components/ui/button";
import { errorMessage } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { formatTimestamp } from "@/lib/format";
import { useFinding, useOrganizations, useProjects } from "@/hooks/queries";
import { useState } from "react";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="eyebrow">{label}</p>
      <div className="text-sm text-ink">{children}</div>
    </div>
  );
}

/**
 * Shows every field the importer currently captures for one finding.
 * Deliberately just a readable record of what's already there — the plan
 * for this page (evidence, history, linked tickets, etc.) is separate and
 * not anticipated here.
 */
export default function FindingDetail() {
  const params = useParams<{ id: string }>();
  const findingId = params.id ? Number(params.id) : undefined;
  const finding = useFinding(findingId);
  const projects = useProjects();
  const organizations = useOrganizations();
  const { permissions } = useAuth();
  const [muting, setMuting] = useState(false);

  const project = (projects.data ?? []).find((p) => p.id === finding.data?.project_id);
  const organization = (organizations.data ?? []).find((o) => o.id === project?.gcp_organization_id);

  if (finding.isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <LoaderCircle className="size-5 animate-spin text-ink-muted" aria-hidden />
      </div>
    );
  }

  if (finding.error || !finding.data) {
    return (
      <Panel padded={false}>
        <ErrorState
          message={errorMessage(finding.error, "Couldn't load this finding.")}
          onRetry={() => finding.refetch()}
        />
      </Panel>
    );
  }

  const data = finding.data;
  const canEdit = permissions.canEdit(organization?.department_id);

  return (
    <div className="space-y-6">
      <Link
        to={`/findings${project ? `?project=${project.id}` : ""}`}
        className="inline-flex items-center gap-1.5 text-sm text-ink-secondary transition-colors duration-150 hover:text-ink"
      >
        <ArrowLeft className="size-3.5" aria-hidden />
        findings
      </Link>

      <PageHeader
        title={data.check_title}
        description={project ? `${project.project_id} · ${data.resource_name}` : data.resource_name}
        actions={
          canEdit && (
            <Button variant="outline" size="sm" onClick={() => setMuting(true)}>
              {data.muted ? (
                <>
                  <BellOff className="size-3.5" aria-hidden />
                  Edit mute
                </>
              ) : (
                "Mute"
              )}
            </Button>
          )
        }
      />

      <Panel className="space-y-5">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityChip severity={data.severity as Severity} />
          <StatusBadge status={data.status as FindingStatus} />
        </div>

        {data.muted && data.mute_reason && (
          <OverlayRail reason={data.mute_reason as MuteReason} note={data.note} />
        )}

        {data.status_extended && (
          <p className="max-w-3xl text-sm leading-relaxed text-ink-secondary">{data.status_extended}</p>
        )}

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Check">
            <p className="text-sm text-ink">{data.check_title}</p>
            <p className="font-mono text-xs text-ink-muted">{data.check_id}</p>
          </Field>
          <Field label="Project">
            {project ? <CopyableUid value={project.project_id} max={32} /> : "—"}
          </Field>
          <Field label="Organization">{organization?.name ?? "—"}</Field>
          <Field label="Service">
            {data.service_name}
            {data.subservice_name ? ` / ${data.subservice_name}` : ""}
          </Field>
          <Field label="Region">{data.region}</Field>
          <Field label="Resource type">{data.resource_type}</Field>
          <Field label="Resource name">{data.resource_name}</Field>
          <Field label="Resource UID">
            <CopyableUid value={data.resource_uid} max={48} />
          </Field>
          <Field label="Finding UID">
            <CopyableUid value={data.finding_uid} max={48} />
          </Field>
          <Field label="First seen">{formatTimestamp(data.first_seen_at)}</Field>
          <Field label="Last updated">{formatTimestamp(data.updated_at)}</Field>
          <Field label="Last scan">
            <Link
              to={`/scans/${data.last_scan_id}`}
              className="text-brand underline-offset-2 hover:underline"
            >
              Scan #{data.last_scan_id}
            </Link>
          </Field>
        </div>
      </Panel>

      {muting && <MuteFindingDialog finding={data} onOpenChange={(open) => !open && setMuting(false)} />}
    </div>
  );
}
