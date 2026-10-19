import { useMemo, useState } from "react";
import { BookCheck, LoaderCircle, ShieldCheck } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { EmptyState } from "@/components/states";
import { useStatus } from "@/components/status-region";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import { errorMessage } from "@/api/client";
import type { ComplianceSeedResult } from "@/api/types";
import { useOrganizations, useProjects, useScans, useSeedComplianceRulebook } from "@/hooks/queries";
import { formatTimestamp } from "@/lib/format";

/**
 * Point at any succeeded scan and load its
 * `compliance/` output as the shared rulebook. Every scan already produces
 * one, so this is a single action rather than a file-upload flow — the
 * report itself is a separate screen once the rulebook exists.
 */
export default function Compliance() {
  const organizations = useOrganizations();
  const projects = useProjects();
  const scans = useScans();
  const seedRulebook = useSeedComplianceRulebook();
  const status = useStatus();

  const [organizationId, setOrganizationId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [scanId, setScanId] = useState("");
  const [result, setResult] = useState<ComplianceSeedResult | null>(null);

  const projectsInOrganization = useMemo(
    () =>
      (projects.data ?? []).filter(
        (p) => !organizationId || String(p.gcp_organization_id) === organizationId,
      ),
    [projects.data, organizationId],
  );

  // Only a succeeded scan has a complete compliance/ directory on disk —
  // anything else (still running, failed, cancelled) has nothing to load.
  const succeededScansForProject = useMemo(
    () =>
      (scans.data ?? [])
        .filter((s) => s.project_id === Number(projectId) && s.status === "succeeded")
        .sort((a, b) => b.id - a.id),
    [scans.data, projectId],
  );

  const handleSeed = async () => {
    if (!scanId) return;
    setResult(null);
    try {
      const response = await seedRulebook.mutateAsync(Number(scanId));
      setResult(response.data);
      status.succeed(
        `Loaded ${response.data.requirement_count} requirements across ${response.data.framework_count} frameworks.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't load the rulebook from that scan."));
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="compliance rulebook"
        description="Load the compliance framework rulebook from any succeeded scan's output. This replaces the entire rulebook, shared by every project — the per-project report lives on its own screen once loaded."
      />

      <Panel>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div className="space-y-1.5">
            <Label htmlFor="compliance-organization">Organization</Label>
            <Combobox
              id="compliance-organization"
              value={organizationId}
              onValueChange={(value) => {
                setOrganizationId(value);
                setProjectId("");
                setScanId("");
                setResult(null);
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
            <Label htmlFor="compliance-project">Project</Label>
            <Combobox
              id="compliance-project"
              value={projectId}
              onValueChange={(value) => {
                setProjectId(value);
                setScanId("");
                setResult(null);
              }}
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
            <Label htmlFor="compliance-scan">Succeeded scan</Label>
            <Combobox
              id="compliance-scan"
              value={scanId}
              onValueChange={(value) => {
                setScanId(value);
                setResult(null);
              }}
              disabled={!projectId}
              options={succeededScansForProject.map((scan) => ({
                value: String(scan.id),
                label: `Scan #${scan.id} · ${formatTimestamp(scan.completed_at ?? scan.triggered_at)}`,
              }))}
              placeholder={projectId ? "Select a scan" : "Choose a project first"}
              searchPlaceholder="Search scans…"
              emptyMessage="No scans match."
              className="w-full"
            />
            {projectId && succeededScansForProject.length === 0 && (
              <p className="text-xs text-ink-muted">No succeeded scans for this project yet.</p>
            )}
          </div>
        </div>

        <div className="mt-4">
          <Button onClick={handleSeed} disabled={!scanId || seedRulebook.isPending}>
            {seedRulebook.isPending ? (
              <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
            ) : (
              <BookCheck className="size-3.5" aria-hidden />
            )}
            Load rulebook from this scan
          </Button>
        </div>
      </Panel>

      {result ? (
        <Panel>
          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <p className="eyebrow">Frameworks</p>
              <p className="font-display text-2xl font-light tabular-nums text-ink">{result.framework_count}</p>
            </div>
            <div>
              <p className="eyebrow">Requirements</p>
              <p className="font-display text-2xl font-light tabular-nums text-ink">{result.requirement_count}</p>
            </div>
            <div>
              <p className="eyebrow">Scanner version</p>
              <p className="font-display text-2xl font-light tabular-nums text-ink">{result.prowler_version}</p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-1.5">
            {result.frameworks.map((framework) => (
              <span
                key={framework}
                className="rounded border border-hairline bg-subtle px-1.5 py-0.5 font-mono text-[11px] text-ink-secondary"
              >
                {framework}
              </span>
            ))}
          </div>
        </Panel>
      ) : (
        <Panel padded={false}>
          <EmptyState
            icon={ShieldCheck}
            title="No rulebook loaded this session"
            description="Pick an organization, project and succeeded scan above, then load the rulebook — every scan already produces a compliance/ folder alongside its main output."
          />
        </Panel>
      )}
    </div>
  );
}
