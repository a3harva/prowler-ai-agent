import { Link } from "react-router-dom";
import { ArrowRight, Building2, FolderGit2, Radar, ShieldCheck, Users } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { EmptyState } from "@/components/states";
import { ScanState, type ScanStatus } from "@/components/scan-state";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/auth/AuthContext";
import { formatRelative } from "@/lib/format";
import { useDepartments, useOrganizations, useProjects, useScans } from "@/hooks/queries";
import { cn } from "@/lib/utils";

/**
 * A stat card: label and supporting text on the left, the figure large on
 * the right, a proportion bar beneath. The number is the thing being read,
 * so it gets the display face and the size; everything else supports it.
 */
function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  to,
  loading,
}: {
  label: string;
  value: number | undefined;
  hint: string;
  icon: typeof Building2;
  to?: string;
  loading?: boolean;
}) {
  const count = value ?? 0;

  const body = (
    <Panel
      className={cn(
        "h-full transition-all duration-150",
        to && "hover:border-brand-200 hover:shadow-[var(--shadow-lift)]",
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 space-y-1">
          <div className="flex items-center gap-1.5">
            <Icon className="size-3.5 shrink-0 text-ink-muted" aria-hidden />
            <p className="text-sm font-medium text-ink-secondary">{label}</p>
          </div>
          <p className="text-sm leading-relaxed text-ink-muted">{hint}</p>
        </div>
        {loading ? (
          <Skeleton className="h-10 w-14 shrink-0" />
        ) : (
          <p className="display-number shrink-0 leading-none">{count}</p>
        )}
      </div>

      {/* No proportion bar here on purpose. These counts have no
          denominator — "4 projects" is not 4 out of anything — so a bar
          would sit at 100% on every card and read as data while carrying
          none. Bars return on the compliance screen, where a genuine
          ratio exists. */}
      {to && (
        <span className="mt-4 inline-flex items-center gap-1 border-t border-hairline pt-3 text-sm font-medium text-brand">
          View all
          <ArrowRight className="size-3.5" aria-hidden />
        </span>
      )}
    </Panel>
  );

  return to ? (
    <Link to={to} className="block rounded-xl focus-visible:outline-2 focus-visible:outline-offset-2">
      {body}
    </Link>
  ) : (
    body
  );
}

export default function Dashboard() {
  const { user, permissions } = useAuth();
  const projects = useProjects();
  const organizations = useOrganizations();
  // Departments are scoped server-side, so this count is "what you can see",
  // not "what exists" — the honest number for a non-admin.
  const departments = useDepartments();
  const scans = useScans();
  const recentScans = (scans.data ?? []).slice(0, 5);

  const firstName = user?.name?.split(" ")[0] ?? "there";
  const loading = projects.isLoading || organizations.isLoading || departments.isLoading;
  const hasProjects = (projects.data?.length ?? 0) > 0;

  return (
    <div className="space-y-5">
      <PageHeader
        title={`welcome back, ${firstName}`}
        description={
          permissions.isGlobalAdmin
            ? "You have administrator access to every department."
            : "You're seeing the departments you have been granted access to."
        }
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <StatCard
          label="Projects"
          value={projects.data?.length}
          hint="GCP projects registered for scanning."
          icon={FolderGit2}
          to="/projects"
          loading={loading}
        />
        <StatCard
          label="Organizations"
          value={organizations.data?.length}
          hint="GCP organizations grouped under departments."
          icon={Building2}
          to="/organizations"
          loading={loading}
        />
        <StatCard
          label="Departments"
          value={departments.data?.length}
          hint={
            permissions.isGlobalAdmin
              ? "Onboarded from Freshservice."
              : "Departments you hold a role on."
          }
          icon={Users}
          to={permissions.isGlobalAdmin ? "/admin/departments" : undefined}
          loading={loading}
        />
      </div>

      <Panel padded={recentScans.length > 0}>
        {recentScans.length === 0 ? (
          <EmptyState
            icon={Radar}
            title="No scans yet"
            description={
              hasProjects
                ? "Submit a scan against a registered project and watch it run from here."
                : "Register a GCP project first — a project is what a scan runs against."
            }
            action={
              <Button asChild>
                <Link to={hasProjects ? "/scans" : "/projects"}>
                  {hasProjects ? <Radar className="size-3.5" aria-hidden /> : <FolderGit2 className="size-3.5" aria-hidden />}
                  {hasProjects ? "Run a scan" : "Register a project"}
                </Link>
              </Button>
            }
          />
        ) : (
          <div className="divide-y divide-hairline">
            <div className="flex items-center justify-between px-1 pb-3">
              <p className="card-title">recent scans</p>
              <Link to="/scans" className="inline-flex items-center gap-1 text-sm font-medium text-brand">
                View all
                <ArrowRight className="size-3.5" aria-hidden />
              </Link>
            </div>
            {recentScans.map((scan) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center justify-between gap-3 px-1 py-3 transition-colors duration-150 hover:bg-subtle"
              >
                <span className="font-mono text-xs text-ink-muted">#{scan.id}</span>
                <ScanState status={scan.status as ScanStatus} />
                <span className="ml-auto text-xs text-ink-muted">{formatRelative(scan.triggered_at)}</span>
              </Link>
            ))}
          </div>
        )}
      </Panel>

      {!permissions.isGlobalAdmin && permissions.grantedDepartmentIds.length === 0 && (
        <Panel>
          <div className="flex items-start gap-3">
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-ink-muted" aria-hidden />
            <div className="space-y-1">
              <p className="text-sm font-medium text-ink">No department access yet</p>
              <p className="text-sm leading-relaxed text-ink-muted">
                Your account is signed in but holds no department role, so there is nothing to
                show. Ask an administrator to grant you access.
              </p>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}
