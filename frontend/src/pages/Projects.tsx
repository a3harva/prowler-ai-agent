import { useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { FolderGit2, KeyRound, LoaderCircle, Pencil, Plus, Trash2 } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable } from "@/components/data-table";
import { CopyableUid } from "@/components/copyable-uid";
import { EmptyState } from "@/components/states";
import { useStatus } from "@/components/status-region";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import { errorMessage } from "@/api/client";
import type { Project } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { shortenServiceAccount } from "@/lib/format";
import {
  useDeleteProject,
  useOrganizationNames,
  useProjects,
  useRegisterProject,
  useUpdateProject,
} from "@/hooks/queries";

function EditProjectDialog({
  project,
  onOpenChange,
  organizationOptions,
}: {
  project: Project;
  onOpenChange: (open: boolean) => void;
  organizationOptions: { value: string; label: string }[];
}) {
  const updateProject = useUpdateProject();
  const status = useStatus();

  const [organizationId, setOrganizationId] = useState(String(project.gcp_organization_id));
  const [targetSaEmail, setTargetSaEmail] = useState(project.target_sa_email);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      await updateProject.mutateAsync({
        id: project.id,
        gcp_organization_id: Number(organizationId),
        target_sa_email: targetSaEmail.trim(),
      });
      status.succeed(`Updated ${project.project_id}.`);
      onOpenChange(false);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't update that project."));
    }
  };

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit project</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label>GCP project ID</Label>
            {/* Immutable — the GCP identifier can't change once registered.
                Shown as read-only text, not an input, so there is nothing
                here that could even be typed into. */}
            <p className="rounded-md border border-hairline bg-subtle px-3 py-2 font-mono text-sm text-ink-secondary">
              {project.project_id}
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edit-project-organization">Organization</Label>
            <Combobox
              id="edit-project-organization"
              value={organizationId}
              onValueChange={setOrganizationId}
              options={organizationOptions}
              placeholder="Select an organization"
              searchPlaceholder="Search organizations…"
              emptyMessage="No organizations match."
              className="w-full"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edit-target-sa">Target service account</Label>
            <Input
              id="edit-target-sa"
              type="email"
              value={targetSaEmail}
              onChange={(event) => setTargetSaEmail(event.target.value)}
              className="font-mono"
              required
            />
          </div>
          <DialogFooter>
            <Button
              type="submit"
              disabled={updateProject.isPending || !organizationId || !targetSaEmail.trim()}
            >
              {updateProject.isPending && (
                <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
              )}
              Save
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function Projects() {
  const { permissions } = useAuth();
  const projects = useProjects();
  const organizations = useOrganizationNames();
  const status = useStatus();

  const [projectId, setProjectId] = useState("");
  const [organizationId, setOrganizationId] = useState<string>("");
  const [targetSaEmail, setTargetSaEmail] = useState("");
  const [editingProject, setEditingProject] = useState<Project | null>(null);

  const registerProject = useRegisterProject();
  const deleteProject = useDeleteProject();

  // A department Admin manages projects only within the department(s) they
  // administer — not just the global bootstrap admin. The org picker (both
  // for registering and editing) is scoped to match, so a submission can
  // never fail permission-wise for an option the picker itself offered.
  const manageableDepartmentIds = new Set(permissions.departmentIdsWithAtLeast("admin"));
  const canRegisterProjects = permissions.isGlobalAdmin || manageableDepartmentIds.size > 0;
  const manageableOrganizations = (organizations.data ?? []).filter(
    (organization) => permissions.isGlobalAdmin || manageableDepartmentIds.has(organization.department_id),
  );
  const organizationOptions = manageableOrganizations.map((organization) => ({
    value: String(organization.id),
    label: organization.name,
  }));

  const handleRegister = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!organizationId) return;
    try {
      await registerProject.mutateAsync({
        project_id: projectId.trim(),
        gcp_organization_id: Number(organizationId),
        target_sa_email: targetSaEmail.trim(),
      });
      const registered = projectId.trim();
      setProjectId("");
      setOrganizationId("");
      setTargetSaEmail("");
      status.succeed(
        `Registered ${registered}. Grant impersonation on the target service account before scanning it.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't register that project."));
    }
  };

  const handleDelete = async (project: Project) => {
    try {
      await deleteProject.mutateAsync(project.id);
      status.succeed(
        `Deleted ${project.project_id}. Registering the same ID again is fine — it starts as a new record.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't delete that project."));
    }
  };

  const columns: ColumnDef<Project, any>[] = [
    {
      accessorKey: "project_id",
      header: "Project ID",
      cell: ({ row }) => <CopyableUid value={row.original.project_id} max={32} />,
    },
    {
      accessorKey: "gcp_organization_id",
      header: "Organization",
      cell: ({ row }) => (
        <span className="text-sm text-ink-secondary">
          {organizations.nameFor(row.original.gcp_organization_id)}
        </span>
      ),
    },
    {
      accessorKey: "target_sa_email",
      header: "Target service account",
      cell: ({ row }) => (
        <CopyableUid
          value={row.original.target_sa_email}
          display={shortenServiceAccount(row.original.target_sa_email)}
          max={40}
        />
      ),
    },
    {
      id: "actions",
      header: "",
      enableSorting: false,
      cell: ({ row }) => {
        const project = row.original;
        const organizationDepartmentId = organizations.data?.find(
          (organization) => organization.id === project.gcp_organization_id,
        )?.department_id;
        if (!permissions.isGlobalAdmin && !permissions.canManageProjects(organizationDepartmentId)) {
          return null;
        }
        const deleting = deleteProject.isPending && deleteProject.variables === project.id;
        return (
          <div className="flex justify-end gap-1">
            <Button variant="ghost" size="sm" onClick={() => setEditingProject(project)}>
              <Pencil className="size-3.5" aria-hidden />
              Edit
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleDelete(project)}
              disabled={deleting}
            >
              {deleting ? (
                <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
              ) : (
                <Trash2 className="size-3.5" aria-hidden />
              )}
              Delete
            </Button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="projects"
        description="GCP projects registered for scanning, each under an organization."
      />

      {canRegisterProjects && (
        <Panel className="space-y-4">
          {/* State this at the point of registration: a project missing the
              grant looks completely healthy right up
              until its first scan fails, which is why it is a standing
              notice here rather than an error surfaced later. */}
          <div className="flex items-start gap-2.5 rounded-md border border-notice-line bg-notice-bg px-3 py-2.5">
            <KeyRound className="mt-0.5 size-4 shrink-0 text-notice" aria-hidden />
            <p className="text-sm leading-relaxed text-ink-secondary">
              Registering a project only records it here. It does{" "}
              <strong className="font-semibold text-ink">not</strong> grant anything —
              someone with access to the target GCP project must separately grant impersonation
              on the service account below, outside this application.{" "}
              <span className="text-ink-muted">
                A project with that grant missing looks completely healthy until its first scan
                fails.
              </span>
            </p>
          </div>

          <form onSubmit={handleRegister} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="space-y-1.5">
              <Label htmlFor="project-id">GCP project ID</Label>
              <Input
                id="project-id"
                value={projectId}
                onChange={(event) => setProjectId(event.target.value)}
                placeholder="synthetic-project-id"
                className="font-mono"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="project-organization">Organization</Label>
              <Combobox
                id="project-organization"
                value={organizationId}
                onValueChange={setOrganizationId}
                options={organizationOptions}
                placeholder="Select an organization"
                searchPlaceholder="Search organizations…"
                emptyMessage="No organizations match."
                className="w-full"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="target-sa">Target service account</Label>
              <Input
                id="target-sa"
                type="email"
                value={targetSaEmail}
                onChange={(event) => setTargetSaEmail(event.target.value)}
                placeholder="scanner@target.iam.gserviceaccount.com"
                className="font-mono"
                required
              />
            </div>
            <div className="flex items-end">
              <Button
                type="submit"
                className="w-full"
                disabled={
                  registerProject.isPending ||
                  !projectId.trim() ||
                  !organizationId ||
                  !targetSaEmail.trim()
                }
              >
                {registerProject.isPending ? (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Plus className="size-3.5" aria-hidden />
                )}
                Register
              </Button>
            </div>
          </form>
        </Panel>
      )}

      <DataTable
        columns={columns}
        data={projects.data}
        isLoading={projects.isLoading}
        error={projects.error}
        errorMessage={errorMessage(projects.error, "Couldn't load projects.")}
        onRetry={() => projects.refetch()}
        searchPlaceholder="Search projects…"
        empty={
          <EmptyState
            icon={FolderGit2}
            title="No projects yet"
            description={
              canRegisterProjects
                ? "Register a GCP project above to make it scannable."
                : "Nothing has been registered under the departments you can access."
            }
          />
        }
      />

      {editingProject && (
        <EditProjectDialog
          project={editingProject}
          organizationOptions={organizationOptions}
          onOpenChange={(open) => !open && setEditingProject(null)}
        />
      )}
    </div>
  );
}
