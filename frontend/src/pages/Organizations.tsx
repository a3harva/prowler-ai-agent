import { useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Building2, LoaderCircle, Pencil, Plus, Trash2 } from "lucide-react";
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
import type { Organization } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import {
  useDeleteOrganization,
  useDepartmentNames,
  useOrganizations,
  useRegisterOrganization,
  useUpdateOrganization,
} from "@/hooks/queries";

function EditOrganizationDialog({
  organization,
  onOpenChange,
}: {
  organization: Organization;
  onOpenChange: (open: boolean) => void;
}) {
  const departments = useDepartmentNames();
  const updateOrganization = useUpdateOrganization();
  const status = useStatus();

  const [name, setName] = useState(organization.name);
  const [departmentId, setDepartmentId] = useState(String(organization.department_id));

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      await updateOrganization.mutateAsync({
        id: organization.id,
        name: name.trim(),
        department_id: Number(departmentId),
      });
      status.succeed(`Updated ${organization.org_id}.`);
      onOpenChange(false);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't update that organization."));
    }
  };

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit organization</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label>GCP organization ID</Label>
            {/* Immutable — the GCP identifier can't change once registered.
                Shown as read-only text, not an input. */}
            <p className="rounded-md border border-hairline bg-subtle px-3 py-2 font-mono text-sm text-ink-secondary">
              {organization.org_id}
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edit-org-name">Name</Label>
            <Input
              id="edit-org-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edit-org-department">Department</Label>
            <Combobox
              id="edit-org-department"
              value={departmentId}
              onValueChange={setDepartmentId}
              options={(departments.data ?? []).map((department) => ({
                value: String(department.id),
                label: department.name,
              }))}
              placeholder="Select a department"
              searchPlaceholder="Search departments…"
              emptyMessage="No departments match."
              className="w-full"
            />
          </div>
          <DialogFooter>
            <Button
              type="submit"
              disabled={updateOrganization.isPending || !name.trim() || !departmentId}
            >
              {updateOrganization.isPending && (
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

export default function Organizations() {
  const { permissions } = useAuth();
  const organizations = useOrganizations();
  // Now readable by any signed-in user and scoped server-side, so a non-admin
  // finally sees department *names* here instead of a raw id.
  const departments = useDepartmentNames();
  const status = useStatus();

  const [orgId, setOrgId] = useState("");
  const [name, setName] = useState("");
  const [departmentId, setDepartmentId] = useState<string>("");
  const [editingOrganization, setEditingOrganization] = useState<Organization | null>(null);

  const registerOrganization = useRegisterOrganization();
  const deleteOrganization = useDeleteOrganization();

  const handleRegister = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!departmentId) return;
    try {
      await registerOrganization.mutateAsync({
        org_id: orgId.trim(),
        name: name.trim(),
        department_id: Number(departmentId),
      });
      setOrgId("");
      setName("");
      setDepartmentId("");
      status.succeed(`Registered ${name.trim()}.`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't register that organization."));
    }
  };

  const handleDelete = async (organization: Organization) => {
    try {
      await deleteOrganization.mutateAsync(organization.id);
      status.succeed(
        `Deleted ${organization.name}. Registering the same ID again is fine — it starts as a new record.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't delete that organization."));
    }
  };

  const columns: ColumnDef<Organization, any>[] = [
    {
      accessorKey: "name",
      header: "Organization",
      cell: ({ row }) => (
        <span className="font-medium text-ink">{row.original.name}</span>
      ),
    },
    {
      accessorKey: "org_id",
      header: "GCP org ID",
      cell: ({ row }) => <CopyableUid value={row.original.org_id} max={28} />,
    },
    {
      accessorKey: "department_id",
      header: "Department",
      cell: ({ row }) => (
        <span className="text-sm text-ink-secondary">
          {departments.nameFor(row.original.department_id)}
        </span>
      ),
    },
    ...(permissions.isGlobalAdmin
      ? [
          {
            id: "actions",
            header: "",
            enableSorting: false,
            cell: ({ row }) => {
              const organization = row.original;
              const deleting =
                deleteOrganization.isPending && deleteOrganization.variables === organization.id;
              return (
                <div className="flex justify-end gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setEditingOrganization(organization)}
                  >
                    <Pencil className="size-3.5" aria-hidden />
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDelete(organization)}
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
          } satisfies ColumnDef<Organization, any>,
        ]
      : []),
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="organizations"
        description="GCP organizations, each belonging to a department. One department can span several — a customer is not guaranteed to be a single organization."
      />

      {permissions.isGlobalAdmin && (
        <Panel>
          <form onSubmit={handleRegister} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="space-y-1.5">
              <Label htmlFor="org-name">Name</Label>
              <Input
                id="org-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Sample Organization"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org-id">GCP organization ID</Label>
              <Input
                id="org-id"
                value={orgId}
                onChange={(event) => setOrgId(event.target.value)}
                placeholder="synthetic-organization-id"
                className="font-mono"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org-department">Department</Label>
              <Combobox
                id="org-department"
                value={departmentId}
                onValueChange={setDepartmentId}
                options={(departments.data ?? []).map((department) => ({
                  value: String(department.id),
                  label: department.name,
                }))}
                placeholder="Select a department"
                searchPlaceholder="Search departments…"
                emptyMessage="No departments match."
                className="w-full"
              />
            </div>
            <div className="flex items-end">
              <Button
                type="submit"
                className="w-full"
                disabled={
                  registerOrganization.isPending || !orgId.trim() || !name.trim() || !departmentId
                }
              >
                {registerOrganization.isPending ? (
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
        data={organizations.data}
        isLoading={organizations.isLoading}
        error={organizations.error}
        errorMessage={errorMessage(organizations.error, "Couldn't load organizations.")}
        onRetry={() => organizations.refetch()}
        searchPlaceholder="Search organizations…"
        empty={
          <EmptyState
            icon={Building2}
            title="No organizations yet"
            description={
              permissions.isGlobalAdmin
                ? "Register one above. A project has to belong to an organization before it can be scanned."
                : "Nothing has been registered under the departments you can access."
            }
          />
        }
      />

      {editingOrganization && (
        <EditOrganizationDialog
          organization={editingOrganization}
          onOpenChange={(open) => !open && setEditingOrganization(null)}
        />
      )}
    </div>
  );
}
