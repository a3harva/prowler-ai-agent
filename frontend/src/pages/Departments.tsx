import { useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Building2, LoaderCircle, Plus, RefreshCw, Trash2 } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable, MonoCell } from "@/components/data-table";
import { EmptyState } from "@/components/states";
import { useStatus } from "@/components/status-region";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorMessage } from "@/api/client";
import type { Department } from "@/api/types";
import {
  useAddDepartment,
  useDeleteDepartment,
  useDepartments,
  useRefreshDepartment,
} from "@/hooks/queries";
import { formatTimestamp } from "@/lib/format";

export default function Departments() {
  const departments = useDepartments();
  const status = useStatus();

  const [freshserviceId, setFreshserviceId] = useState("");

  const addDepartment = useAddDepartment();
  const deleteDepartment = useDeleteDepartment();
  const refreshDepartment = useRefreshDepartment();

  const handleAdd = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      await addDepartment.mutateAsync(freshserviceId.trim());
      setFreshserviceId("");
      status.succeed(`Department ${freshserviceId.trim()} added from Freshservice.`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't add that department."));
    }
  };

  const handleRefresh = async (department: Department) => {
    try {
      await refreshDepartment.mutateAsync(department.id);
      status.succeed(`Refreshed ${department.name} from Freshservice.`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't refresh from Freshservice."));
    }
  };

  const handleDelete = async (department: Department) => {
    try {
      await deleteDepartment.mutateAsync(department.id);
      status.succeed(`Deleted ${department.name}.`);
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't delete that department."));
    }
  };

  const columns: ColumnDef<Department, any>[] = [
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ row }) => (
        <span className="font-medium text-ink">{row.original.name}</span>
      ),
    },
    {
      accessorKey: "freshservice_id",
      header: "Freshservice ID",
      cell: ({ row }) => <MonoCell>{row.original.freshservice_id}</MonoCell>,
    },
    {
      accessorKey: "domains",
      header: "Domains",
      cell: ({ row }) => {
        const domains = row.original.domains;
        if (domains.length === 0) {
          return <span className="text-sm text-ink-muted">None in Freshservice</span>;
        }
        return (
          <div className="flex flex-wrap gap-1">
            {domains.map((domain) => (
              <span
                key={domain}
                className="rounded border border-hairline bg-subtle px-1.5 py-0.5 font-mono text-[11px] text-ink-secondary"
              >
                {domain}
              </span>
            ))}
          </div>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: "Added",
      cell: ({ row }) => (
        <span className="text-sm text-ink-muted">{formatTimestamp(row.original.created_at)}</span>
      ),
    },
    {
      id: "actions",
      header: "",
      enableSorting: false,
      cell: ({ row }) => {
        const department = row.original;
        const refreshing =
          refreshDepartment.isPending && refreshDepartment.variables === department.id;
        const deleting =
          deleteDepartment.isPending && deleteDepartment.variables === department.id;
        return (
          <div className="flex justify-end gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleRefresh(department)}
              disabled={refreshing}
            >
              {refreshing ? (
                <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
              ) : (
                <RefreshCw className="size-3.5" aria-hidden />
              )}
              Refresh
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleDelete(department)}
              disabled={deleting}
            >
              <Trash2 className="size-3.5" aria-hidden />
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
        title="departments"
        description="Departments are onboarded from Freshservice by ID — never typed in by hand, so the name and its domains always match the source of truth."
      />

      <Panel>
        <form onSubmit={handleAdd} className="flex flex-wrap items-end gap-3">
          <div className="min-w-0 flex-1 space-y-1.5 sm:max-w-xs">
            <Label htmlFor="freshservice-id">Freshservice department ID</Label>
            <Input
              id="freshservice-id"
              value={freshserviceId}
              onChange={(event) => setFreshserviceId(event.target.value)}
              placeholder="e.g. 42"
              required
            />
          </div>
          <Button type="submit" disabled={addDepartment.isPending || !freshserviceId.trim()}>
            {addDepartment.isPending ? (
              <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
            ) : (
              <Plus className="size-3.5" aria-hidden />
            )}
            Add department
          </Button>
        </form>
      </Panel>

      <DataTable
        columns={columns}
        data={departments.data}
        isLoading={departments.isLoading}
        error={departments.error}
        errorMessage={errorMessage(departments.error, "Couldn't load departments.")}
        onRetry={() => departments.refetch()}
        searchPlaceholder="Search departments…"
        empty={
          <EmptyState
            icon={Building2}
            title="No departments yet"
            description="Add one by its Freshservice ID above. Everything else in the product — organizations, projects, scans — hangs off a department."
          />
        }
      />
    </div>
  );
}
