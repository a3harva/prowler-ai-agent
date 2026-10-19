import { useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { KeyRound, LoaderCircle, Plus, UserPlus, X } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/states";
import { useStatus } from "@/components/status-region";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Combobox } from "@/components/combobox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { errorMessage } from "@/api/client";
import type { Role, UserWithGrants } from "@/api/types";
import {
  useChangeRole,
  useDepartmentNames,
  useGrantRole,
  useRemoveRole,
  useSetPassword,
  useUsers,
} from "@/hooks/queries";
import { formatRelative, formatTimestamp } from "@/lib/format";

const ROLES: Role[] = ["viewer", "editor", "admin"];

const ROLE_LABELS: Record<Role, string> = {
  viewer: "Viewer",
  editor: "Editor",
  admin: "Admin",
};

const ROLE_HINTS: Record<Role, string> = {
  viewer: "Read-only: can view findings and export, but change nothing.",
  editor: "Can submit scans and triage findings within the department.",
  admin: "Full control of the department. Not global administrator.",
};

export default function Users() {
  const users = useUsers();
  const departments = useDepartmentNames();
  const status = useStatus();

  const [email, setEmail] = useState("");
  const [departmentId, setDepartmentId] = useState<string>("");
  const [role, setRole] = useState<Role>("viewer");

  const grantRole = useGrantRole();
  const changeRole = useChangeRole();
  const removeRole = useRemoveRole();
  const setPassword = useSetPassword();

  const [passwordTarget, setPasswordTarget] = useState<UserWithGrants | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [passwordFormError, setPasswordFormError] = useState<string | null>(null);

  const handleSetPassword = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!passwordTarget) return;
    setPasswordFormError(null);
    try {
      await setPassword.mutateAsync({ email: passwordTarget.email, password: newPassword });
      status.succeed(
        `${passwordTarget.has_password ? "Reset" : "Set"} password for ${passwordTarget.email}.`,
      );
      setPasswordTarget(null);
      setNewPassword("");
    } catch (error) {
      setPasswordFormError(errorMessage(error, "Couldn't set that password."));
    }
  };

  const handleGrant = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!departmentId) return;
    try {
      await grantRole.mutateAsync({
        email: email.trim(),
        department_id: Number(departmentId),
        role,
      });
      const granted = email.trim();
      setEmail("");
      setDepartmentId("");
      setRole("viewer");
      status.succeed(
        `Granted ${ROLE_LABELS[role]} on ${departments.nameFor(Number(departmentId))} to ${granted}.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't grant that role."));
    }
  };

  const handleChangeRole = async (
    user: UserWithGrants,
    grantDepartmentId: number,
    nextRole: Role,
  ) => {
    try {
      await changeRole.mutateAsync({
        userId: user.id,
        departmentId: grantDepartmentId,
        role: nextRole,
      });
      status.succeed(
        `${user.email} is now ${ROLE_LABELS[nextRole]} on ${departments.nameFor(grantDepartmentId)}.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't change that role."));
    }
  };

  const handleRemoveRole = async (user: UserWithGrants, grantDepartmentId: number) => {
    try {
      await removeRole.mutateAsync({ userId: user.id, departmentId: grantDepartmentId });
      status.succeed(
        `Removed ${user.email}'s access to ${departments.nameFor(grantDepartmentId)}.`,
      );
    } catch (error) {
      status.fail(errorMessage(error, "Couldn't remove that role."));
    }
  };

  const columns: ColumnDef<UserWithGrants, any>[] = [
    {
      accessorKey: "email",
      header: "User",
      cell: ({ row }) => (
        <div className="min-w-0 space-y-0.5">
          <p className="truncate text-sm font-medium text-ink">{row.original.name}</p>
          <p className="truncate font-mono text-xs text-ink-muted">{row.original.email}</p>
        </div>
      ),
    },
    {
      accessorKey: "last_login_at",
      header: "Last signed in",
      cell: ({ row }) => {
        const value = row.original.last_login_at;
        return (
          <div className="space-y-0.5">
            <p className="text-sm text-ink-secondary">{formatRelative(value)}</p>
            {value && (
              <p className="font-mono text-[11px] text-ink-muted">{formatTimestamp(value)}</p>
            )}
          </div>
        );
      },
    },
    {
      id: "grants",
      header: "Department access",
      enableSorting: false,
      cell: ({ row }) => {
        const user = row.original;
        if (user.grants.length === 0) {
          return (
            <span className="text-sm text-ink-muted">
              No access — signed in but sees nothing
            </span>
          );
        }
        return (
          <div className="space-y-1.5">
            {user.grants.map((grant) => (
              <div key={grant.department_id} className="flex flex-wrap items-center gap-2">
                <span className="min-w-32 text-sm text-ink-secondary">
                  {departments.nameFor(grant.department_id)}
                </span>
                <Combobox
                  value={grant.role}
                  onValueChange={(next) =>
                    handleChangeRole(user, grant.department_id, next as Role)
                  }
                  options={ROLES.map((r) => ({
                    value: r,
                    label: ROLE_LABELS[r],
                  }))}
                  className="w-28"
                  size="sm"
                />
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={() => handleRemoveRole(user, grant.department_id)}
                >
                  <X className="size-3.5" aria-hidden />
                  <span className="sr-only">
                    Remove access to {departments.nameFor(grant.department_id)}
                  </span>
                </Button>
              </div>
            ))}
          </div>
        );
      },
    },
    {
      id: "password",
      header: "Password login",
      enableSorting: false,
      cell: ({ row }) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            setPasswordTarget(row.original);
            setNewPassword("");
            setPasswordFormError(null);
          }}
        >
          <KeyRound className="size-3.5" aria-hidden />
          {row.original.has_password ? "Reset password" : "Set password"}
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="users & roles"
        description="Access is granted per person, per department. There is no invitation to accept — a grant is live the moment that person first signs in with their prowler agent account."
      />

      <Panel>
        <form onSubmit={handleGrant} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="space-y-1.5">
            <Label htmlFor="grant-email">Email</Label>
            <Input
              id="grant-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="person@example.test"
              className="font-mono"
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="grant-department">Department</Label>
            <Combobox
              id="grant-department"
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
          <div className="space-y-1.5">
            <Label htmlFor="grant-role">Role</Label>
            <Combobox
              id="grant-role"
              value={role}
              onValueChange={(next) => setRole(next as Role)}
              options={ROLES.map((r) => ({
                value: r,
                label: ROLE_LABELS[r],
              }))}
              className="w-full"
            />
          </div>
          <div className="flex items-end">
            <Button
              type="submit"
              className="w-full"
              disabled={grantRole.isPending || !email.trim() || !departmentId}
            >
              {grantRole.isPending ? (
                <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
              ) : (
                <Plus className="size-3.5" aria-hidden />
              )}
              Grant role
            </Button>
          </div>
          <p className="text-xs leading-relaxed text-ink-muted sm:col-span-2 lg:col-span-4">
            {ROLE_HINTS[role]}
          </p>
        </form>
      </Panel>

      <DataTable
        columns={columns}
        data={users.data}
        isLoading={users.isLoading}
        error={users.error}
        errorMessage={errorMessage(users.error, "Couldn't load users.")}
        onRetry={() => users.refetch()}
        searchPlaceholder="Search by name or email…"
        skeletonColumns={3}
        empty={
          <EmptyState
            icon={UserPlus}
            title="No users yet"
            description="Grant someone a role above. They will have access the first time they sign in — nothing to accept, nothing to verify."
          />
        }
      />

      <Dialog open={passwordTarget !== null} onOpenChange={(open) => !open && setPasswordTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {passwordTarget?.has_password ? "Reset password" : "Set password"} for{" "}
              {passwordTarget?.email}
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSetPassword} className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="new-password">New password</Label>
              <Input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                autoComplete="new-password"
                minLength={12}
                required
              />
              <p className="text-xs text-ink-muted">At least 12 characters.</p>
            </div>
            {passwordFormError && (
              <p className="text-sm text-status-fail">{passwordFormError}</p>
            )}
            <DialogFooter>
              <Button type="submit" disabled={setPassword.isPending}>
                {setPassword.isPending && (
                  <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
                )}
                Save
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
