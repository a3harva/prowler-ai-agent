import type { CurrentUser, Role } from "@/api/types";

/** Mirrors `services/rbac.py::_ROLE_ORDER`. Admin is additive over editor
 *  over viewer — they are a ladder, not separate silos. */
const ROLE_ORDER: Record<Role, number> = { viewer: 0, editor: 1, admin: 2 };

export interface Permissions {
  /** Global admin. The only thing `require_admin` accepts on the server, so
   *  it is the only thing that may reveal admin-only screens here. */
  isGlobalAdmin: boolean;
  /** The user's role on a department, or null. A global admin resolves to
   *  "admin" everywhere without needing a row. */
  roleFor: (departmentId: number | null | undefined) => Role | null;
  hasAtLeast: (departmentId: number | null | undefined, minimum: Role) => boolean;
  canView: (departmentId: number | null | undefined) => boolean;
  canEdit: (departmentId: number | null | undefined) => boolean;
  /** Department Admin has full control of that department, including
   *  managing its projects — not just the global bootstrap admin. */
  canManageProjects: (departmentId: number | null | undefined) => boolean;
  /** Departments the user holds any grant on. Empty for a global admin,
   *  who sees everything — check `isGlobalAdmin` before reading this. */
  grantedDepartmentIds: number[];
  /** Departments the user holds at least `minimum` on. Empty for a global
   *  admin, who administers everything — check `isGlobalAdmin` first. */
  departmentIdsWithAtLeast: (minimum: Role) => number[];
}

/** The server refuses what it refuses regardless of what this returns.
 *  This exists so a Viewer never sees a control that would 403; unavailable
 *  controls should be absent, not merely rejected on click. */
export function buildPermissions(user: CurrentUser | null): Permissions {
  const isGlobalAdmin = user?.is_bootstrap_admin ?? false;
  const grants = user?.grants ?? [];
  const byDepartment = new Map(grants.map((g) => [g.department_id, g.role]));

  const roleFor = (departmentId: number | null | undefined): Role | null => {
    if (isGlobalAdmin) return "admin";
    if (departmentId === null || departmentId === undefined) return null;
    return byDepartment.get(departmentId) ?? null;
  };

  const hasAtLeast = (departmentId: number | null | undefined, minimum: Role) => {
    const role = roleFor(departmentId);
    return role !== null && ROLE_ORDER[role] >= ROLE_ORDER[minimum];
  };

  return {
    isGlobalAdmin,
    roleFor,
    hasAtLeast,
    canView: (departmentId) => hasAtLeast(departmentId, "viewer"),
    canEdit: (departmentId) => hasAtLeast(departmentId, "editor"),
    canManageProjects: (departmentId) => hasAtLeast(departmentId, "admin"),
    grantedDepartmentIds: grants.map((g) => g.department_id),
    departmentIdsWithAtLeast: (minimum) =>
      grants.filter((g) => ROLE_ORDER[g.role] >= ROLE_ORDER[minimum]).map((g) => g.department_id),
  };
}
