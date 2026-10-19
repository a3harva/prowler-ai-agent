import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import type {
  AgentMessage,
  AgentSession,
  AgentTurn,
  AuditLogEntry,
  ComplianceFrameworkOption,
  ComplianceReport,
  ComplianceSeedResult,
  Department,
  Finding,
  Organization,
  Project,
  Report,
  ReportMode,
  ReportWithContent,
  Role,
  Scan,
  ScanLog,
  UserWithGrants,
} from "@/api/types";
import { isScanActive, type ScanStatus } from "@/components/scan-state";
import { isReportActive, type ReportStatus } from "@/components/report-state";

/** One key namespace per resource, so a mutation can invalidate exactly what
 *  it affected rather than blowing away the whole cache. */
export const queryKeys = {
  departments: ["departments"] as const,
  organizations: ["organizations"] as const,
  projects: ["projects"] as const,
  users: ["users"] as const,
  scans: ["scans"] as const,
  scan: (id: number) => ["scans", id] as const,
  scanLog: (id: number) => ["scans", id, "log"] as const,
  findings: (projectId?: number) => ["findings", projectId ?? "all"] as const,
  finding: (id: number) => ["findings", "detail", id] as const,
  complianceFrameworks: (projectId?: number) => ["compliance", "frameworks", projectId ?? "none"] as const,
  complianceReport: (projectId?: number, framework?: string, frameworkName?: string, includeMuted?: boolean) =>
    ["compliance", "report", projectId ?? "none", framework ?? "none", frameworkName ?? "none", !!includeMuted] as const,
  reports: ["reports"] as const,
  report: (id: number) => ["reports", id] as const,
  auditLog: ["audit"] as const,
  agentSessions: ["agent", "sessions"] as const,
  agentMessages: (sessionId: number) => ["agent", "sessions", sessionId, "messages"] as const,
};

async function get<T>(url: string): Promise<T> {
  const response = await apiClient.get<T>(url);
  return response.data;
}

// ── departments ──────────────────────────────────────────────────────────
// Readable by any signed-in user and scoped server-side, so every screen can
// resolve a department *name* rather than showing a raw id.

export function useDepartments(enabled = true) {
  return useQuery({
    queryKey: queryKeys.departments,
    queryFn: () => get<Department[]>("/departments"),
    enabled,
  });
}

/** id → name, for the many places a foreign key needs a human label. */
export function useDepartmentNames() {
  const query = useDepartments();
  const lookup = new Map((query.data ?? []).map((d) => [d.id, d.name]));
  return {
    ...query,
    nameFor: (id: number) => lookup.get(id) ?? `Department #${id}`,
  };
}

export function useAddDepartment() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (freshserviceId: string) =>
      apiClient.post("/departments", { freshservice_id: freshserviceId }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.departments }),
  });
}

export function useDeleteDepartment() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiClient.post(`/departments/${id}/delete`),
    onSuccess: () => {
      // Deleting a department changes what organizations and projects are
      // visible, so those listings are stale too.
      queryClient.invalidateQueries({ queryKey: queryKeys.departments });
      queryClient.invalidateQueries({ queryKey: queryKeys.organizations });
      queryClient.invalidateQueries({ queryKey: queryKeys.projects });
    },
  });
}

export function useRefreshDepartment() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiClient.post(`/departments/${id}/refresh`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.departments }),
  });
}

// ── organizations ────────────────────────────────────────────────────────

export function useOrganizations() {
  return useQuery({
    queryKey: queryKeys.organizations,
    queryFn: () => get<Organization[]>("/organizations"),
  });
}

export function useOrganizationNames() {
  const query = useOrganizations();
  const lookup = new Map((query.data ?? []).map((o) => [o.id, o.name]));
  return {
    ...query,
    nameFor: (id: number) => lookup.get(id) ?? `Organization #${id}`,
  };
}

export function useRegisterOrganization() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { org_id: string; name: string; department_id: number }) =>
      apiClient.post("/organizations", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.organizations }),
  });
}

export function useUpdateOrganization() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: { id: number; name: string; department_id: number }) =>
      apiClient.put(`/organizations/${id}`, body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.organizations }),
  });
}

export function useDeleteOrganization() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiClient.post(`/organizations/${id}/delete`),
    onSuccess: () => {
      // Deleting an organization changes what projects are visible too.
      queryClient.invalidateQueries({ queryKey: queryKeys.organizations });
      queryClient.invalidateQueries({ queryKey: queryKeys.projects });
    },
  });
}

// ── projects ─────────────────────────────────────────────────────────────

export function useProjects() {
  return useQuery({
    queryKey: queryKeys.projects,
    queryFn: () => get<Project[]>("/projects"),
  });
}

export function useRegisterProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      project_id: string;
      gcp_organization_id: number;
      target_sa_email: string;
    }) => apiClient.post("/projects", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.projects }),
  });
}

export function useUpdateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...body
    }: {
      id: number;
      gcp_organization_id: number;
      target_sa_email: string;
    }) => apiClient.put(`/projects/${id}`, body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.projects }),
  });
}

export function useDeleteProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiClient.post(`/projects/${id}/delete`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.projects }),
  });
}

// ── scans ────────────────────────────────────────────────────────────────

export function useScans() {
  return useQuery({
    queryKey: queryKeys.scans,
    queryFn: () => get<Scan[]>("/scans"),
  });
}

/** Auto-polls every 3s while the scan is still active (queued/running/
 *  importing), and stops once it reaches a terminal state — closing the tab
 *  doesn't affect the scan, and once it's done there's nothing left to poll
 *  for. `refetch` is exposed directly for the manual-refresh escape hatch. */
export function useScan(id: number | undefined) {
  return useQuery({
    queryKey: queryKeys.scan(id ?? -1),
    queryFn: () => get<Scan>(`/scans/${id}`),
    enabled: id !== undefined,
    refetchInterval: (query) => {
      const status = query.state.data?.status as ScanStatus | undefined;
      return status && isScanActive(status) ? 3000 : false;
    },
  });
}

export function useScanLog(id: number | undefined, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.scanLog(id ?? -1),
    queryFn: () => get<ScanLog>(`/scans/${id}/log`),
    enabled: enabled && id !== undefined,
  });
}

export function useSubmitScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { project_id: number }) => apiClient.post<Scan>("/scans", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.scans }),
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiClient.post<Scan>(`/scans/${id}/cancel`),
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans });
      queryClient.invalidateQueries({ queryKey: queryKeys.scan(id) });
    },
  });
}

// ── compliance ───────────────────────────────────────────────────────────

/** Not a TanStack Query cache entry — the rulebook is shared, project-
 *  independent state with no per-caller data to invalidate; the compliance
 *  report (below) reads live from Postgres on every request regardless, so
 *  there's nothing here for a seed to stale out. This is a one-shot admin
 *  action; its result is read straight from the mutation. */
export function useSeedComplianceRulebook() {
  return useMutation({
    mutationFn: (scanId: number) =>
      apiClient.post<ComplianceSeedResult>("/compliance/seed", { scan_id: scanId }),
  });
}

export function useComplianceFrameworks(projectId?: number) {
  return useQuery({
    queryKey: queryKeys.complianceFrameworks(projectId),
    queryFn: () => get<ComplianceFrameworkOption[]>(`/compliance/frameworks?project_id=${projectId}`),
    enabled: projectId !== undefined,
  });
}

/** The report is a live query on the backend (nothing precomputed) — a page
 *  load or manual navigation back to this screen always recomputes against
 *  current findings, no separate refresh action needed. Within one cached
 *  session the global QueryClient's 30s `staleTime` (main.tsx) still
 *  applies, same as every other list in the app; `useMuteFinding` /
 *  `useMuteByCheck` invalidate the `["compliance"]` prefix on top of
 *  `["findings"]` specifically so muting from this page's own drill-through
 *  doesn't leave a stale score cached for that window. */
export function useComplianceReport(
  projectId: number | undefined,
  framework: string | undefined,
  frameworkName: string | undefined,
  includeMuted: boolean,
) {
  return useQuery({
    queryKey: queryKeys.complianceReport(projectId, framework, frameworkName, includeMuted),
    queryFn: () =>
      get<ComplianceReport>(
        `/compliance/report?project_id=${projectId}&framework=${encodeURIComponent(framework!)}` +
          `&framework_name=${encodeURIComponent(frameworkName!)}&include_muted=${includeMuted}`,
      ),
    enabled: projectId !== undefined && !!framework && !!frameworkName,
  });
}

// ── findings ─────────────────────────────────────────────────────────────

export function useFindings(projectId?: number) {
  return useQuery({
    queryKey: queryKeys.findings(projectId),
    queryFn: () =>
      get<Finding[]>(projectId ? `/findings?project_id=${projectId}` : "/findings"),
  });
}

export function useFinding(id: number | undefined) {
  return useQuery({
    queryKey: queryKeys.finding(id ?? -1),
    queryFn: () => get<Finding>(`/findings/${id}`),
    enabled: id !== undefined,
  });
}

export function useUpdateFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...body
    }: {
      id: number;
      muted: boolean;
      mute_reason: string | null;
      note: string | null;
    }) => apiClient.patch<Finding>(`/findings/${id}`, body),
    // Prefix match — invalidates every findings list regardless of which
    // project filter it was fetched under, since we don't know from here
    // which lists this finding appears in. Also invalidates the compliance
    // report/frameworks queries: they roll up finding status, and without
    // this a mute made from the report's own drill-through would leave a
    // stale score cached for up to the query's staleTime.
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance"] });
    },
  });
}

export function useMuteByCheck() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      project_id: number;
      check_id: string;
      mute_reason: string;
      note: string | null;
    }) => apiClient.post<{ muted_count: number }>("/findings/mute-by-check", body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance"] });
    },
  });
}

// ── users and grants ─────────────────────────────────────────────────────

export function useUsers(enabled = true) {
  return useQuery({
    queryKey: queryKeys.users,
    queryFn: () => get<UserWithGrants[]>("/users"),
    enabled,
  });
}

// ── audit log ────────────────────────────────────────────────────────────
// Admin-only, fetched once and filtered client-side (user, action type,
// target type, date range) — same shape as the findings table: at the
// volumes this trail runs at, one fetch plus in-browser filtering is
// instant, and the server-side filter params `services/audit.py` exposes
// stay there for direct API use rather than being wired through here.

export function useAuditLog() {
  return useQuery({
    queryKey: queryKeys.auditLog,
    queryFn: () => get<AuditLogEntry[]>("/audit"),
  });
}

export function useGrantRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { email: string; department_id: number; role: Role }) =>
      apiClient.post("/users", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.users }),
  });
}

export function useChangeRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      userId,
      departmentId,
      role,
    }: {
      userId: number;
      departmentId: number;
      role: Role;
    }) => apiClient.put(`/users/${userId}/roles/${departmentId}`, { role }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.users }),
  });
}

export function useRemoveRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, departmentId }: { userId: number; departmentId: number }) =>
      apiClient.delete(`/users/${userId}/roles/${departmentId}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.users }),
  });
}

export function useSetPassword() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { email: string; password: string }) => apiClient.post("/users/password", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.users }),
  });
}

// ── password login ──────────────────────────────────────────────────────

export function useLocalLogin() {
  return useMutation({
    mutationFn: (body: { email: string; password: string }) =>
      apiClient.post("/auth/login-local", body),
  });
}

// ── reports ──────────────────────────────────────────────────────────────
// Readable by any signed-in user and scoped server-side, like scans.

/** Polls every 3s while any report in the list is still queued or generating,
 *  and stops once they are all terminal. One poll for the whole page rather
 *  than one per row — the list endpoint is a single cheap query, and a report
 *  finishes in minutes, so per-row polling would buy nothing. */
export function useReports() {
  return useQuery({
    queryKey: queryKeys.reports,
    queryFn: () => get<Report[]>("/reports"),
    refetchInterval: (query) =>
      (query.state.data ?? []).some((r) => isReportActive(r.status as ReportStatus))
        ? 3000
        : false,
  });
}

/** The full document, fetched only when a report is actually opened. */
export function useReport(id: number | undefined) {
  return useQuery({
    queryKey: queryKeys.report(id ?? -1),
    queryFn: () => get<ReportWithContent>(`/reports/${id}`),
    enabled: id !== undefined,
  });
}

export function useSubmitReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      project_id: number;
      include_muted: boolean;
      mode?: ReportMode;
      instructions?: string | null;
    }) => apiClient.post<Report>("/reports", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.reports }),
  });
}

/** Human correction of a completed report's text. Clears the server's stored
 *  PDF (see `services/reports.py::update_report_content`), so the response is
 *  written straight into the cache — a refetch would otherwise flash the old
 *  content before the invalidated query resolves. */
export function useUpdateReportContent(id: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (content: string) =>
      apiClient.patch<ReportWithContent>(`/reports/${id}`, { content }),
    onSuccess: (response) => {
      queryClient.setQueryData(queryKeys.report(id), response.data);
      queryClient.invalidateQueries({ queryKey: queryKeys.reports });
    },
  });
}

// ── agent chat ────────────────────────────────────────────────────────────
// A turn can take ten to twenty seconds — the model may call several tools
// before answering — so these mutations set no retry and the caller shows a
// thinking state rather than a spinner-free wait.

export function useAgentSessions() {
  return useQuery({
    queryKey: queryKeys.agentSessions,
    queryFn: () => get<AgentSession[]>("/agent/sessions"),
  });
}

export function useAgentMessages(sessionId: number | undefined) {
  return useQuery({
    queryKey: queryKeys.agentMessages(sessionId ?? -1),
    queryFn: () => get<AgentMessage[]>(`/agent/sessions/${sessionId}/messages`),
    enabled: sessionId !== undefined,
  });
}

export function useCreateAgentSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (projectId: number) =>
      (await apiClient.post<AgentSession>("/agent/sessions", { project_id: projectId })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.agentSessions }),
  });
}

/** The session id travels **with the call**, not captured from a hook
 *  argument. A conversation's first message creates its session and sends in
 *  the same handler, so a hook closing over `sessionId` state would still hold
 *  the pre-render `undefined` and post to `/agent/sessions/undefined/messages`
 *  — which is exactly what it did before this shape. */
export function useSendAgentMessage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ sessionId, message }: { sessionId: number; message: string }) =>
      (await apiClient.post<AgentTurn>(`/agent/sessions/${sessionId}/messages`, { message }))
        .data,
    retry: false,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agentSessions });
      queryClient.invalidateQueries({
        queryKey: queryKeys.agentMessages(variables.sessionId),
      });
    },
  });
}

/** Carries the action id and nothing else — deliberately. The arguments live
 *  on the stored row server-side, so the change that executes is byte-for-byte
 *  the one the banner described. Sending them back from here would make the
 *  confirmation decorative. */
export function useApplyAgentAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (actionId: number) =>
      (await apiClient.post<{ result: Record<string, unknown> }>(
        `/agent/actions/${actionId}/apply`,
      )).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}

export function useDiscardAgentAction() {
  return useMutation({
    mutationFn: async (actionId: number) =>
      (await apiClient.post<{ result: Record<string, unknown> }>(
        `/agent/actions/${actionId}/discard`,
      )).data,
  });
}
