/** Wire types, mirroring `backend/app/schemas/`. Kept in one file so a
 *  backend schema change has a single place to land on this side. */

export type Role = "viewer" | "editor" | "admin";

export interface DepartmentGrant {
  department_id: number;
  role: Role;
}

export interface CurrentUser {
  email: string;
  name: string;
  /** Global admin, from BOOTSTRAP_ADMIN_EMAILS. Additive over every grant.
   *  A department-level `admin` grant appears in `grants` and does NOT set
   *  this — it confers department-scoped rights only, matching
   *  `deps.py::require_admin`, which checks this flag alone. */
  is_bootstrap_admin: boolean;
  grants: DepartmentGrant[];
}

export interface Department {
  id: number;
  freshservice_id: string;
  name: string;
  domains: string[];
  deleted: boolean;
  created_at: string;
}

export interface Organization {
  id: number;
  org_id: string;
  name: string;
  department_id: number;
  deleted: boolean;
}

export interface Project {
  id: number;
  project_id: string;
  gcp_organization_id: number;
  target_sa_email: string;
  deleted: boolean;
  created_at: string;
}

export interface Scan {
  id: number;
  project_id: number;
  status: string;
  triggered_by_user_id: number;
  triggered_at: string;
  started_at: string | null;
  completed_at: string | null;
  pass_count: number | null;
  fail_count: number | null;
  exit_code: number | null;
  error_message: string | null;
  /** Computed at read time — `running` well past SCAN_TIMEOUT_SECONDS,
   *  almost always because the worker that owned it crashed. */
  stale: boolean;
  /** Set by the importer when this scan's own inline COMPLIANCE mappings
   *  didn't match the loaded rulebook — usually a Prowler upgrade nobody
   *  re-seeded the rulebook for. */
  compliance_drift_detected: boolean;
}

export interface ScanLog {
  scan_id: number;
  log: string;
}

export interface ComplianceSeedResult {
  framework_count: number;
  requirement_count: number;
  prowler_version: string;
  frameworks: string[];
}

export interface ComplianceFrameworkOption {
  framework: string;
  framework_name: string;
  /** How many of this framework's distinct mapped checks have a finding in
   *  the project it was requested for — the live "most-used" ranking. */
  match_count: number;
}

export type ComplianceRequirementStatus = "pass" | "fail" | "needs_review" | "not_assessed";

export interface ComplianceRequirementResult {
  requirement_id: string;
  requirement_description: string | null;
  check_ids: string[];
  status: ComplianceRequirementStatus;
}

export interface ComplianceReportSummary {
  passed: number;
  failed: number;
  needs_review: number;
  not_assessed: number;
  total_requirements: number;
  /** null when passed + failed === 0 — nothing to score, never a
   *  misleadingly perfect 100%. */
  score_percent: number | null;
}

export interface ComplianceReport {
  framework: string;
  framework_name: string;
  summary: ComplianceReportSummary;
  requirements: ComplianceRequirementResult[];
}

export interface Finding {
  id: number;
  project_id: number;
  check_id: string;
  resource_uid: string;
  finding_uid: string;
  check_title: string;
  severity: string;
  status: string;
  status_extended: string | null;
  region: string;
  muted: boolean;
  mute_reason: string | null;
  note: string | null;
  service_name: string;
  subservice_name: string | null;
  resource_type: string;
  resource_name: string;
  last_scan_id: number;
  first_seen_at: string;
  updated_at: string;
}

export interface UserWithGrants {
  id: number;
  email: string;
  name: string;
  created_at: string;
  last_login_at: string | null;
  has_password: boolean;
  grants: DepartmentGrant[];
}

export interface AuditLogEntry {
  id: number;
  user_id: number;
  actor_email: string;
  actor_name: string;
  action_type: string;
  target_type: string;
  target_id: string;
  before_value: Record<string, unknown> | null;
  after_value: Record<string, unknown> | null;
  timestamp: string;
}

/** Which pipeline wrote a report's prose.
 *
 *  `standard` is one model call per pillar. `deep` runs the LangGraph agent,
 *  which investigates with tools before writing and adds Key Themes and a
 *  Remediation Plan. Both render the *same facts* — the backend's ledger
 *  guarantees the check sections and counts are identical — so this is a
 *  provenance label, not a warning. */
export type ReportMode = "standard" | "deep";

export interface Report {
  id: number;
  project_id: number;
  scan_id: number;
  task_reference_id: string;
  status: "queued" | "generating" | "completed" | "failed";
  mode: ReportMode;
  requested_by_user_id: number;
  include_muted: boolean;
  has_pdf: boolean;
  error_message: string | null;
  skipped_finding_count: number;
  unknown_category_count: number;
  created_at: string;
  completed_at: string | null;
  content_edited_at: string | null;
}

/** One deterministic gate's finding. Mirrors
 *  `backend/app/agents/report_ledger.py::GateFailure`. */
export interface ReportGateFailure {
  gate: string;
  detail: string;
  repair_targets: string[];
}

/** What the gates checked on this document, and what they found. Present on
 *  `deep` reports only — a record that the counts were verified rather than
 *  assumed. */
export interface ReportVerification {
  gates_run?: string[];
  passed?: boolean;
  failures?: ReportGateFailure[];
  document_passed?: boolean;
  document_problems?: string[];
  revision?: number;
}

/** The reviewing pass's verdict. Advisory — recorded, never obeyed, the same
 *  posture as `format_warnings`. */
export interface ReportCritique {
  verdict: "accept" | "revise";
  confidence: "high" | "medium" | "low";
  assessment: string;
  issues: { severity: "blocking" | "advisory"; target: string; problem: string }[];
}

/** Only the single-report endpoint carries `content` — the list endpoint omits
 *  it so a page showing twenty reports doesn't ship twenty full documents. */
export interface ReportWithContent extends Report {
  content: string | null;
  instructions: string | null;
  verification: ReportVerification | null;
  critique: ReportCritique | null;
}

// ── agent chat ────────────────────────────────────────────────────────────
// A session is bound to one project at creation and can never be repointed —
// mirroring `backend/app/models/agent.py`. There is deliberately no way to
// change `project_id` on an existing session from this client, because there
// is no endpoint that would accept it.

export interface AgentSession {
  id: number;
  project_id: number;
  title: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentMessage {
  id: number;
  role: "user" | "assistant" | "tool";
  content: string | null;
  tool_name: string | null;
  tool_args: Record<string, unknown> | null;
  tool_result: Record<string, unknown> | null;
  created_at: string;
}

/** What the confirmation banner renders. Built server-side at proposal time
 *  from the same validated arguments that will execute, so what is described
 *  and what happens cannot drift. */
export interface PendingActionSummary {
  action: string;
  check_id?: string;
  check_title?: string;
  severity?: string;
  resource_name?: string;
  mute_reason?: string;
  current_mute_reason?: string | null;
  previous_note?: string | null;
  note?: string | null;
  affected_count: number;
  sample_resources?: string[];
}

export interface PendingAction {
  id: number;
  tool_name: string;
  summary: PendingActionSummary;
  status: string;
  expires_at: string;
}

export interface AgentToolCall {
  name: string;
  args: Record<string, unknown>;
  result: Record<string, unknown>;
}

export interface AgentTurn {
  answer: string;
  tool_calls: AgentToolCall[];
  pending_actions: PendingAction[];
}
