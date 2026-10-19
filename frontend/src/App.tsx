import { lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AdminRoute, ProtectedRoute } from "@/auth/ProtectedRoute";
import { AppShell } from "@/components/app-shell";
import Login from "@/pages/Login";

// Lazy — every page behind the shell is its own chunk, downloaded on first
// visit rather than bundled into the one ~600KB entry chunk Vite kept
// warning about at every build. Login stays eager: it's the very first
// thing an unauthenticated visitor sees, small on its own, and lazy-loading
// it would just add a network round-trip in front of the sign-in screen for
// no bundle-size benefit anyone actually gets (nothing behind it loads
// until they're signed in anyway). AppShell's own <Suspense> around
// <Outlet /> is what renders while a page's chunk is still downloading.
const Agent = lazy(() => import("@/pages/Agent"));
const AuditLog = lazy(() => import("@/pages/AuditLog"));
const Compliance = lazy(() => import("@/pages/Compliance"));
const ComplianceReport = lazy(() => import("@/pages/ComplianceReport"));
const Reports = lazy(() => import("@/pages/Reports"));
const ReportDetail = lazy(() => import("@/pages/ReportDetail"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Departments = lazy(() => import("@/pages/Departments"));
const Findings = lazy(() => import("@/pages/Findings"));
const FindingDetail = lazy(() => import("@/pages/FindingDetail"));
const FindingsOverview = lazy(() => import("@/pages/FindingsOverview"));
const Organizations = lazy(() => import("@/pages/Organizations"));
const Projects = lazy(() => import("@/pages/Projects"));
const ScanDetail = lazy(() => import("@/pages/ScanDetail"));
const Scans = lazy(() => import("@/pages/Scans"));
const Users = lazy(() => import("@/pages/Users"));

/**
 * Routes are nested under a layout so the shell mounts once and survives
 * navigation. The previous flat registration re-mounted every page's guard
 * and had no shared chrome at all, which is why there was no way back from a
 * screen except the browser's own history.
 */
export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route index element={<Dashboard />} />
          <Route path="projects" element={<Projects />} />
          <Route path="organizations" element={<Organizations />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/:id" element={<FindingDetail />} />
          <Route path="findings-overview" element={<FindingsOverview />} />
          <Route path="agent" element={<Agent />} />
          <Route path="compliance-report" element={<ComplianceReport />} />
          <Route path="reports" element={<Reports />} />
          <Route path="reports/:id" element={<ReportDetail />} />

          <Route path="admin" element={<AdminRoute />}>
            <Route path="departments" element={<Departments />} />
            <Route path="users" element={<Users />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="audit" element={<AuditLog />} />
          </Route>
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
