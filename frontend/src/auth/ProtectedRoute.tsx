import type { ReactNode } from "react";
import { Navigate, Outlet } from "react-router-dom";
import { LoaderCircle } from "lucide-react";
import { useAuth } from "@/auth/AuthContext";
import { EmptyState } from "@/components/states";
import { ShieldAlert } from "lucide-react";

function FullPageLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center" role="status">
      <LoaderCircle className="size-5 animate-spin text-action" aria-hidden />
      <span className="sr-only">Loading</span>
    </div>
  );
}

/** Used as a layout route, so the shell mounts once rather than per page. */
export function ProtectedRoute({ children }: { children?: ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) return <FullPageLoader />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children ?? <Outlet />}</>;
}

/**
 * Global-admin gate for whole screens.
 *
 * This hides the screen; the server refuses the data regardless. Both must
 * hold — a hidden button and an unenforced endpoint is not access control,
 * and an enforced endpoint with a visible button is a bad interface.
 */
export function AdminRoute({ children }: { children?: ReactNode }) {
  const { permissions } = useAuth();

  if (!permissions.isGlobalAdmin) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="Administrator access required"
        description="This screen manages every department. Ask an administrator if you need access to it."
      />
    );
  }
  return <>{children ?? <Outlet />}</>;
}
