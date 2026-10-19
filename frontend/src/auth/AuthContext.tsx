import { createContext, useContext, useMemo, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import type { CurrentUser } from "@/api/types";
import { buildPermissions, type Permissions } from "@/lib/permissions";

interface AuthState {
  user: CurrentUser | null;
  loading: boolean;
  permissions: Permissions;
  refetch: () => Promise<unknown>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export const currentUserQueryKey = ["auth", "me"] as const;

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: currentUserQueryKey,
    queryFn: async () => {
      const response = await apiClient.get<CurrentUser>("/auth/me");
      return response.data;
    },
    // A 401 here means "not signed in", which is a normal state on first
    // load, not a transient failure worth retrying.
    retry: false,
    staleTime: 60_000,
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await apiClient.post("/auth/logout");
    },
    onSuccess: () => {
      // Drop every cached response, not just the user — the cache holds
      // department-scoped data the next account must not see.
      queryClient.clear();
    },
  });

  const user = query.isError ? null : (query.data ?? null);

  const value = useMemo<AuthState>(
    () => ({
      user,
      loading: query.isLoading,
      permissions: buildPermissions(user),
      refetch: () => query.refetch(),
      logout: async () => {
        await logoutMutation.mutateAsync();
      },
    }),
    [user, query.isLoading, query.refetch, logoutMutation.mutateAsync],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

/** Convenience accessor — most call sites only want the permission helpers. */
export function usePermissions(): Permissions {
  return useAuth().permissions;
}
