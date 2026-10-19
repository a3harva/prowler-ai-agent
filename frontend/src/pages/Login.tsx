import { useState } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { LoaderCircle, TriangleAlert } from "lucide-react";
import { currentUserQueryKey, useAuth } from "@/auth/AuthContext";
import { errorMessage } from "@/api/client";
import { useLocalLogin } from "@/hooks/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const apiBase = import.meta.env.VITE_API_BASE_URL ?? "/api";

function OrbitMark({ className }: { className?: string }) {
  // A neutral local mark with no external asset dependency.
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden focusable="false">
      <circle cx="12" cy="12" r="10.5" fill="none" stroke="currentColor" strokeWidth="1.6" opacity="0.3" />
      <circle cx="12" cy="12" r="6.75" fill="none" stroke="currentColor" strokeWidth="1.8" opacity="0.65" />
      <circle cx="12" cy="12" r="3" fill="currentColor" />
    </svg>
  );
}

export default function Login() {
  const [params] = useSearchParams();
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const localLogin = useLocalLogin();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const domainRejected = params.get("login_error") === "domain_not_allowed";
  const sessionExpired = params.get("session") === "expired";

  const handlePasswordLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    setPasswordError(null);
    try {
      await localLogin.mutateAsync({ email: email.trim(), password });
      await queryClient.invalidateQueries({ queryKey: currentUserQueryKey });
      navigate("/", { replace: true });
    } catch (error) {
      setPasswordError(errorMessage(error, "Invalid email or password."));
    }
  };

  if (loading) {
    return (
      <div className="grid min-h-screen place-items-center bg-page" role="status">
        <LoaderCircle className="size-5 animate-spin text-brand" aria-hidden />
        <span className="sr-only">Loading</span>
      </div>
    );
  }
  if (user) return <Navigate to="/" replace />;

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* A neutral local decorative element. */}
      <div className="relative hidden overflow-hidden bg-brand-deep lg:block">
        <div className="absolute inset-0 grid place-items-center text-white">
          <OrbitMark className="size-[38rem] opacity-[0.07]" />
        </div>
        <div className="relative flex h-full flex-col justify-between p-10 text-white">
          <div className="flex items-center gap-2.5">
            <OrbitMark className="size-6" />
            <span className="font-display text-lg font-semibold tracking-tight">prowler agent</span>
          </div>
          <div className="max-w-md space-y-4">
            <h2 className="font-display text-3xl font-semibold leading-tight tracking-tight">
              Understand and improve your cloud security posture.
            </h2>
            <p className="text-[15px] leading-relaxed text-white/70">
              Run Prowler against a GCP project, triage what it finds, and report compliance
              against twenty-one frameworks — with triage decisions that survive every re-scan.
            </p>
          </div>
          <p className="font-mono text-xs text-white/45">prowler agent</p>
        </div>
      </div>

      <div className="flex items-center justify-center bg-page px-6 py-12">
        <div className="w-full max-w-sm space-y-7">
          <div className="flex items-center gap-2.5 text-brand lg:hidden">
            <OrbitMark className="size-6" />
            <span className="font-display text-lg font-semibold tracking-tight">prowler agent</span>
          </div>

          <div className="space-y-2">
            <h1 className="font-display text-[38px] font-light tracking-[-0.035em] text-ink">
              sign in
            </h1>
            <p className="text-sm leading-relaxed text-ink-secondary">
              Use an authorized Google account to continue.
            </p>
          </div>

          {domainRejected && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-lg border border-status-fail-line bg-status-fail-bg px-3 py-2.5 text-sm text-status-fail"
            >
              <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span className="leading-relaxed">
                That account is not authorized for this workspace. Use an approved Google account.
              </span>
            </div>
          )}

          {sessionExpired && !domainRejected && (
            <div
              role="status"
              className="flex items-start gap-2.5 rounded-lg border border-hairline bg-panel px-3 py-2.5 text-sm text-ink-secondary"
            >
              <TriangleAlert className="mt-0.5 size-4 shrink-0 text-ink-muted" aria-hidden />
              <span className="leading-relaxed">Your session expired. Sign in to continue.</span>
            </div>
          )}

          {/* A full-page navigation, not a fetch — the OAuth flow is entirely
              server-side and ends by setting httpOnly cookies. */}
          <a
            href={`${apiBase}/auth/login`}
            className="flex w-full items-center justify-center gap-2.5 rounded-full border border-hairline bg-panel px-4 py-2.5 text-sm font-medium text-ink transition-colors duration-150 hover:bg-subtle hover:shadow-[var(--shadow-lift)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
          >
            <GoogleMark />
            Sign in with Google
          </a>

          <div className="flex items-center gap-3 text-xs text-ink-muted">
            <span className="h-px flex-1 bg-hairline" />
            or
            <span className="h-px flex-1 bg-hairline" />
          </div>

          <form onSubmit={handlePasswordLogin} className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="login-email">Email</Label>
              <Input
                id="login-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="person@example.test"
                autoComplete="username"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="login-password">Password</Label>
              <Input
                id="login-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
            </div>

            {passwordError && (
              <div
                role="alert"
                className="flex items-start gap-2.5 rounded-lg border border-status-fail-line bg-status-fail-bg px-3 py-2.5 text-sm text-status-fail"
              >
                <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
                <span className="leading-relaxed">{passwordError}</span>
              </div>
            )}

            <Button type="submit" className="w-full" disabled={localLogin.isPending}>
              {localLogin.isPending && <LoaderCircle className="size-3.5 animate-spin" aria-hidden />}
              Sign in with password
            </Button>
          </form>

          <p className="text-xs leading-relaxed text-ink-muted">
            Access is granted per department by an administrator. Signing in for the first time
            is enough — there is no invitation to accept.
          </p>
        </div>
      </div>
    </div>
  );
}

function GoogleMark() {
  return (
    <svg className="size-4" viewBox="0 0 48 48" aria-hidden focusable="false">
      <path
        fill="#4285F4"
        d="M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84c-.51 2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z"
      />
      <path
        fill="#34A853"
        d="M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52c-1.97 1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7C7.96 41.07 15.4 46 24 46z"
      />
      <path
        fill="#FBBC05"
        d="M11.69 28.18c-.44-1.32-.69-2.73-.69-4.18s.25-2.86.69-4.18v-5.7H4.34C2.85 17.09 2 20.45 2 24s.85 6.91 2.34 9.88l7.35-5.7z"
      />
      <path
        fill="#EA4335"
        d="M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31C34.91 4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7c1.73-5.2 6.58-9.07 12.31-9.07z"
      />
    </svg>
  );
}
