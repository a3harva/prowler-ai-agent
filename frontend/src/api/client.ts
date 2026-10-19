import axios, { AxiosError } from "axios";

// Session lives in httpOnly cookies set by the backend — withCredentials is
// what makes the browser send/accept them on cross-origin-looking requests
// through the dev proxy.
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "/api",
  withCredentials: true,
});

let refreshInFlight: Promise<unknown> | null = null;

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as (typeof error.config & { _retried?: boolean }) | undefined;

    if (error.response?.status !== 401 || !original || original._retried) {
      throw error;
    }
    if (original.url?.includes("/auth/refresh")) {
      throw error;
    }

    original._retried = true;

    refreshInFlight ??= apiClient.post("/auth/refresh").finally(() => {
      refreshInFlight = null;
    });

    try {
      await refreshInFlight;
    } catch (refreshError) {
      // The session is genuinely gone. Previously this rejection propagated
      // and the user sat on a dead page until they happened to reload — every
      // subsequent request failing silently. Send them to sign in instead.
      // Guarded so we do not bounce a user who is already on /login.
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        window.location.assign("/login?session=expired");
      }
      throw refreshError;
    }

    return apiClient.request(original);
  },
);

/** FastAPI puts human-readable messages in `detail`; the services layer
 *  raises with text meant to be shown. Fall back to the transport error only
 *  when there is nothing better, never to a bare "Error". */
export function errorMessage(error: unknown, fallback = "Something went wrong."): string {
  const axiosError = error as AxiosError<{ detail?: string | { msg?: string }[] }>;
  const detail = axiosError?.response?.data?.detail;

  if (typeof detail === "string" && detail.trim()) return detail;
  // Pydantic validation errors arrive as a list of {loc, msg, type}.
  if (Array.isArray(detail)) {
    const messages = detail.map((d) => d?.msg).filter(Boolean);
    if (messages.length) return messages.join("; ");
  }
  if (axiosError?.message) return axiosError.message;
  return fallback;
}
