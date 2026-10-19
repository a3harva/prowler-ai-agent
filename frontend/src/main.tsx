import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { TooltipProvider } from "@/components/ui/tooltip";
import { StatusProvider } from "@/components/status-region";
import { AuthProvider } from "@/auth/AuthContext";
import { ThemeProvider } from "@/lib/theme";
import App from "@/App";
import "@/index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The API is same-origin and fast; refetching on every window focus
      // just produces flicker on a dashboard someone is reading.
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      // A 401 is handled by the axios interceptor (refresh, then redirect),
      // and a 403 will never succeed on retry. Retrying either is noise.
      retry: (failureCount, error) => {
        const status = (error as { response?: { status?: number } })?.response?.status;
        if (status === 401 || status === 403 || status === 404) return false;
        return failureCount < 2;
      },
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <StatusProvider>
              <TooltipProvider delayDuration={200}>
                <App />
              </TooltipProvider>
            </StatusProvider>
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
);
