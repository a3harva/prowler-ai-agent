import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    // shadcn/ui generates imports as "@/components/..." — the alias has to
    // exist here for the bundler and in tsconfig.json for the type checker.
    // Both are required; neither alone is enough.
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    watch: {
      // The source tree is bind-mounted into the container, and inotify
      // events do not cross that boundary — on macOS/Colima they never
      // reach the container at all. Without polling the watcher simply
      // never fires: edits appear in the container's filesystem but Vite
      // keeps serving the module graph it built at startup, so the browser
      // shows stale code and nothing indicates anything is wrong.
      usePolling: true,
      interval: 300,
    },
  },
});
