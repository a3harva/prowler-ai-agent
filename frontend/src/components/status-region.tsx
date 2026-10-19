import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { Check, TriangleAlert, X } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * The app's feedback channel, in place of a toast library.
 *
 * Two things a toast usually gets wrong and this does not: it is announced
 * to assistive technology via `aria-live`, and it does not disappear on a
 * timer before a person has read it. It sits in the page header, in the
 * region the person was already looking at when they pressed the button.
 *
 * The message uses the same verb as the control that produced it — "Archive"
 * produces "Archived" — so the interface reads as one vocabulary.
 */
type StatusTone = "success" | "error";

interface StatusMessage {
  tone: StatusTone;
  text: string;
  /** Bumped per report so repeating the same message still re-announces. */
  id: number;
}

interface StatusContextValue {
  report: (tone: StatusTone, text: string) => void;
  succeed: (text: string) => void;
  fail: (text: string) => void;
  clear: () => void;
  message: StatusMessage | null;
}

const StatusContext = createContext<StatusContextValue | undefined>(undefined);

export function StatusProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<StatusMessage | null>(null);

  const report = useCallback((tone: StatusTone, text: string) => {
    setMessage({ tone, text, id: Date.now() });
  }, []);

  const value = useMemo<StatusContextValue>(
    () => ({
      report,
      succeed: (text: string) => report("success", text),
      fail: (text: string) => report("error", text),
      clear: () => setMessage(null),
      message,
    }),
    [report, message],
  );

  return <StatusContext.Provider value={value}>{children}</StatusContext.Provider>;
}

export function useStatus(): StatusContextValue {
  const context = useContext(StatusContext);
  if (!context) {
    throw new Error("useStatus must be used within StatusProvider");
  }
  return context;
}

export function StatusRegion({ className }: { className?: string }) {
  const { message, clear } = useStatus();

  return (
    // The live region is always mounted — an aria-live container added to
    // the DOM at the same moment as its content is unreliably announced.
    <div aria-live="polite" aria-atomic="true" className={cn("min-h-0", className)}>
      {message && (
        <div
          key={message.id}
          className={cn(
            "flex items-start gap-2 rounded-md border px-3 py-2 text-sm",
            message.tone === "success"
              ? "border-status-pass-line bg-status-pass-bg text-status-pass"
              : "border-status-fail-line bg-status-fail-bg text-status-fail",
          )}
        >
          {message.tone === "success" ? (
            <Check className="mt-0.5 size-4 shrink-0" aria-hidden />
          ) : (
            <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          )}
          <span className="flex-1 leading-relaxed">{message.text}</span>
          <button
            type="button"
            onClick={clear}
            className="rounded p-0.5 opacity-60 transition-opacity hover:opacity-100"
          >
            <X className="size-3.5" aria-hidden />
            <span className="sr-only">Dismiss</span>
          </button>
        </div>
      )}
    </div>
  );
}
