import type { ReactNode } from "react";
import { Inbox, RefreshCw, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

/** An empty screen is an invitation to act, not a shrug. Every use of this
 *  names the next action rather than just reporting the absence. */
export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className,
}: {
  icon?: typeof Inbox;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 px-6 py-14 text-center",
        className,
      )}
    >
      <div className="rounded-full border border-hairline bg-subtle p-3">
        <Icon className="size-5 text-ink-muted" aria-hidden />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-ink">{title}</p>
        {description && (
          <p className="mx-auto max-w-md text-sm text-ink-muted">{description}</p>
        )}
      </div>
      {action}
    </div>
  );
}

/** Errors explain what happened and how to proceed. They do not apologise
 *  and they are never vague — the server's `detail` string is shown as-is. */
export function ErrorState({
  title = "Couldn't load this",
  message,
  onRetry,
  className,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-3 px-6 py-14 text-center",
        className,
      )}
    >
      <div className="rounded-full border border-status-fail-line bg-status-fail-bg p-3">
        <TriangleAlert className="size-5 text-status-fail" aria-hidden />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-ink">{title}</p>
        <p className="mx-auto max-w-md text-sm text-ink-muted">{message}</p>
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="size-3.5" aria-hidden />
          Try again
        </Button>
      )}
    </div>
  );
}

/** Skeleton rows sized to the table they stand in for, so the layout does
 *  not jump when loaded data arrives. */
export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div className="space-y-px" aria-hidden>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div
          key={rowIndex}
          className="flex items-center gap-4 border-b border-hairline px-4 py-3.5 last:border-0"
        >
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton
              key={colIndex}
              className="h-4"
              style={{ width: colIndex === 0 ? "22%" : `${Math.max(10, 60 / columns)}%` }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
