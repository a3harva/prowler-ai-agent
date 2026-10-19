import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Eye, History } from "lucide-react";
import { PageHeader, Panel } from "@/components/app-shell";
import { DataTable, MonoCell, MutedCell } from "@/components/data-table";
import { EmptyState } from "@/components/states";
import { FacetedFilter, type FacetOption } from "@/components/faceted-filter";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorMessage } from "@/api/client";
import type { AuditLogEntry } from "@/api/types";
import { useAuditLog } from "@/hooks/queries";
import { formatTimestamp } from "@/lib/format";

function DiffBlock({ title, value }: { title: string; value: Record<string, unknown> | null }) {
  return (
    <div className="space-y-1.5">
      <p className="text-xs font-medium uppercase tracking-wider text-ink-muted">{title}</p>
      {value === null ? (
        <p className="text-sm text-ink-muted italic">None</p>
      ) : (
        <pre className="max-h-64 overflow-auto rounded-md border border-hairline bg-subtle p-3 font-mono text-xs text-ink">
          {JSON.stringify(value, null, 2)}
        </pre>
      )}
    </div>
  );
}

function AuditEntryDialog({ entry, onOpenChange }: { entry: AuditLogEntry; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{entry.action_type}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-ink-muted">Actor</p>
              <p className="text-ink">{entry.actor_name}</p>
              <p className="font-mono text-xs text-ink-muted">{entry.actor_email}</p>
            </div>
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-ink-muted">Target</p>
              <p className="text-ink">{entry.target_type}</p>
              <p className="font-mono text-xs text-ink-muted">#{entry.target_id}</p>
            </div>
            <div className="col-span-2">
              <p className="text-xs font-medium uppercase tracking-wider text-ink-muted">When</p>
              <p className="text-ink">{formatTimestamp(entry.timestamp)}</p>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <DiffBlock title="Before" value={entry.before_value} />
            <DiffBlock title="After" value={entry.after_value} />
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Admin-only, read-only. There is deliberately no edit or delete action
 * anywhere on this page — an audit trail the interface can rewrite isn't
 * one worth keeping, and this screen exists to prove that, not just say it.
 */
export default function AuditLog() {
  const auditLog = useAuditLog();
  const [viewingEntry, setViewingEntry] = useState<AuditLogEntry | null>(null);

  const [actorFilter, setActorFilter] = useState<Set<string>>(new Set());
  const [actionFilter, setActionFilter] = useState<Set<string>>(new Set());
  const [targetFilter, setTargetFilter] = useState<Set<string>>(new Set());
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  const anyFilterActive =
    actorFilter.size > 0 || actionFilter.size > 0 || targetFilter.size > 0 || !!dateFrom || !!dateTo;

  const clearAllFilters = () => {
    setActorFilter(new Set());
    setActionFilter(new Set());
    setTargetFilter(new Set());
    setDateFrom("");
    setDateTo("");
  };

  const actorOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of auditLog.data ?? []) {
      counts.set(entry.actor_email, (counts.get(entry.actor_email) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [auditLog.data]);

  const actionOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of auditLog.data ?? []) {
      counts.set(entry.action_type, (counts.get(entry.action_type) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [auditLog.data]);

  const targetOptions: FacetOption[] = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of auditLog.data ?? []) {
      counts.set(entry.target_type, (counts.get(entry.target_type) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [auditLog.data]);

  const filteredEntries = useMemo(() => {
    const fromTime = dateFrom ? new Date(dateFrom).getTime() : null;
    // End-of-day for the "to" date, so selecting the same day as "from"
    // includes that whole day rather than matching nothing at midnight.
    const toTime = dateTo ? new Date(dateTo).getTime() + 24 * 60 * 60 * 1000 - 1 : null;

    return (auditLog.data ?? []).filter((entry) => {
      if (actorFilter.size > 0 && !actorFilter.has(entry.actor_email)) return false;
      if (actionFilter.size > 0 && !actionFilter.has(entry.action_type)) return false;
      if (targetFilter.size > 0 && !targetFilter.has(entry.target_type)) return false;
      const entryTime = new Date(entry.timestamp).getTime();
      if (fromTime !== null && entryTime < fromTime) return false;
      if (toTime !== null && entryTime > toTime) return false;
      return true;
    });
  }, [auditLog.data, actorFilter, actionFilter, targetFilter, dateFrom, dateTo]);

  const columns: ColumnDef<AuditLogEntry, any>[] = [
    {
      accessorKey: "timestamp",
      header: "When",
      cell: ({ row }) => <MutedCell>{formatTimestamp(row.original.timestamp)}</MutedCell>,
    },
    {
      accessorKey: "actor_email",
      header: "Actor",
      cell: ({ row }) => (
        <div>
          <p className="text-sm text-ink">{row.original.actor_name}</p>
          <p className="font-mono text-[11px] text-ink-muted">{row.original.actor_email}</p>
        </div>
      ),
    },
    {
      accessorKey: "action_type",
      header: "Action",
      cell: ({ row }) => <MonoCell>{row.original.action_type}</MonoCell>,
    },
    {
      accessorKey: "target_type",
      header: "Target",
      cell: ({ row }) => (
        <div>
          <p className="text-sm text-ink">{row.original.target_type}</p>
          <p className="font-mono text-[11px] text-ink-muted">#{row.original.target_id}</p>
        </div>
      ),
    },
    {
      id: "diff",
      header: "",
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button variant="ghost" size="sm" onClick={() => setViewingEntry(row.original)}>
            <Eye className="size-3.5" aria-hidden />
            View
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="audit log"
        description="Every mutation across the platform, attributed to the user who made it. Viewing anything — findings, scans, this log itself — produces no entry here."
      />

      <DataTable
        columns={columns}
        data={filteredEntries}
        isLoading={auditLog.isLoading}
        error={auditLog.error}
        errorMessage={errorMessage(auditLog.error, "Couldn't load the audit log.")}
        onRetry={() => auditLog.refetch()}
        searchPlaceholder="Search actor, action, target…"
        pageSize={50}
        toolbar={
          (auditLog.data?.length ?? 0) > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <FacetedFilter title="Actor" options={actorOptions} selected={actorFilter} onChange={setActorFilter} />
              <FacetedFilter
                title="Action"
                options={actionOptions}
                selected={actionFilter}
                onChange={setActionFilter}
              />
              <FacetedFilter
                title="Target"
                options={targetOptions}
                selected={targetFilter}
                onChange={setTargetFilter}
              />
              <div className="flex items-center gap-1.5">
                <Label htmlFor="audit-date-from" className="sr-only">
                  From date
                </Label>
                <Input
                  id="audit-date-from"
                  type="date"
                  value={dateFrom}
                  onChange={(event) => setDateFrom(event.target.value)}
                  className="h-8 w-36 text-xs"
                />
                <span className="text-xs text-ink-muted">to</span>
                <Label htmlFor="audit-date-to" className="sr-only">
                  To date
                </Label>
                <Input
                  id="audit-date-to"
                  type="date"
                  value={dateTo}
                  onChange={(event) => setDateTo(event.target.value)}
                  className="h-8 w-36 text-xs"
                />
              </div>
              {anyFilterActive && (
                <Button variant="ghost" size="sm" onClick={clearAllFilters}>
                  Reset
                </Button>
              )}
            </div>
          )
        }
        empty={
          anyFilterActive ? (
            <EmptyState
              icon={History}
              title="No entries match these filters"
              description="Nothing in the trail matches the selected actor, action, target or date range."
              action={
                <Button variant="outline" size="sm" onClick={clearAllFilters}>
                  Clear filters
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={History}
              title="No activity yet"
              description="Mutating actions across the platform — departments, projects, scans, findings, the compliance rulebook — will show up here."
            />
          )
        }
      />

      {viewingEntry && (
        <AuditEntryDialog entry={viewingEntry} onOpenChange={(open) => !open && setViewingEntry(null)} />
      )}
    </div>
  );
}
