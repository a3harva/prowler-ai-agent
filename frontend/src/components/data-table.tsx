import { useState, type ReactNode } from "react";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronsUpDown, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ErrorState, TableSkeleton } from "@/components/states";
import { cn } from "@/lib/utils";

/**
 * One table implementation for the whole app.
 *
 * Every list screen goes through this, present and future — findings, the
 * audit log, compliance requirements. Filtering and sorting happen in the
 * browser over the full row set, which is the right trade at this product's
 * scale (hundreds of rows per project, not millions) and is what makes
 * narrowing feel instant rather than a sequence of page loads.
 */
export interface DataTableProps<TData> {
  columns: ColumnDef<TData, any>[];
  data: TData[] | undefined;
  isLoading?: boolean;
  error?: unknown;
  errorMessage?: string;
  onRetry?: () => void;
  /** Renders in place of the table body when there are no rows at all. */
  empty?: ReactNode;
  searchPlaceholder?: string;
  /** Set false for short, fixed lists where a search box is just noise. */
  searchable?: boolean;
  pageSize?: number;
  /** Extra controls rendered in the toolbar, right of the search box. */
  toolbar?: ReactNode;
  skeletonColumns?: number;
  /** Sort applied on first render only — e.g. a rollup table that should
   *  open worst-first. The user's own clicks on column headers still take
   *  over normally after that; this isn't a controlled/re-applied sort. */
  initialSorting?: SortingState;
  /** Lifts the search box's value into the caller — e.g. Findings.tsx needs
   *  the live text to build a matching server-side export. Uncontrolled
   *  (internal state) when omitted, so every other caller is unaffected. */
  globalFilter?: string;
  onGlobalFilterChange?: (value: string) => void;
}

export function DataTable<TData>({
  columns,
  data,
  isLoading,
  error,
  errorMessage = "The server did not return this list.",
  onRetry,
  empty,
  searchPlaceholder = "Search…",
  searchable = true,
  pageSize = 25,
  toolbar,
  skeletonColumns,
  initialSorting,
  globalFilter: controlledGlobalFilter,
  onGlobalFilterChange,
}: DataTableProps<TData>) {
  const [sorting, setSorting] = useState<SortingState>(initialSorting ?? []);
  const [internalGlobalFilter, setInternalGlobalFilter] = useState("");
  const globalFilter = controlledGlobalFilter ?? internalGlobalFilter;
  const setGlobalFilter = onGlobalFilterChange ?? setInternalGlobalFilter;

  const table = useReactTable({
    data: data ?? [],
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  });

  const rows = table.getRowModel().rows;
  const totalRows = data?.length ?? 0;
  const showToolbar = searchable || toolbar;

  return (
    <div className="space-y-3">
      {showToolbar && (
        <div className="flex flex-wrap items-center gap-2">
          {searchable && (
            <div className="relative min-w-0 flex-1 sm:max-w-xs">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-ink-muted"
                aria-hidden
              />
              <Input
                value={globalFilter}
                onChange={(event) => setGlobalFilter(event.target.value)}
                placeholder={searchPlaceholder}
                className="pl-8"
                aria-label={searchPlaceholder}
                disabled={isLoading || totalRows === 0}
              />
            </div>
          )}
          {toolbar}
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-hairline bg-panel">
        {/* Wide tables scroll inside their own container so the page body
            never scrolls horizontally. */}
        <div className="overflow-x-auto">
          {isLoading ? (
            <TableSkeleton rows={5} columns={skeletonColumns ?? columns.length} />
          ) : error ? (
            <ErrorState message={errorMessage} onRetry={onRetry} />
          ) : totalRows === 0 ? (
            (empty ?? <ErrorState title="Nothing here yet" message="There is nothing to show." />)
          ) : (
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map((headerGroup) => (
                  <TableRow key={headerGroup.id} className="hover:bg-transparent">
                    {headerGroup.headers.map((header) => {
                      const canSort = header.column.getCanSort();
                      const sorted = header.column.getIsSorted();
                      return (
                        <TableHead
                          key={header.id}
                          className="eyebrow whitespace-nowrap bg-subtle"
                        >
                          {header.isPlaceholder ? null : canSort ? (
                            <button
                              type="button"
                              onClick={header.column.getToggleSortingHandler()}
                              className="inline-flex items-center gap-1.5 rounded transition-colors duration-150 hover:text-ink"
                            >
                              {flexRender(
                                header.column.columnDef.header,
                                header.getContext(),
                              )}
                              {sorted === "asc" ? (
                                <ArrowUp className="size-3" aria-hidden />
                              ) : sorted === "desc" ? (
                                <ArrowDown className="size-3" aria-hidden />
                              ) : (
                                <ChevronsUpDown className="size-3 opacity-40" aria-hidden />
                              )}
                              <span className="sr-only">
                                {sorted === "asc"
                                  ? "sorted ascending"
                                  : sorted === "desc"
                                    ? "sorted descending"
                                    : "not sorted"}
                              </span>
                            </button>
                          ) : (
                            flexRender(header.column.columnDef.header, header.getContext())
                          )}
                        </TableHead>
                      );
                    })}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {rows.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={columns.length} className="p-0">
                      <ErrorState
                        title="No matches"
                        message={`Nothing matches “${globalFilter}”. Try a shorter search.`}
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  rows.map((row) => (
                    <TableRow
                      key={row.id}
                      className="border-hairline transition-colors duration-150 hover:bg-subtle"
                    >
                      {row.getVisibleCells().map((cell) => (
                        <TableCell key={cell.id} className="py-3">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </div>
      </div>

      {table.getPageCount() > 1 && (
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-ink-muted">
            Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()} ·{" "}
            {rows.length} of {totalRows} shown
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

/** Shared cell helpers, so column definitions stay declarative. */
export function MonoCell({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-xs text-ink", className)}>{children}</span>;
}

export function MutedCell({ children }: { children: ReactNode }) {
  return <span className="text-sm text-ink-muted">{children}</span>;
}
