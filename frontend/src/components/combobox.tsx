import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Check, ChevronDown, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";

export interface ComboboxOption {
  value: string;
  label: string;
  /** Secondary text shown after the label — a project id under a name, a
   *  timestamp under a scan. Also searched. */
  hint?: string;
  /** A small swatch or icon rendered before the label. Identity only, never
   *  the sole way to tell options apart. */
  icon?: ReactNode;
  disabled?: boolean;
}

/** Below this many options the search box is pointless noise; above it, an
 *  organization/project list is long enough that scrolling alone is painful. */
const SEARCH_THRESHOLD = 7;

/**
 * The single-select control for every "pick one thing" surface — organization,
 * project, department, scan, framework, role, mute reason.
 *
 * It is deliberately built on Popover + a plain list rather than Radix's
 * `Select`, so it shares its popover internals (search field, row hover, check
 * indicator) with `FacetedFilter`: the two controls sit next to each other on
 * findings/scans and used to look like they came from different applications.
 * The trigger keeps `SelectTrigger`'s pill geometry so nothing else had to move.
 *
 * Search appears automatically once the list passes `SEARCH_THRESHOLD`; pass
 * `searchable` to force it either way.
 */
export function Combobox({
  id,
  value,
  onValueChange,
  options,
  placeholder = "Select…",
  searchPlaceholder,
  emptyMessage = "No matches.",
  disabled,
  searchable,
  size = "default",
  align = "start",
  className,
  contentClassName,
}: {
  id?: string;
  value: string;
  onValueChange: (value: string) => void;
  options: ComboboxOption[];
  placeholder?: string;
  searchPlaceholder?: string;
  emptyMessage?: string;
  disabled?: boolean;
  searchable?: boolean;
  size?: "sm" | "default";
  align?: "start" | "center" | "end";
  className?: string;
  contentClassName?: string;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  const showSearch = searchable ?? options.length > SEARCH_THRESHOLD;
  const selected = options.find((option) => option.value === value);

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return options;
    return options.filter(
      (option) =>
        option.label.toLowerCase().includes(query) ||
        (option.hint?.toLowerCase().includes(query) ?? false),
    );
  }, [options, search]);

  // Reopening should always start from the current selection, not from wherever
  // the previous session's arrow keys left the highlight.
  useEffect(() => {
    if (!open) {
      setSearch("");
      return;
    }
    const index = visible.findIndex((option) => option.value === value);
    setActive(index >= 0 ? index : 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (active > visible.length - 1) setActive(0);
  }, [visible.length, active]);

  useEffect(() => {
    listRef.current
      ?.querySelector<HTMLElement>(`[data-index="${active}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  const commit = (option: ComboboxOption) => {
    if (option.disabled) return;
    onValueChange(option.value);
    setOpen(false);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((current) => (visible.length === 0 ? 0 : (current + 1) % visible.length));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((current) =>
        visible.length === 0 ? 0 : (current - 1 + visible.length) % visible.length,
      );
    } else if (event.key === "Enter") {
      const option = visible[active];
      if (option) {
        event.preventDefault();
        commit(option);
      }
    }
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          id={id}
          type="button"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          data-size={size}
          className={cn(
            // Mirrors SelectTrigger's geometry so swapping one for the other is
            // invisible in layout terms.
            "flex w-fit items-center justify-between gap-1.5 rounded-full border border-strong bg-transparent py-2 pr-2 pl-3 text-left text-sm whitespace-nowrap transition-colors outline-none select-none",
            "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
            "disabled:cursor-not-allowed disabled:opacity-50",
            "data-[size=default]:h-8 data-[size=sm]:h-7",
            className,
          )}
        >
          <span
            className={cn(
              "flex min-w-0 items-center gap-1.5",
              selected ? "text-ink" : "text-muted-foreground",
            )}
          >
            {selected?.icon}
            <span className="truncate">{selected?.label ?? placeholder}</span>
          </span>
          <ChevronDown className="pointer-events-none size-4 shrink-0 text-muted-foreground" aria-hidden />
        </button>
      </PopoverTrigger>
      <PopoverContent
        align={align}
        className={cn("w-(--radix-popover-trigger-width) min-w-56 p-0", contentClassName)}
        onKeyDown={handleKeyDown}
      >
        {showSearch && (
          <div className="relative border-b border-hairline">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-ink-muted"
              aria-hidden
            />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={searchPlaceholder ?? "Search…"}
              aria-label={searchPlaceholder ?? "Search options"}
              autoFocus
              className="h-9 rounded-none border-0 pl-8 shadow-none focus-visible:ring-0"
            />
          </div>
        )}
        <div ref={listRef} role="listbox" className="max-h-64 overflow-y-auto p-1">
          {visible.length === 0 ? (
            <p className="px-2 py-3 text-center text-xs text-ink-muted">{emptyMessage}</p>
          ) : (
            visible.map((option, index) => {
              const isSelected = option.value === value;
              return (
                <button
                  key={option.value}
                  type="button"
                  role="option"
                  data-index={index}
                  aria-selected={isSelected}
                  disabled={option.disabled}
                  onMouseEnter={() => setActive(index)}
                  onClick={() => commit(option)}
                  className={cn(
                    "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-ink transition-colors disabled:pointer-events-none disabled:opacity-50",
                    index === active && "bg-subtle",
                  )}
                >
                  {option.icon}
                  <span className="min-w-0 flex-1 truncate">{option.label}</span>
                  {option.hint && (
                    <span className="shrink-0 font-mono text-xs text-ink-muted">{option.hint}</span>
                  )}
                  <Check
                    className={cn("size-3.5 shrink-0", isSelected ? "opacity-100" : "opacity-0")}
                    aria-hidden
                  />
                </button>
              );
            })
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
