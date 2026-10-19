import { useState, type ReactNode } from "react";
import { Check, PlusCircle, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

export interface FacetOption {
  value: string;
  label: string;
  /** A small swatch or icon rendered before the label — a severity dot, a
   *  status icon. Purely identity, never the only way to tell options apart. */
  icon?: ReactNode;
  count?: number;
}

/**
 * A multi-select filter: a dashed trigger showing the active selection, a
 * searchable checklist in a popover, "Clear filters" at the bottom.
 *
 * Selection lives in the caller (`selected`/`onChange`) — this component
 * owns only the popover's open state and its own search text.
 */
export function FacetedFilter({
  title,
  options,
  selected,
  onChange,
}: {
  title: string;
  options: FacetOption[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");

  const visible = options.filter((option) =>
    option.label.toLowerCase().includes(search.trim().toLowerCase()),
  );

  const toggle = (value: string) => {
    const next = new Set(selected);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    onChange(next);
  };

  const selectedOptions = options.filter((option) => selected.has(option.value));
  // A value can be pre-selected (e.g. arriving via a URL param) before its
  // options list has loaded — fall back to the raw value rather than
  // rendering an empty badge in that window.
  const firstSelectedLabel = selectedOptions[0]?.label ?? [...selected][0];

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className={cn(
            "border-dashed",
            selected.size > 0 && "border-solid",
          )}
        >
          <PlusCircle className="size-3.5" aria-hidden />
          {title}
          {selected.size > 0 && (
            <>
              <Separator orientation="vertical" className="mx-1 h-4" />
              {selected.size === 1 ? (
                <Badge variant="secondary" className="font-normal">
                  {firstSelectedLabel}
                </Badge>
              ) : (
                <Badge variant="secondary" className="font-normal">
                  {selected.size} selected
                </Badge>
              )}
            </>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 p-0">
        <div className="relative border-b border-hairline">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-ink-muted"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={title}
            aria-label={`Search ${title.toLowerCase()}`}
            className="h-9 rounded-none border-0 pl-8 shadow-none focus-visible:ring-0"
          />
        </div>
        <div className="max-h-64 overflow-y-auto p-1">
          {visible.length === 0 ? (
            <p className="px-2 py-3 text-center text-xs text-ink-muted">No matches.</p>
          ) : (
            visible.map((option) => {
              const checked = selected.has(option.value);
              return (
                <button
                  key={option.value}
                  type="button"
                  role="option"
                  aria-selected={checked}
                  onClick={() => toggle(option.value)}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-ink transition-colors hover:bg-subtle"
                >
                  {/* A plain styled span, not the interactive Checkbox —
                      the surrounding button already owns the click and the
                      accessible state; nesting Radix's own <button> inside
                      this one would be invalid HTML and steal the click. */}
                  <span
                    aria-hidden
                    className={cn(
                      "flex size-4 shrink-0 items-center justify-center rounded-sm border border-strong transition-colors",
                      checked && "border-primary bg-primary text-primary-foreground",
                    )}
                  >
                    {checked && <Check className="size-3.5" />}
                  </span>
                  {option.icon}
                  <span className="flex-1 truncate">{option.label}</span>
                  {option.count !== undefined && (
                    <span className="font-mono text-xs text-ink-muted">{option.count}</span>
                  )}
                </button>
              );
            })
          )}
        </div>
        {selected.size > 0 && (
          <>
            <Separator />
            <button
              type="button"
              onClick={() => onChange(new Set())}
              className="w-full rounded-b-lg px-2 py-2 text-center text-sm text-ink-secondary transition-colors hover:bg-subtle hover:text-ink"
            >
              Clear filters
            </button>
          </>
        )}
      </PopoverContent>
    </Popover>
  );
}
