import { useMemo, useState } from "react";
import { Check, ChevronDown, Search } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import type { Organization, Project } from "@/api/types";

/**
 * The conversation's project, chosen the way a chat app chooses its model:
 * a compact pill inside the composer rather than two form fields above it.
 *
 * One flat list grouped by organization, not an organization select feeding a
 * project select. Two chained dropdowns is the shape a *form* wants, where
 * each field is a separate decision; here there is only one decision — which
 * project — and the organization is context for telling two similarly-named
 * projects apart. Collapsing it to one list also removes a nested-popover
 * problem, since the trigger is already inside a popover-bearing composer.
 *
 * Locks once a conversation exists. The binding is immutable server-side, so
 * an editable control here would promise something the API will refuse — the
 * disabled pill plus "New conversation" says the true thing instead.
 */
export function ProjectPicker({
  projects,
  organizations,
  value,
  onChange,
  disabled,
}: {
  projects: Project[];
  organizations: Organization[];
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const orgName = useMemo(
    () => new Map(organizations.map((o) => [o.id, o.name])),
    [organizations],
  );

  const grouped = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const matches = projects.filter(
      (p) =>
        !needle ||
        p.project_id.toLowerCase().includes(needle) ||
        (orgName.get(p.gcp_organization_id) ?? "").toLowerCase().includes(needle),
    );
    const byOrg = new Map<string, Project[]>();
    for (const project of matches) {
      const name = orgName.get(project.gcp_organization_id) ?? "Unknown organization";
      byOrg.set(name, [...(byOrg.get(name) ?? []), project]);
    }
    return [...byOrg.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [projects, orgName, query]);

  const selected = projects.find((p) => String(p.id) === value);
  const label = selected?.project_id ?? "Choose project";

  if (disabled) {
    return (
      <span
        className="inline-flex max-w-[14rem] items-center gap-1.5 truncate rounded-full bg-subtle px-3 py-1.5 text-sm text-ink-secondary"
        title={selected ? `Bound to ${selected.project_id}` : undefined}
      >
        <span className="truncate">{label}</span>
      </span>
    );
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className={cn(
            "inline-flex max-w-[14rem] items-center gap-1 rounded-full px-3 py-1.5 text-sm transition-colors",
            selected
              ? "bg-subtle text-ink-secondary hover:bg-hairline"
              : "bg-brand-100 text-brand hover:bg-brand-200",
          )}
        >
          <span className="truncate">{label}</span>
          <ChevronDown className="size-3.5 shrink-0 opacity-60" aria-hidden />
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <div className="flex items-center gap-2 border-b border-hairline px-3 py-2">
          <Search className="size-3.5 shrink-0 text-ink-muted" aria-hidden />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Find a project"
            className="w-full bg-transparent text-sm text-ink outline-none placeholder:text-ink-muted"
          />
        </div>
        <div className="max-h-72 overflow-y-auto p-1">
          {grouped.length === 0 && (
            <p className="px-3 py-6 text-center text-sm text-ink-muted">No matching project.</p>
          )}
          {grouped.map(([organization, items]) => (
            <div key={organization} className="mb-1 last:mb-0">
              <p className="px-3 pb-1 pt-2 text-[11px] font-medium uppercase tracking-wide text-ink-muted">
                {organization}
              </p>
              {items.map((project) => {
                const active = String(project.id) === value;
                return (
                  <button
                    key={project.id}
                    type="button"
                    onClick={() => {
                      onChange(String(project.id));
                      setOpen(false);
                      setQuery("");
                    }}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm transition-colors",
                      // The one dropdown hover colour the whole app shares —
                      // never shadcn's vendored accent, which nothing else uses.
                      "hover:bg-subtle hover:text-ink",
                      active ? "text-ink" : "text-ink-secondary",
                    )}
                  >
                    <Check
                      className={cn("size-3.5 shrink-0", active ? "opacity-100" : "opacity-0")}
                      aria-hidden
                    />
                    <span className="truncate">{project.project_id}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}
