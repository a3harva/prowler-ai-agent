import { Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Bot,
  FileText,
  BookCheck,
  Building2,
  ChevronsLeft,
  ChevronsRight,
  ClipboardCheck,
  Compass,
  FolderGit2,
  History,
  Landmark,
  LayoutDashboard,
  LoaderCircle,
  LogOut,
  Menu,
  Moon,
  Radar,
  Search,
  ShieldAlert,
  Sun,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { StatusRegion } from "@/components/status-region";
import { useAuth } from "@/auth/AuthContext";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

const SIDEBAR_COLLAPSED_KEY = "prowler-sidebar-collapsed";

/** Persisted like the theme choice — a Freshservice-style collapse is a
 *  standing display preference, not a per-visit toggle, so it should still
 *  be collapsed the next time this browser opens the app. Local to
 *  AppShell rather than a context: nothing outside this file needs it. */
function useSidebarCollapsed() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "true",
  );
  useEffect(() => {
    localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(collapsed));
  }, [collapsed]);
  return [collapsed, setCollapsed] as const;
}

interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  /** Global-admin only. Mirrors `require_admin`, which accepts nothing else. */
  adminOnly?: boolean;
}

/**
 * Navigation is a config array so every live route is declared once and feeds
 * the sidebar, page search and breadcrumb label together. A nav item pointing
 * at a page that does not exist is worse than a shorter nav.
 *
 * Three groups organize the day-to-day scan
 * and findings work), ESTATE (the GCP inventory being scanned), and
 * ADMINISTRATION (department/user/rulebook/audit management). Grouping is
 * visual only — Departments stays behind the same `adminOnly` route guard
 * it always had, even though it now sits under ESTATE rather than
 * ADMINISTRATION.
 */
const POSTURE_NAV: NavItem[] = [
  { to: "/", label: "dashboard", icon: LayoutDashboard },
  { to: "/scans", label: "scans", icon: Radar },
  { to: "/findings", label: "findings", icon: ShieldAlert },
  { to: "/findings-overview", label: "findings overview", icon: Compass },
  { to: "/agent", label: "agent", icon: Bot },
  { to: "/compliance-report", label: "compliance report", icon: ClipboardCheck },
  { to: "/reports", label: "assessment reports", icon: FileText },
];

const ESTATE_NAV: NavItem[] = [
  { to: "/projects", label: "projects", icon: FolderGit2 },
  { to: "/organizations", label: "organizations", icon: Building2 },
  { to: "/admin/departments", label: "departments", icon: Landmark, adminOnly: true },
];

const ADMIN_NAV: NavItem[] = [
  { to: "/admin/users", label: "users & roles", icon: Users, adminOnly: true },
  { to: "/admin/compliance", label: "compliance", icon: BookCheck, adminOnly: true },
  { to: "/admin/audit", label: "audit log", icon: History, adminOnly: true },
];

function OrbitMark({ className }: { className?: string }) {
  // A neutral local mark with no external asset dependency.
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden focusable="false">
      <circle cx="12" cy="12" r="10.5" fill="none" stroke="currentColor" strokeWidth="1.6" opacity="0.35" />
      <circle cx="12" cy="12" r="6.75" fill="none" stroke="currentColor" strokeWidth="1.8" opacity="0.7" />
      <circle cx="12" cy="12" r="3" fill="currentColor" />
    </svg>
  );
}

function SidebarNavLink({
  item,
  collapsed,
  onNavigate,
}: {
  item: NavItem;
  collapsed?: boolean;
  onNavigate?: () => void;
}) {
  const Icon = item.icon;
  const link = (
    <NavLink
      to={item.to}
      end={item.to === "/"}
      onClick={onNavigate}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-2.5 rounded-full px-3 py-1.5 text-sm transition-colors duration-150",
          collapsed && "justify-center px-0",
          isActive
            ? "bg-brand-100 font-medium text-brand"
            : "text-ink-secondary hover:bg-subtle hover:text-ink",
        )
      }
    >
      <Icon className="size-4 shrink-0" aria-hidden />
      {!collapsed && item.label}
    </NavLink>
  );

  if (!collapsed) return link;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{item.label}</TooltipContent>
    </Tooltip>
  );
}

/** A real jump-to-page search over the nav config — not a decorative
 *  input. Vercel's own "Find" box is a full command palette; this is the
 *  scoped equivalent for an app with a dozen destinations rather than
 *  hundreds. */
function SidebarSearch({ items, onNavigate }: { items: NavItem[]; onNavigate?: () => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return items.filter((item) => item.label.toLowerCase().includes(q));
  }, [items, query]);

  const go = (item: NavItem) => {
    navigate(item.to);
    setQuery("");
    setOpen(false);
    onNavigate?.();
  };

  return (
    <div ref={containerRef} className="relative">
      <div className="flex items-center gap-2 rounded-full border border-strong bg-page px-3 py-1.5 text-sm text-ink-muted transition-colors focus-within:border-brand">
        <Search className="size-3.5 shrink-0" aria-hidden />
        <input
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && matches[0]) go(matches[0]);
            if (event.key === "Escape") setOpen(false);
          }}
          placeholder="find"
          aria-label="Jump to a page"
          className="w-full bg-transparent text-ink outline-none placeholder:text-ink-muted"
        />
        {!query && (
          <kbd className="rounded-full border border-hairline px-2 py-0.5 font-mono text-[10px] text-ink-muted">
            F
          </kbd>
        )}
      </div>
      {open && matches.length > 0 && (
        <div className="absolute inset-x-0 top-full z-20 mt-1 overflow-hidden rounded-lg border border-hairline bg-panel py-1 shadow-md">
          {matches.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.to}
                type="button"
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => go(item)}
                className="flex w-full items-center gap-2.5 px-2.5 py-1.5 text-left text-sm text-ink transition-colors hover:bg-subtle"
              >
                <Icon className="size-4 shrink-0 text-ink-muted" aria-hidden />
                {item.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SidebarContent({
  collapsed,
  onNavigate,
}: {
  /** Only the persistent desktop sidebar ever collapses — the mobile
   *  Sheet always renders the full version, since it's already an
   *  overlay the user dismisses outright rather than a fixed-width
   *  neighbor competing with the page for space. */
  collapsed?: boolean;
  onNavigate?: () => void;
}) {
  const { user, permissions, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const adminItems = permissions.isGlobalAdmin ? ADMIN_NAV : [];
  const estateItems = ESTATE_NAV.filter((item) => !item.adminOnly || permissions.isGlobalAdmin);

  const initials =
    user?.name
      ?.split(" ")
      .map((part) => part[0])
      .filter(Boolean)
      .slice(0, 2)
      .join("")
      .toUpperCase() ?? "?";

  return (
    <div className="flex h-full flex-col gap-4 p-3">
      <Link
        to="/"
        onClick={onNavigate}
        className={cn(
          "flex items-center gap-2 rounded-md px-1 py-1 text-ink",
          collapsed && "justify-center px-0",
        )}
      >
        <OrbitMark className="size-6 shrink-0 text-brand" />
        {!collapsed && (
          <>
            <span className="font-display text-[15px] font-medium tracking-tight">prowler agent</span>
          </>
        )}
      </Link>

      {/* Collapsing hides the Find box rather than shrinking it to an
          icon — its whole value is the always-visible input plus results
          list, neither of which fits a 68px rail. */}
      {!collapsed && (
        <SidebarSearch items={[...POSTURE_NAV, ...estateItems, ...adminItems]} onNavigate={onNavigate} />
      )}

      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-0.5">
          {!collapsed && <p className="eyebrow px-3 pb-1">posture</p>}
          <nav className="flex flex-col gap-0.5" aria-label="Posture">
            {POSTURE_NAV.map((item) => (
              <SidebarNavLink key={item.to} item={item} collapsed={collapsed} onNavigate={onNavigate} />
            ))}
          </nav>
        </div>

        <div className="flex flex-col gap-0.5">
          {!collapsed && <p className="eyebrow px-3 pb-1">estate</p>}
          <nav className="flex flex-col gap-0.5" aria-label="Estate">
            {estateItems.map((item) => (
              <SidebarNavLink key={item.to} item={item} collapsed={collapsed} onNavigate={onNavigate} />
            ))}
          </nav>
        </div>

        {adminItems.length > 0 && (
          <div className="flex flex-col gap-0.5">
            {!collapsed && <p className="eyebrow px-3 pb-1">administration</p>}
            <nav className="flex flex-col gap-0.5" aria-label="Administration">
              {adminItems.map((item) => (
                <SidebarNavLink key={item.to} item={item} collapsed={collapsed} onNavigate={onNavigate} />
              ))}
            </nav>
          </div>
        )}
      </div>

      <div
        className={cn(
          "mt-auto flex items-center gap-1 border-t border-hairline pt-3",
          collapsed && "flex-col-reverse justify-end",
        )}
      >
        <DropdownMenu>
          <DropdownMenuTrigger
            className={cn(
              "flex min-w-0 flex-1 items-center gap-2 rounded-md px-1.5 py-1.5 text-left transition-colors duration-150 hover:bg-subtle",
              collapsed && "flex-none justify-center px-0",
            )}
          >
            <span className="grid size-7 shrink-0 place-items-center rounded-full bg-brand text-[11px] font-semibold text-primary-foreground">
              {initials}
            </span>
            {!collapsed && <span className="min-w-0 flex-1 truncate text-sm text-ink">{user?.name}</span>}
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" side="top" className="w-60">
            <DropdownMenuLabel className="font-normal">
              <p className="text-sm font-medium text-ink">{user?.name}</p>
              <p className="truncate font-mono text-xs text-ink-muted">{user?.email}</p>
              <p className="mt-1 text-xs text-ink-muted">
                {permissions.isGlobalAdmin
                  ? "Administrator — all departments"
                  : `${permissions.grantedDepartmentIds.length} department${
                      permissions.grantedDepartmentIds.length === 1 ? "" : "s"
                    }`}
              </p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={logout}>
              <LogOut className="size-3.5" aria-hidden />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <Button
          variant="ghost"
          size="icon-sm"
          onClick={(event) => toggleTheme(event.currentTarget)}
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
        >
          {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </Button>
      </div>
    </div>
  );
}

/** The slim breadcrumb strip above every page — just enough chrome to
 *  place the sidebar's mobile trigger and say where you are, without
 *  duplicating each page's own `PageHeader` title in a second, larger
 *  size. */
function TopBar({ onOpenMobileNav }: { onOpenMobileNav: () => void }) {
  const location = useLocation();
  const { permissions } = useAuth();
  const adminItems = permissions.isGlobalAdmin ? ADMIN_NAV : [];

  const currentLabel = useMemo(() => {
    const all = [...POSTURE_NAV, ...ESTATE_NAV, ...adminItems];
    // Longest matching `to` wins, so `/scans/9` (scan detail) still
    // resolves to the "Scans" nav item rather than falling through.
    const match = all
      .filter((item) => (item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to)))
      .sort((a, b) => b.to.length - a.to.length)[0];
    return match?.label;
  }, [location.pathname, adminItems]);

  return (
    <div data-print-hide className="sticky top-0 z-20">
      <div className="flex h-14 items-center gap-3 border-b border-hairline bg-page px-4 sm:px-6">
        <Button
          variant="ghost"
          size="icon"
          onClick={onOpenMobileNav}
          className="lg:hidden"
          aria-label="Open navigation"
        >
          <Menu className="size-4" />
        </Button>
        {currentLabel && (
          <span className="text-sm font-medium text-ink lowercase">{currentLabel}</span>
        )}
      </div>
      <div
        aria-hidden
        className="h-[3px] bg-gradient-to-r from-brand via-brand-light to-transparent opacity-70"
      />
    </div>
  );
}

function PageFallback() {
  return (
    <div className="flex items-center justify-center py-20">
      <LoaderCircle className="size-5 animate-spin text-ink-muted" aria-hidden />
    </div>
  );
}

export function AppShell() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [collapsed, setCollapsed] = useSidebarCollapsed();

  return (
    <div className="flex min-h-screen bg-page">
      <aside
        data-print-hide
        className={cn(
          "relative hidden shrink-0 border-r border-hairline transition-[width] duration-150 lg:block",
          collapsed ? "w-[68px]" : "w-60",
        )}
      >
        <div className="sticky top-0 h-screen overflow-hidden">
          <SidebarContent collapsed={collapsed} />
        </div>

        {/* Freshservice-style rail toggle: straddles the sidebar's own
            border rather than living inside the scrollable content, so
            it's reachable in exactly the same spot whether the sidebar is
            open or closed. */}
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={() => setCollapsed((value) => !value)}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              className="absolute top-16 -right-3 z-10 grid size-6 place-items-center rounded-full border border-hairline bg-panel text-ink-muted shadow-sm transition-colors hover:text-ink"
            >
              {collapsed ? <ChevronsRight className="size-3.5" /> : <ChevronsLeft className="size-3.5" />}
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">{collapsed ? "Expand sidebar" : "Collapse sidebar"}</TooltipContent>
        </Tooltip>
      </aside>

      <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
        <SheetContent side="left" className="w-72 p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarContent onNavigate={() => setMobileNavOpen(false)} />
        </SheetContent>
      </Sheet>

      <div className="min-w-0 flex-1">
        <TopBar onOpenMobileNav={() => setMobileNavOpen(true)} />
        <main className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6">
          <div className="space-y-5">
            <StatusRegion />
            {/* Every page below is lazy-loaded (see App.tsx) — this is what
                shows while its chunk downloads, so the sidebar/top bar stay
                put instead of the whole shell blanking out. */}
            <Suspense fallback={<PageFallback />}>
              <Outlet />
            </Suspense>
          </div>
        </main>
      </div>
    </div>
  );
}

/** Page title block. Consistent placement is what makes the app read as one
 *  product rather than a set of pages. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0 space-y-1">
        <h1 className="font-display text-[38px] font-light tracking-[-0.035em] text-ink">{title}</h1>
        {description && (
          <p className="max-w-3xl text-sm leading-relaxed text-ink-secondary">{description}</p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

/** The one surface every screen uses. Vercel's cards read tighter and
 *  flatter than the previous rounded-xl/soft-shadow treatment. */
export function Panel({
  children,
  className,
  padded = true,
}: {
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <section
      className={cn(
        "rounded-lg border border-hairline bg-panel transition-shadow duration-150 hover:shadow-[var(--shadow-lift)]",
        padded && "p-4 sm:p-5",
        className,
      )}
    >
      {children}
    </section>
  );
}
