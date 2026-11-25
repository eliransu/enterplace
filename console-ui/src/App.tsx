import { useEffect, useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { RouteTabs } from "@/components/page";
import { cn } from "@/lib/utils";
import type { Me } from "@/lib/api";
import { LiveContext, useLiveFeed, useLiveStream } from "@/lib/live";
import { useData } from "@/lib/use";
import { find, GROUPS, HOME, moved as movedTo, SECTIONS, type Section } from "@/pages";
import { LogOut, Wrench } from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";

/// The # route and its query: `#/people?issue=1` is the People page with its Issue dialog open. A route that moved is
/// replaced by its new one in place, query and all, so the back button does not bounce through it.
function readHash() {
  const [route, query = ""] = (window.location.hash.slice(1) || HOME).split(
    "?",
  );
  const moved = movedTo(route, new URLSearchParams(query));
  if (moved) {
    window.history.replaceState(
      null,
      "",
      `#${moved}${query ? `?${query}` : ""}`,
    );
    return { route: moved, query: new URLSearchParams(query) };
  }
  return { route, query: new URLSearchParams(query) };
}

function useHash() {
  const [hash, setHash] = useState(readHash);
  useEffect(() => {
    const on = () => setHash(readHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

export function App() {
  const live = useLiveStream();
  return (
    <LiveContext.Provider value={live}>
      <Shell />
    </LiveContext.Provider>
  );
}

// The shell is shadcn's Sidebar pattern: icon and label per page, group labels, the current page filled, collapsible
// to icons (Ctrl or Cmd+B), a sheet on phones, and the person and the live status in the footer. A section with more
// than one page shows them as tabs over the page.
function Shell() {
  const { route, query } = useHash();
  const { section, tab } = find(route);
  // Read again on every change, so the name setting and the role are current on every page.
  const { data: me } = useData<Me>("me");
  const live = useLiveFeed();
  // The MCP extension still names its old server-rendered pages; they are tabs of MCP tools now.
  const tools =
    me?.tools.filter(
      (t) =>
        !t.href.startsWith("/console/mcp/") &&
        !SECTIONS.some((s) => s.label === t.label),
    ) ?? [];
  const tabs = section.tabs.filter((t) => !t.hidden);
  useEffect(() => {
    document.title =
      section.tabs.length > 1
        ? `${tab.label}, ${section.label} | Enterplace`
        : `${section.label} | Enterplace`;
  }, [section, tab]);
  const status =
    live.state === "live"
      ? `Live, ${typeof live.last === "number" ? `last request ${new Date(live.last).toLocaleTimeString("en-GB", { timeZone: "UTC" })} UTC` : "no requests yet"}`
      : live.state === "paused"
        ? "Reconnecting"
        : "Connecting";
  return (
    <SidebarProvider>
      <Sidebar>
        <SidebarHeader className="h-14 flex-row items-center justify-between border-b border-border py-0">
          <a
            href={`#${HOME}`}
            className="flex min-w-0 items-center gap-3 px-2 no-underline text-foreground"
          >
            {/* The Enterplace mark: a dot and a bar. */}
            <span
              aria-hidden="true"
              className="inline-flex flex-none items-center gap-1"
            >
              <span className="size-2 rounded-pill bg-foreground" />
              <span className="h-4 w-1.5 rounded-pill bg-foreground" />
            </span>
            <span className="t-sm truncate group-data-collapsed/sidebar:md:hidden">
              Enterplace
            </span>
          </a>
        </SidebarHeader>
        <SidebarContent className="py-2">
          <SidebarGroup>
            <SidebarMenu>
              {SECTIONS.filter((s) => !s.group).map((s) => (
                <NavItem key={s.label} section={s} active={s === section} />
              ))}
            </SidebarMenu>
          </SidebarGroup>
          {GROUPS.map((g) => (
            <SidebarGroup key={g} aria-label={g}>
              <SidebarGroupLabel>{g}</SidebarGroupLabel>
              <SidebarMenu>
                {SECTIONS.filter((s) => s.group === g).map((s) => (
                  <NavItem key={s.label} section={s} active={s === section} />
                ))}
              </SidebarMenu>
            </SidebarGroup>
          ))}
          {/* The pages an embedding binary adds that are still server rendered: linked as they are. */}
          {tools.length ? (
            <SidebarGroup aria-label="Tools">
              <SidebarGroupLabel>Tools</SidebarGroupLabel>
              <SidebarMenu>
                {tools.map((t) => (
                  <SidebarMenuItem key={t.href}>
                    <SidebarMenuButton asChild tooltip={t.label}>
                      <a href={t.href}>
                        <Wrench aria-hidden="true" />
                        <span>{t.label}</span>
                      </a>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroup>
          ) : null}
        </SidebarContent>
        <SidebarFooter>
          <span
            data-live={live.state}
            title={status}
            className="t-small flex h-8 items-center gap-3 px-2 text-muted-foreground"
          >
            <span
              aria-hidden="true"
              className="flex size-4 flex-none items-center justify-center"
            >
              <span
                className={cn(
                  "size-2 rounded-pill border border-foreground",
                  live.state === "live"
                    ? "border-lime bg-lime"
                    : "bg-transparent",
                )}
              />
            </span>
            <span className="truncate group-data-collapsed/sidebar:md:hidden">
              {status}
            </span>
          </span>
          {me ? (
            <div className="flex items-center gap-3 rounded-box px-2 py-1">
              <span
                aria-hidden="true"
                className="t-small flex size-8 flex-none items-center justify-center rounded-pill bg-accent font-semibold text-foreground"
              >
                {me.name.slice(0, 1).toUpperCase()}
              </span>
              <span className="grid min-w-0 flex-1 group-data-collapsed/sidebar:md:hidden">
                <span
                  className="t-small truncate font-semibold text-foreground"
                  title={me.name}
                >
                  {me.name}
                </span>
                <span className="t-small truncate text-muted-foreground">
                  {me.role}
                </span>
              </span>
              <a
                href="/console/sign-out"
                aria-label="Sign out"
                title="Sign out"
                className="inline-flex size-8 flex-none items-center justify-center rounded-box text-muted-foreground hover:bg-accent hover:text-foreground group-data-collapsed/sidebar:md:hidden [&_svg]:size-4"
              >
                <LogOut aria-hidden="true" />
              </a>
            </div>
          ) : null}
        </SidebarFooter>
      </Sidebar>
      <SidebarInset className="grid min-w-0 content-start gap-6 px-4 pb-10 md:px-8">
        <header className="sticky top-0 z-10 -mx-4 flex h-14 items-center gap-2 border-b border-border bg-background px-4 md:-mx-8 md:px-8">
          <SidebarTrigger className="-ml-2" />
          <span aria-hidden="true" className="h-4 border-l border-border" />
          <nav
            aria-label="Breadcrumb"
            className="t-small flex min-w-0 items-center gap-2 text-muted-foreground"
          >
            {section.group ? (
              <>
                <span className="hidden sm:inline">{section.group}</span>
                <span aria-hidden="true" className="hidden sm:inline">
                  /
                </span>
              </>
            ) : null}
            <span className="truncate text-foreground">{section.label}</span>
          </nav>
        </header>
        {me?.observe ? (
          <div
            role="status"
            className="t-small flex flex-wrap items-center justify-between gap-2 rounded-box border border-input px-4 py-2"
          >
            <span>
              Observe mode: rules, limits and guardrails only record what they
              would refuse. A request without a valid key or person token, an
              unknown model and a kill switch are still refused.
            </span>
            <a href="#/policy">Turn on enforcement</a>
          </div>
        ) : null}
        {tabs.length > 1 ? (
          <RouteTabs label={section.label} tabs={tabs} current={tab.route} />
        ) : null}
        {tab.policy && me && !me.edit_policy ? (
          <div
            role="status"
            className="t-body rounded-panel border border-input p-4"
          >
            Read only: your role may not change the policy. Ask an admin whose
            role may edit it.
          </div>
        ) : null}
        {/* Keyed by the route, so a page's own state (a search, an open form) does not leak into the next page. */}
        <tab.page key={tab.route} me={me} query={query} />
        {tab.policy && me ? (
          <p className="t-small m-0 text-muted-foreground">
            {me.source === "store"
              ? "Each change is saved as a new policy version, checked as enterplace check checks a file, and recorded with your name."
              : `Each change rewrites ${me.policy} once it passes enterplace check, and is recorded with your name. Comments in the file are not kept.`}
          </p>
        ) : null}
      </SidebarInset>
      <Toaster />
    </SidebarProvider>
  );
}

function NavItem({ section, active }: { section: Section; active: boolean }) {
  const { setMobileOpen } = useSidebar();
  const Icon = section.icon;
  const to = section.tabs[0].route;
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={active} tooltip={section.label}>
        <a
          href={`#${to}`}
          aria-current={active ? "page" : undefined}
          onClick={() => setMobileOpen(false)}
        >
          <Icon aria-hidden="true" />
          <span>{section.label}</span>
        </a>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}
