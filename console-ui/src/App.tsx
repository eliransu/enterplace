import { useEffect, useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, type Me } from "@/lib/api";
import { LiveContext, useLiveStream } from "@/lib/live";
import { GROUPS, PAGES } from "@/pages";
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

/// The # route and its query: `#/people?issue=1` is the People page with its Issue dialog open.
function useHash() {
  const read = () => {
    const [route, query = ""] = (window.location.hash.slice(1) || "/start").split("?");
    return { route, query: new URLSearchParams(query) };
  };
  const [hash, setHash] = useState(read);
  useEffect(() => {
    const on = () => setHash(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

// The shell is shadcn's Sidebar pattern: icon and label per page, group labels, the current page filled, collapsible
// to icons (Ctrl or Cmd+B), a sheet on phones, and the person and the live status in the footer.
export function App() {
  const { route, query } = useHash();
  const current = PAGES.find((p) => p.route === route) ?? PAGES[0];
  const [me, setMe] = useState<Me | null>(null);
  const live = useLiveStream();
  useEffect(() => {
    api
      .get<Me>("me")
      .then(setMe)
      .catch(() => setMe(null));
  }, []);
  const tools = me?.tools.filter((t) => !PAGES.some((p) => p.label === t.label)) ?? [];
  const shown = PAGES.filter((p) => !p.hidden);
  const status =
    live.state === "live"
      ? `Live, ${typeof live.last === "number" ? `last request ${new Date(live.last).toLocaleTimeString()}` : "no requests yet"}`
      : live.state === "paused"
        ? "Reconnecting"
        : "Connecting";
  return (
    <LiveContext.Provider value={live}>
      <SidebarProvider>
        <Sidebar>
          <SidebarHeader className="h-14 flex-row items-center justify-between border-b border-border py-0">
            <a href="#/start" className="flex min-w-0 items-center gap-3 px-2 no-underline text-foreground">
              {/* The Enterplace mark: a dot and a bar. */}
              <span aria-hidden="true" className="inline-flex flex-none items-center gap-1">
                <span className="size-2 rounded-pill bg-foreground" />
                <span className="h-4 w-1.5 rounded-pill bg-foreground" />
              </span>
              <span className="t-sm truncate group-data-collapsed/sidebar:md:hidden">Enterplace</span>
            </a>
          </SidebarHeader>
          <SidebarContent className="py-2">
            <SidebarGroup>
              <SidebarMenu>
                {shown
                  .filter((p) => !p.group)
                  .map((p) => (
                    <NavItem key={p.route} page={p} active={current === p} />
                  ))}
              </SidebarMenu>
            </SidebarGroup>
            {GROUPS.map((g) => (
              <SidebarGroup key={g} aria-label={g}>
                <SidebarGroupLabel>{g}</SidebarGroupLabel>
                <SidebarMenu>
                  {shown
                    .filter((p) => p.group === g)
                    .map((p) => (
                      <NavItem key={p.route} page={p} active={current === p} />
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
            <span data-live={live.state} title={status} className="t-small flex h-8 items-center gap-3 px-2 text-muted-foreground">
              <span aria-hidden="true" className="flex size-4 flex-none items-center justify-center">
                <span
                  className={cn(
                    "size-2 rounded-pill border border-foreground",
                    live.state === "live" ? "border-lime bg-lime" : "bg-transparent",
                  )}
                />
              </span>
              <span className="truncate group-data-collapsed/sidebar:md:hidden">{status}</span>
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
                  <span className="t-small truncate font-semibold text-foreground">{me.name}</span>
                  <span className="t-small truncate text-muted-foreground">{me.role}</span>
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
        <SidebarInset className="grid content-start gap-6 px-4 pb-6 md:px-8">
          <header className="sticky top-0 z-10 -mx-4 flex h-14 items-center gap-2 border-b border-border bg-background px-4 md:-mx-8 md:px-8">
            <SidebarTrigger className="-ml-2" />
            <span aria-hidden="true" className="h-4 border-l border-border" />
            <nav aria-label="Breadcrumb" className="t-small flex min-w-0 items-center gap-2 text-muted-foreground">
              {current.group ? (
                <>
                  <span>{current.group}</span>
                  <span aria-hidden="true">/</span>
                </>
              ) : null}
              <span className="truncate text-foreground">{current.label}</span>
            </nav>
          </header>
          {me?.observe ? (
            <p className="t-small m-0 text-muted-foreground">
              Observe mode: rules only record. <a href="#/start?track=limit">Turn on enforcement</a>
            </p>
          ) : null}
          {current.policy && me && !me.edit_policy ? (
            <div role="status" className="t-body rounded-panel border border-input p-4">
              Read only: your role may not change the policy. Ask an admin whose role has edit_policy.
            </div>
          ) : null}
          <current.page me={me} query={query} />
          {current.policy && me ? (
            <p className="t-small m-0 text-muted-foreground">
              {me.source === "store"
                ? "Each change is saved as a new policy version, checked as enterplace check checks a file, and recorded with your name."
                : `Each change rewrites ${me.policy} once it passes enterplace check, and is recorded with your name. Comments in the file are not kept.`}
            </p>
          ) : null}
        </SidebarInset>
        <Toaster />
      </SidebarProvider>
    </LiveContext.Provider>
  );
}

function NavItem({ page, active }: { page: (typeof PAGES)[number]; active: boolean }) {
  const { setMobileOpen } = useSidebar();
  const Icon = page.icon;
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={active} tooltip={page.label}>
        <a href={`#${page.route}`} aria-current={active ? "page" : undefined} onClick={() => setMobileOpen(false)}>
          {Icon ? <Icon aria-hidden="true" /> : null}
          <span>{page.label}</span>
        </a>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}
