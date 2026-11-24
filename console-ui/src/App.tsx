import { useEffect, useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, type Me } from "@/lib/api";
import { GROUPS, PAGES } from "@/pages";
import { Menu } from "lucide-react";

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

// The sidebar, as the approved design draws it (design-screens People): a card on the ground, muted items, a disc on
// the current one, group names above their pages, and the live status, the person and Sign out at the foot.
// Items are 36px, not the design's 44px: the design had 6 pages and this has 17, and the foot must stay in view.
// Every item keeps the disc's room in its left padding, so labels line up with the group names and nothing shifts.
const item =
  "t-body flex min-h-9 items-center gap-2 rounded-pill pr-4 no-underline text-muted-foreground hover:text-foreground before:size-2 before:flex-none before:rounded-pill before:content-['']";
const current_item = "text-foreground before:bg-foreground";
const group = "t-small px-4 pt-4 pb-1 text-muted-foreground";

/// The live status at the foot of the sidebar: /console/live.json every 2 seconds while the tab is visible,
/// paused when it is hidden or the poll fails (the server-rendered pages' console.js does the same).
function useLive() {
  const [live, setLive] = useState<{ state: "checking" | "live" | "paused"; last?: number | null }>({ state: "checking" });
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    const tick = () => {
      timer = undefined;
      if (document.hidden) return setLive({ state: "paused" });
      fetch("/console/live.json", { credentials: "same-origin", cache: "no-store" })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null)
        .then((j: { last_request_ms: number | null } | null) => {
          setLive(j ? { state: "live", last: j.last_request_ms } : { state: "paused" });
          if (!stopped) timer = setTimeout(tick, 2000);
        });
    };
    const onVisible = () => (document.hidden ? setLive({ state: "paused" }) : timer ? null : tick());
    document.addEventListener("visibilitychange", onVisible);
    tick();
    return () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);
  return live;
}

export function App() {
  const { route, query } = useHash();
  const current = PAGES.find((p) => p.route === route) ?? PAGES[0];
  const [me, setMe] = useState<Me | null>(null);
  const [menu, setMenu] = useState(false);
  const live = useLive();
  useEffect(() => {
    api.get<Me>("me").then(setMe).catch(() => setMe(null));
  }, []);
  useEffect(() => setMenu(false), [route]);
  const tools = me?.tools.filter((t) => !PAGES.some((p) => p.label === t.label)) ?? [];
  const shown = PAGES.filter((p) => !p.hidden);
  const link = (p: (typeof PAGES)[number]) => (
    <a key={p.route} href={`#${p.route}`} aria-current={current === p ? "page" : undefined} className={cn(item, current === p && current_item)}>
      {p.label}
    </a>
  );
  const status =
    live.state === "live"
      ? `Live, ${typeof live.last === "number" ? `last request ${new Date(live.last).toLocaleTimeString()}` : "no requests yet"}`
      : live.state === "paused"
        ? "Paused"
        : "Checking requests";
  return (
    <div className="flex min-h-screen flex-col gap-4 p-2 md:flex-row md:items-start md:p-4">
      <nav
        aria-label="Console"
        className="flex flex-none flex-col rounded-panel bg-card p-2 md:sticky md:top-4 md:max-h-[calc(100vh-var(--space-8))] md:w-nav md:overflow-y-auto md:p-4"
      >
        <div className="flex items-center justify-between">
          <a href="#/start" className="flex min-h-11 items-center gap-3 px-2 no-underline text-foreground md:pb-2">
            {/* The Enterplace mark: a dot and a bar. */}
            <span aria-hidden="true" className="inline-flex flex-none items-center gap-1">
              <span className="size-3 rounded-pill bg-foreground" />
              <span className="h-6 w-2 rounded-pill bg-foreground" />
            </span>
            <span className="t-sm">Enterplace</span>
          </a>
          <button
            type="button"
            aria-expanded={menu}
            onClick={() => setMenu(!menu)}
            className="t-small flex min-h-11 items-center gap-2 rounded-pill bg-transparent px-4 text-foreground md:hidden"
          >
            <Menu aria-hidden="true" className="size-4" />
            Menu
          </button>
        </div>
        <div className={cn("flex-col", menu ? "flex" : "hidden md:flex")}>
          {shown.filter((p) => !p.group).map(link)}
          {GROUPS.map((g) => (
            <div key={g} role="group" aria-label={g} className="flex flex-col">
              <span className={group}>{g}</span>
              {shown.filter((p) => p.group === g).map(link)}
            </div>
          ))}
          {/* The pages an embedding binary adds that are still server rendered: linked as they are. */}
          {tools.length ? (
            <div role="group" aria-label="Tools" className="flex flex-col">
              <span className={group}>Tools</span>
              {tools.map((t) => (
                <a key={t.href} href={t.href} className={item}>
                  {t.label}
                </a>
              ))}
            </div>
          ) : null}
          <div className="mt-6 grid gap-2 border-t border-border px-4 pt-4 pb-2">
            <span data-live={live.state} className="t-small inline-flex items-center gap-2 text-foreground">
              <span aria-hidden="true" className={cn("size-3 flex-none rounded-pill border border-foreground", live.state === "live" ? "bg-lime" : "bg-transparent")} />
              {status}
            </span>
            {me ? (
              <>
                <span className="t-small font-mono text-muted-foreground">
                  {me.name}, {me.role}
                </span>
                <a href="/console/sign-out" className="t-small text-foreground">
                  Sign out
                </a>
              </>
            ) : null}
          </div>
        </div>
      </nav>
      <main className="grid min-w-0 flex-1 content-start gap-6 px-2 py-4 md:px-4 md:py-6">
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
      </main>
      <Toaster />
    </div>
  );
}
