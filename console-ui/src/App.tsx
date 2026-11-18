import { useEffect, useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, type Me } from "@/lib/api";
import { PAGES } from "@/pages";

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

const item = "t-body flex min-h-11 items-center rounded-small px-4 no-underline text-foreground hover:bg-secondary";

export function App() {
  const { route, query } = useHash();
  const current = PAGES.find((p) => p.route === route) ?? PAGES[0];
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    api.get<Me>("me").then(setMe).catch(() => setMe(null));
  }, []);
  const tools = me?.tools.filter((t) => !PAGES.some((p) => p.label === t.label)) ?? [];
  return (
    <div className="grid min-h-screen md:grid-cols-[var(--nav)_1fr]">
      <nav aria-label="Console" className="grid content-start gap-1 border-b border-border p-4 md:border-r md:border-b-0">
        <a href="#/start" className="flex min-h-11 items-center gap-2 px-4 no-underline text-foreground">
          {/* The Enterplace mark, as the console's g-mark draws it: a dot and a bar. */}
          <span aria-hidden="true" className="inline-flex flex-none items-center gap-1">
            <span className="size-3 rounded-pill bg-foreground" />
            <span className="h-6 w-2 rounded-pill bg-foreground" />
          </span>
          <span className="t-sm">Enterplace</span>
        </a>
        {/* Start here leads, as on the server-rendered nav; the pages after it are under Manage. */}
        {PAGES.filter((p) => !p.hidden).map((p, i) => (
          <div key={p.route} className="contents">
            {i === 1 ? <span className="t-tag px-4 pt-4 uppercase text-muted-foreground">Manage</span> : null}
            <a href={`#${p.route}`} aria-current={current === p ? "page" : undefined} className={cn(item, current === p && "bg-secondary")}>
              {p.label}
            </a>
          </div>
        ))}
        {/* The pages an embedding binary adds that are still server rendered: linked as they are. One moved to the app is listed above. */}
        {tools.length ? (
          <div className="grid gap-1">
            <span className="t-tag px-4 pt-4 uppercase text-muted-foreground">Tools</span>
            {tools.map((t) => (
              <a key={t.href} href={t.href} className={item}>
                {t.label}
              </a>
            ))}
          </div>
        ) : null}
        {me ? (
          <div className="t-small grid gap-1 px-4 pt-6 text-muted-foreground">
            <span className="t-mono">{me.name}</span>
            <span>{me.role}</span>
            <a href="/console/sign-out" className="text-foreground">
              Sign out
            </a>
          </div>
        ) : null}
      </nav>
      <main className="grid max-w-wide content-start gap-8 p-6 md:p-10">
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
