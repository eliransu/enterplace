import { useEffect, useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, type Me } from "@/lib/api";
import { Providers } from "@/pages/Providers";
import { McpServers } from "@/pages/McpServers";
import { PolicyBasics } from "@/pages/PolicyBasics";

// The pages of this app, by hash, and the server-rendered pages the console still serves, linked as they are.
const PAGES = [
  { hash: "#/providers", label: "Models and providers" },
  { hash: "#/mcp", label: "MCP servers" },
  { hash: "#/policy", label: "Policy basics" },
] as const;

const SERVER_PAGES: [string, [string, string][]][] = [
  ["", [["/console/start", "Start here"]]],
  ["Activity", [["/console/requests", "Requests"], ["/console/audit", "Audit log"], ["/console/analytics", "Analytics"], ["/console/spend", "Spend"]]],
  ["Access", [["/console/people", "People"], ["/console/policy", "Raw policy"], ["/console/models", "Prices"], ["/console/credentials", "Credentials"]]],
  ["Tools", [["/console/mcp/tools", "MCP tools"], ["/console/mcp/approvals", "MCP approvals"]]],
];

function useHash() {
  const [hash, setHash] = useState(window.location.hash || "#/providers");
  useEffect(() => {
    const on = () => setHash(window.location.hash || "#/providers");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

const item = "t-body flex min-h-11 items-center rounded-small px-4 no-underline text-foreground hover:bg-secondary";

export function App() {
  const hash = useHash();
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    api.get<Me>("me").then(setMe).catch(() => setMe(null));
  }, []);
  return (
    <div className="grid min-h-screen md:grid-cols-[var(--nav)_1fr]">
      <nav aria-label="Console" className="grid content-start gap-1 border-b border-border p-4 md:border-r md:border-b-0">
        <a href="/console/start" className="flex min-h-11 items-center gap-2 px-4 no-underline text-foreground">
          {/* The Enterplace mark, as the console's g-mark draws it: a dot and a bar. */}
          <span aria-hidden="true" className="inline-flex flex-none items-center gap-1">
            <span className="size-3 rounded-pill bg-foreground" />
            <span className="h-6 w-2 rounded-pill bg-foreground" />
          </span>
          <span className="t-sm">Enterplace</span>
        </a>
        <span className="t-tag px-4 pt-4 uppercase text-muted-foreground">Manage</span>
        {PAGES.map((p) => (
          <a key={p.hash} href={p.hash} aria-current={hash === p.hash ? "page" : undefined} className={cn(item, hash === p.hash && "bg-secondary")}>
            {p.label}
          </a>
        ))}
        {SERVER_PAGES.map(([group, links]) => (
          <div key={group} className="grid gap-1">
            {group ? <span className="t-tag px-4 pt-4 uppercase text-muted-foreground">{group}</span> : null}
            {links.map(([href, label]) => (
              <a key={href} href={href} className={item}>
                {label}
              </a>
            ))}
          </div>
        ))}
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
        {me && !me.edit_policy ? (
          <div role="status" className="t-body rounded-panel border border-input p-4">
            Read only: your role may not change the policy. Ask an admin whose role has edit_policy.
          </div>
        ) : null}
        {hash === "#/mcp" ? <McpServers me={me} /> : hash === "#/policy" ? <PolicyBasics me={me} /> : <Providers me={me} />}
        {me ? (
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
