import type { LucideIcon } from "lucide-react";
import { Blocks, Server, SquareTerminal, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Head, Problem } from "@/components/page";
import { unnamed } from "@/components/person";
import { api, type Me } from "@/lib/api";
import { count, num, useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import { Setup, type SetupState } from "./Setup";
import { isService, type Keys } from "./People";
import type { PageProps } from "@/pages";

// The analytics answer, as far as Overview reads it: a breakdown's rows, or `empty` when nothing was ever sent.
export type Ranking = {
  empty?: unknown;
  ranking?: {
    value: string;
    requests: string;
    refused: string;
    usd: string;
    href: string;
  }[];
  stats?: { figure: string; label: string }[];
};
// The coding agents the gateway tells apart by their user agent (enterplace_core::audit::tool_of). An SDK's user agent
// (OpenAI/Python) is an app, not a coding agent.
export const CODING_TOOLS = ["claude-code", "codex", "gemini-cli", "qwen-code", "github-copilot", "cursor", "kilo-code", "roo-code", "cline", "opencode"];

export const figure = (s: string) => Number(s.replace(/[^\d.]/g, "")) || 0;

/// Requests recorded under no name in a ranking by person.
export const unnamedIn = (r: Ranking | null) => figure(r?.ranking?.find((x) => unnamed(x.value))?.requests ?? "0");

/// What needs the admin about names: requests may go unnamed, or `seen` did in the last day.
export function nameWarning(
  me: Me | null,
  seen: number,
): { title: string; body: string } | null {
  const n = me?.names;
  if (!n) return null;
  if (!n.required && n.passthrough) {
    return {
      title:
        seen > 0
          ? `${count(seen, "request")} without a name in the last 24 hours`
          : "Requests without a name are allowed",
      body: "A coding agent with no person token is recorded as unnamed. Hand out person tokens, then turn on Every request needs a name.",
    };
  }
  if (seen > 0) {
    return {
      title: `${count(seen, "request")} without a name in the last 24 hours`,
      body: "They came with no valid key or person token, so they were refused. Hand out a key or a person token to whoever sent them.",
    };
  }
  return null;
}

type Card = {
  id: string;
  title: string;
  icon: LucideIcon;
  line: string;
  facts: { figure: string; label: string }[];
  live: boolean;
  status: string;
  attention: string[];
  next: { label: string; href: string };
};

export function Overview({ me, query }: PageProps) {
  const start = useData<SetupState>("start");
  const keys = useData<Keys>("people");
  const agents = useData<Ranking>("analytics?by=agent&window=24h");
  const persons = useData<Ranking>("analytics?by=person&window=24h");
  const mcp = useData<{ servers: unknown[] }>("mcp");
  const approvals = useData<{ calls?: unknown[] }>("mcp-approvals");

  // An empty install: nothing sent, nothing chosen. Each card's button then starts that use case's checklist.
  const choosing = start.data?.view === "welcome";
  const may = !!start.data?.may_choose;
  const entries = keys.data?.entries ?? [];
  const services = entries.filter(isService);
  const people = entries.filter((e) => !isService(e));
  const tools = (agents.data?.ranking ?? []).filter(
    (r) => CODING_TOOLS.includes(r.value),
  );
  const codingToday = tools.reduce((n, r) => n + figure(r.requests), 0);
  const byName = new Map(
    (persons.data?.ranking ?? []).map((r) => [r.value, figure(r.requests)]),
  );
  const appsToday = services.reduce((n, s) => n + (byName.get(s.name) ?? 0), 0);
  const appsSeen = services.filter((s) => byName.get(s.name)).length;
  const peopleToday = [...byName.keys()].filter(
    (name) => !unnamed(name) && people.some((p) => p.name === name),
  ).length;
  const servers = mcp.data?.servers.length ?? 0;
  const waiting = approvals.data?.calls?.length ?? 0;
  // ponytail: read from the 24 hour ranking, which lists the 25 costliest names; a busy install may cut unnamed off.
  const names = nameWarning(me, unnamedIn(persons.data));
  const loaded = !!(keys.data && agents.data && persons.data);

  const cards: Card[] = [
    {
      id: "coding",
      title: "Coding agents",
      icon: SquareTerminal,
      line: "Claude Code, Codex, Cursor, Copilot and the rest, each request under the person who sent it.",
      facts: [
        { figure: num(codingToday), label: "requests today" },
        {
          figure: num(peopleToday),
          label: peopleToday === 1 ? "person today" : "people today",
        },
        {
          figure: num(tools.length),
          label: tools.length === 1 ? "tool seen" : "tools seen",
        },
      ],
      live: codingToday > 0,
      status:
        codingToday > 0
          ? "Requests today"
          : tools.length
            ? "No requests today"
            : "Not connected yet",
      attention: names ? [names.title] : [],
      next:
        codingToday === 0
          ? { label: "Connect a coding agent", href: "#/coding" }
          : names
            ? {
                label: "Hand out person tokens",
                href: "#/coding?issue=1&token=1",
              }
            : { label: "See who uses which tool", href: "#/coding" },
    },
    {
      id: "apps",
      title: "Apps and agents",
      icon: Blocks,
      line: "Internal apps, custom agents and cloud agents that call models with a service key.",
      facts: [
        { figure: num(appsToday), label: "requests today" },
        {
          figure: num(appsSeen),
          label: appsSeen === 1 ? "app today" : "apps today",
        },
        {
          figure: num(services.length),
          label: services.length === 1 ? "service key" : "service keys",
        },
      ],
      live: appsToday > 0,
      status:
        appsToday > 0
          ? "Requests today"
          : services.length
            ? "No requests today"
            : "Not connected yet",
      attention: [],
      next:
        services.length === 0
          ? { label: "Make a service key", href: "#/apps?issue=1" }
          : appsToday === 0
            ? { label: "Connect an app", href: "#/apps" }
            : { label: "Set budgets per app", href: "#/apps" },
    },
    {
      id: "mcp",
      title: "MCP tools",
      icon: Server,
      line: "MCP servers behind Enterplace, which tools each team may call, and the calls that wait for an admin.",
      facts: [
        { figure: num(servers), label: servers === 1 ? "server" : "servers" },
        { figure: num(waiting), label: "calls waiting" },
      ],
      live: false,
      status: servers ? "Connected" : "Not connected yet",
      attention: waiting
        ? [`${count(waiting, "call")} waiting for approval`]
        : [],
      next:
        servers === 0
          ? { label: "Add an MCP server", href: "#/mcp?add=1" }
          : waiting
            ? { label: "Review approvals", href: "#/mcp/approvals" }
            : { label: "Review tools", href: "#/mcp/tools" },
    },
  ];

  // Before anything is chosen, a card's button keeps the choice (so the checklist follows it) and opens its page.
  const setUp = (id: string, href: string) =>
    start.change(async () => {
      const done = await api.post("start/pick", { choice: id });
      window.location.hash = href;
      return done;
    });

  const attention = [
    ...(names
      ? [
          {
            ...names,
            action: {
              label: "Hand out person tokens",
              href: "#/coding?issue=1&token=1",
            },
          },
        ]
      : []),
    ...(waiting
      ? [
          {
            title: `${count(waiting, "MCP tool call")} waiting for approval`,
            body: "The agent that made each call waits until an admin approves or denies it, or its time runs out.",
            action: { label: "Review approvals", href: "#/mcp/approvals" },
          },
        ]
      : []),
  ];

  return (
    <>
      <Head
        title="Overview"
        lead={
          choosing
            ? "Start here: pick the use case to connect first. Each one is a short checklist that ticks itself as the gateway sees it happen."
            : "What goes through Enterplace, by use case."
        }
      />
      {keys.error && agents.error ? (
        <Problem text={keys.error} retry={keys.reload} />
      ) : null}
      {attention.length ? (
        <section aria-label="Needs attention" className="grid gap-2">
          {attention.map((a) => (
            <div
              key={a.title}
              className="flex flex-wrap items-center gap-4 rounded-panel border border-input p-4"
            >
              <TriangleAlert aria-hidden="true" className="size-4 flex-none" />
              <div className="grid min-w-0 flex-1 gap-1">
                <span className="t-body-strong">{a.title}</span>
                <span className="t-small text-muted-foreground">{a.body}</span>
              </div>
              <Button size="sm" variant="outline" asChild>
                <a href={a.action.href}>{a.action.label}</a>
              </Button>
            </div>
          ))}
        </section>
      ) : null}
      <section aria-label="Use cases" className="grid gap-4 lg:grid-cols-3">
        {cards.map((c) => (
          <article
            key={c.id}
            className="grid min-w-0 grid-rows-[auto_auto_1fr_auto] gap-4 rounded-panel bg-card p-6"
          >
            <div className="flex items-center justify-between gap-2">
              <a
                href={`#/${c.id}`}
                className="flex min-w-0 items-center gap-2 no-underline text-foreground"
              >
                <c.icon aria-hidden="true" className="size-4 flex-none" />
                <h2 className="t-sm m-0 truncate">{c.title}</h2>
              </a>
              {loaded ? (
                <span className="t-small flex flex-none items-center gap-2 text-muted-foreground">
                  <span
                    aria-hidden="true"
                    className={cn(
                      "size-2 rounded-pill border border-foreground",
                      c.live && "border-lime bg-lime",
                    )}
                  />
                  {c.status}
                </span>
              ) : null}
            </div>
            <p className="t-small m-0 text-muted-foreground">{c.line}</p>
            <div className="grid content-start gap-4">
              <dl className="m-0 grid grid-cols-3 gap-2">
                {c.facts.map((f) => (
                  <div key={f.label} className="grid min-w-0 gap-1">
                    <dt className="t-small order-2 text-muted-foreground">
                      {f.label}
                    </dt>
                    <dd className="t-md m-0 tabular-nums">
                      {loaded ? f.figure : <Skeleton className="h-8 w-12" />}
                    </dd>
                  </div>
                ))}
              </dl>
              {c.attention.map((a) => (
                <p key={a} className="t-small m-0 flex items-center gap-2">
                  <TriangleAlert
                    aria-hidden="true"
                    className="size-4 flex-none"
                  />
                  {a}
                </p>
              ))}
            </div>
            {choosing && may ? (
              <Button
                className="justify-self-start"
                onClick={() => setUp(c.id, `#/${c.id}`)}
              >
                Set up {c.id === "mcp" ? "MCP tools" : c.title.toLowerCase()}
              </Button>
            ) : (
              <Button
                className="justify-self-start"
                variant={
                  c.next.href.includes("?") || !c.live ? "default" : "outline"
                }
                asChild
              >
                <a href={c.next.href}>{c.next.label}</a>
              </Button>
            )}
          </article>
        ))}
      </section>
      {choosing && !may && start.data ? (
        <p className="t-small m-0 text-muted-foreground">
          Your role cannot choose what this install starts with. An admin can.
        </p>
      ) : null}
      <section aria-label="Setup" className="grid gap-4">
        <Setup query={query} base="/overview" compact />
      </section>
    </>
  );
}
