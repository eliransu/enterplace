import { Fragment, useEffect, useState } from "react";
import { Check } from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Head, Problem, Refusal } from "@/components/page";
import { Copy } from "@/components/copy";
import { api } from "@/lib/api";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import type { PageProps } from "@/pages";

type Tabs = { param: string; label: string; options: { id: string; label: string }[]; selected: string; keep: Record<string, string> } | null;
type Input_ = { name: string; label: string; placeholder?: string; secret?: boolean; options?: { id: string; label: string }[] };
type Block =
  | { type: "p" | "note"; text: string }
  | { type: "link"; label: string; href: string }
  | { type: "button"; label: string; action: string; body: Record<string, string> | null; quiet: boolean }
  | { type: "actions"; items: Block[] }
  | { type: "command"; text: string }
  | { type: "lines"; id: string; tabs: Tabs; caption: string; lines: string[] }
  | { type: "form"; action: string; button: string; hidden: Record<string, string>; fields: Input_[]; after: string }
  | {
      type: "policy";
      id: string;
      marks: { n: number; text: string; kind: string }[];
      plain: string;
      way: { kind: "draft"; label: string; href: string } | { kind: "cannot"; text: string } | { kind: "copy"; text: string; path: string };
    };
type Step = {
  n: number;
  title: string;
  optional: boolean;
  state: "done" | "now" | "listening" | "ahead";
  word: string;
  body: Block[];
  agent: string;
  listen: string;
  open: { label: string; href: string } | null;
  done_text: string;
};
type Track = { id: string; name: string; button: string; line: string; covers: string; steps: number; enterprise: boolean };
type Live = { count: string; tools: string[]; providers: string[]; rows: { id: string; time: string; person: string; model: string; refused: boolean; code: string }[] };
type Stages = {
  steps: { name: string; state: string; word: string }[];
  current: {
    n: number;
    title: string;
    lead: string;
    why: string;
    action: { label: string; href: string };
    guide: { label: string; href: string };
    when: { text: string; value: string }[];
  } | null;
};
type State = {
  base: string;
  problem: string;
  may_choose: boolean;
  tracks: Track[];
  choice: string | null;
  query: string;
  view: "welcome" | "pick" | "checklist" | "folded";
  lead: string;
  signature: string;
  track?: string;
  name?: string;
  live?: Live | null;
  viewing?: string;
  pay?: "api" | "subscriptions" | null;
  steps?: Step[];
  banner?: boolean;
  others?: Track[];
  made?: { word: string; name: string; team: string; key: string } | null;
  folded?: string;
  stages?: Stages;
};
type Answer = { message: string; query?: string; state?: State };
type Act = (action: string, body: Record<string, unknown>) => Promise<string>;

const route = (query: string) => `#/start${query ? `?${query}` : ""}`;

// Text from the API: `value` is set in mono and [label](href) is a link. Nothing else is markup.
function Inline({ text }: { text: string }) {
  return (
    <>
      {text.split(/(`[^`]+`|\[[^\]]+\]\([^)\s]+\))/g).map((part, i) => {
        if (part.length > 1 && part.startsWith("`") && part.endsWith("`")) {
          return (
            <span key={i} className="t-mono">
              {part.slice(1, -1)}
            </span>
          );
        }
        const link = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(part);
        return link ? (
          <a key={i} href={link[2]}>
            {link[1]}
          </a>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        );
      })}
    </>
  );
}

export function Start({ query }: PageProps) {
  const q = query.toString();
  const path = `start${q ? `?${q}` : ""}`;
  // Live: the page reads the gateway's records every 2 seconds, so a step turns done as the gateway sees it happen.
  const { data, error, change } = useData<State>(path, 2000);
  // A view with a key in it, shown once, stays until a step changes; then the polled view takes over, as the old
  // page reloaded only when its signature changed.
  const [held, setHeld] = useState<{ path: string; state: State } | null>(null);
  const shown = held && held.path === path && (!data || data.signature === held.state.signature) ? held.state : data;
  // The welcome has no nav: nothing in it would have data yet.
  const welcome = shown?.view === "welcome";
  useEffect(() => {
    document.documentElement.toggleAttribute("data-bare", welcome);
    return () => document.documentElement.removeAttribute("data-bare");
  }, [welcome]);

  const act: Act = (action, body) =>
    change(async () => {
      // The view the change is made from, so a key made comes back in the lines of that view.
      const answer = (await api.post(`start/${action}`, { ...Object.fromEntries(query), ...body })) as Answer;
      if (answer.state) {
        setHeld({ path: `start${answer.query ? `?${answer.query}` : ""}`, state: answer.state });
      }
      if (answer.query !== undefined) {
        window.location.hash = route(answer.query);
      } else if (action === "pick") {
        window.location.hash = route("");
      }
      return answer;
    });

  if (!shown) {
    return error ? <Problem text={error} /> : <p className="t-body m-0 text-muted-foreground">Reading what the gateway has seen.</p>;
  }
  const problem = shown.problem || error;

  if (shown.view === "welcome") {
    return (
      <div data-welcome className="fixed inset-0 z-10 overflow-auto bg-background">
        <div className="mx-auto grid max-w-wide content-start gap-8 p-6 md:p-10">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <span className="flex items-center gap-2">
              <span aria-hidden="true" className="inline-flex flex-none items-center gap-1">
                <span className="size-3 rounded-pill bg-foreground" />
                <span className="h-6 w-2 rounded-pill bg-foreground" />
              </span>
              <span className="t-sm">Enterplace</span>
            </span>
            <span className="t-small flex items-center gap-2 text-muted-foreground">
              <span aria-hidden="true" className="size-2 rounded-pill bg-lime" />
              Running at {shown.base}
            </span>
          </div>
          {problem ? <Problem text={problem} /> : null}
          <Head title="What do you want to start with?" lead={shown.lead} />
          <Pick state={shown} act={act} />
        </div>
      </div>
    );
  }

  const change_ = shown.may_choose ? (
    <a className="t-small" href={route("pick=1")}>
      Change what to start with
    </a>
  ) : null;

  if (shown.view === "pick") {
    return (
      <>
        <Head title="Start here" lead={shown.lead} />
        {problem ? <Problem text={problem} /> : null}
        <Pick state={shown} act={act} />
      </>
    );
  }

  if (shown.view === "folded") {
    const checklist = new URLSearchParams(shown.query);
    checklist.set("view", "checklist");
    return (
      <>
        <Head title="Start here" lead={shown.lead} />
        {problem ? <Problem text={problem} /> : null}
        {shown.live ? <LiveStrip live={shown.live} /> : null}
        <div className="flex flex-wrap items-center gap-4 rounded-panel bg-card p-6">
          <span aria-hidden="true" className="grid size-8 flex-none place-items-center rounded-pill bg-primary text-primary-foreground">
            <Check className="size-4" />
          </span>
          <div className="grid min-w-0 flex-1 gap-1">
            <span className="t-body-strong">{shown.name}</span>
            <span className="t-small text-muted-foreground">{shown.folded}</span>
          </div>
          <a className={buttonVariants({ variant: "outline", size: "sm" })} href={route(checklist.toString())}>
            Show the steps
          </a>
        </div>
        {shown.stages ? <FiveSteps stages={shown.stages} /> : null}
        <Others state={shown} act={act} />
      </>
    );
  }

  const steps = <Checklist steps={shown.steps ?? []} query={query} act={act} />;
  return (
    <>
      <Head title="Start here" lead={shown.lead} actions={change_} />
      {problem ? <Problem text={problem} /> : null}
      {shown.made ? (
        <div role="status" className="grid gap-4 rounded-panel border border-input p-6">
          <p className="t-body m-0">
            {shown.made.word} made for <span className="t-mono">{shown.made.name}</span>, team <span className="t-mono">{shown.made.team}</span>. Shown once:
            Enterplace keeps only its hash. Copy it now.
          </p>
          <div className="flex flex-wrap items-center gap-4">
            <code id="made-key" className="t-mono min-w-0 break-all">
              {shown.made.key}
            </code>
            <Copy text={shown.made.key} />
          </div>
        </div>
      ) : null}
      {shown.viewing ? <p className="t-small m-0 text-muted-foreground">{shown.viewing}</p> : null}
      {shown.pay ? (
        <div className="grid gap-2">
          <h2 className="t-sm m-0">How does your team pay for its coding agents?</h2>
          <TabRow
            label="How your team pays for its coding agents"
            items={[
              { id: "api", label: "API keys, any coding agent" },
              { id: "subscriptions", label: "Claude subscriptions, for Claude Code" },
            ].map((t) => ({ ...t, href: route(`track=coding&pay=${t.id}`), current: shown.pay === t.id }))}
          />
        </div>
      ) : null}
      {shown.live ? (
        <>
          <LiveStrip live={shown.live} />
          <div className="grid gap-4">
            <h2 className="t-sm m-0">Your steps</h2>
            {steps}
          </div>
        </>
      ) : (
        steps
      )}
      {shown.banner ? (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-panel bg-card p-6">
          <span className="t-body">All required steps are done. Next: the five steps of a rollout, starting with the one this choice leaves open.</span>
          <Button data-five-steps onClick={() => act("pick", { steps: "1" })}>
            Show the five steps
          </Button>
        </div>
      ) : null}
      <Others state={shown} act={act} />
    </>
  );
}

// Pick: the one starting choice, a radio per row.
function Pick({ state, act }: { state: State; act: Act }) {
  const [choice, setChoice] = useState(state.choice ?? "coding");
  const picked = state.tracks.find((t) => t.id === choice) ?? state.tracks[0];
  const may = state.may_choose;
  return (
    <form
      className="grid gap-8"
      onSubmit={(e) => {
        e.preventDefault();
        act("pick", { choice });
      }}
    >
      <fieldset className="m-0 grid gap-2 border-0 p-0">
        <legend className="t-tag pb-2 pl-6 uppercase text-muted-foreground">Start with</legend>
        {state.tracks.map((t) => (
          <label
            key={t.id}
            className={cn("flex cursor-pointer gap-4 rounded-box border border-border p-4", choice === t.id && "border-foreground")}
          >
            <input type="radio" name="choice" value={t.id} checked={choice === t.id} disabled={!may} onChange={() => setChoice(t.id)} className="mt-1" />
            <span className="grid gap-1">
              <span className="flex flex-wrap items-center gap-2">
                <span className="t-body-strong">{t.name}</span>
                {t.enterprise ? <Badge>Enterprise</Badge> : null}
              </span>
              <span className="t-small">{t.line}</span>
              <span className="t-small text-muted-foreground">{t.steps} steps</span>
            </span>
          </label>
        ))}
      </fieldset>
      {may ? (
        <div className="flex flex-wrap items-center gap-4">
          <Button type="submit" data-start-button>
            Start with {picked?.button}
          </Button>
          <Button type="button" variant="link" onClick={() => act("pick", { skip: "1" })}>
            Skip and open the console
          </Button>
        </div>
      ) : (
        <p className="t-small m-0 text-muted-foreground">Your role cannot choose what this install starts with. An admin can.</p>
      )}
    </form>
  );
}

function TabRow({ label, items }: { label: string; items: { id: string; label: string; href: string; current: boolean }[] }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-2">
      {items.map((t) => (
        <a
          key={t.id}
          href={t.href}
          aria-current={t.current ? "true" : undefined}
          className={cn(buttonVariants({ variant: t.current ? "default" : "outline", size: "sm" }), "no-underline")}
        >
          {t.label}
        </a>
      ))}
    </div>
  );
}

// Checklist: one row per step, its marker carrying the state.
function Checklist({ steps, query, act }: { steps: Step[]; query: URLSearchParams; act: Act }) {
  return (
    <ol data-checklist className="m-0 grid list-none gap-2 p-0">
      {steps.map((s) => {
        const open = s.state === "now" || s.state === "listening";
        return (
          <li
            key={s.n}
            id={`step-${s.n}`}
            data-state={s.state}
            aria-current={open ? "step" : undefined}
            className={cn("grid grid-cols-[var(--space-8)_1fr] gap-x-4 gap-y-2 rounded-panel p-6", open && "bg-card")}
          >
            <span
              aria-hidden="true"
              className={cn(
                "grid size-8 place-items-center rounded-pill border border-input",
                s.state === "done" && "border-primary bg-primary text-primary-foreground",
                open && "border-foreground",
              )}
            >
              {s.state === "done" ? <Check className="size-4" /> : null}
              {s.state === "listening" ? <span className="size-2 animate-pulse rounded-pill bg-foreground" /> : null}
            </span>
            <div className="flex flex-wrap items-center justify-between gap-2 self-center">
              <span className={cn("flex flex-wrap items-center gap-2", open ? "t-sm" : "t-body")}>
                {s.title}
                {s.optional ? <Badge>Optional</Badge> : null}
              </span>
              <span className="t-small text-muted-foreground">{s.word}</span>
            </div>
            {s.state === "done" && s.done_text ? (
              <p className="t-small col-start-2 m-0 text-muted-foreground">
                <Inline text={s.done_text} />
              </p>
            ) : null}
            {open ? (
              <div className="col-start-2 grid min-w-0 gap-4">
                {s.body.map((b, i) => (
                  <Block key={i} block={b} query={query} act={act} />
                ))}
                {s.agent ? (
                  <div className="flex flex-wrap gap-2">
                    <Copy text={s.agent} label="Copy for your agent" />
                  </div>
                ) : null}
                {s.state === "listening" ? (
                  <p role="status" className="t-small m-0 flex flex-wrap items-center gap-2">
                    <span aria-hidden="true" className="size-2 animate-pulse rounded-pill bg-lime" />
                    <span>{s.listen}</span>
                    {s.open ? <a href={s.open.href}>{s.open.label}</a> : null}
                  </p>
                ) : null}
              </div>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}

function Block({ block, query, act }: { block: Block; query: URLSearchParams; act: Act }) {
  switch (block.type) {
    case "p":
      return (
        <p className="t-body m-0 max-w-measure">
          <Inline text={block.text} />
        </p>
      );
    case "note":
      return (
        <p className="t-small m-0 text-muted-foreground">
          <Inline text={block.text} />
        </p>
      );
    case "link":
      return (
        <a className="t-small" href={block.href}>
          {block.label}
        </a>
      );
    case "button":
      return (
        <Button type="button" variant={block.quiet ? "outline" : "default"} onClick={() => act(block.action, block.body ?? {})}>
          {block.label}
        </Button>
      );
    case "actions":
      return (
        <div className="flex flex-wrap items-center gap-4">
          {block.items.map((b, i) => (
            <Block key={i} block={b} query={query} act={act} />
          ))}
        </div>
      );
    case "command":
      return (
        <div className="flex flex-wrap items-center gap-4 rounded-box bg-well px-6 py-3">
          <code className="t-mono min-w-0 flex-1 break-all">{block.text}</code>
          <Copy text={block.text} />
        </div>
      );
    case "lines":
      return <Lines block={block} query={query} />;
    case "form":
      return <StepForm block={block} act={act} />;
    case "policy":
      return <PolicyLines block={block} />;
  }
}

// Lines to paste, with the tabs that pick them and Copy. A tab keeps the rest of the view.
function Lines({ block, query }: { block: Extract<Block, { type: "lines" }>; query: URLSearchParams }) {
  const tabs = block.tabs;
  const href = (id: string) => {
    const next = new URLSearchParams(query);
    next.delete("view");
    next.delete("pick");
    next.set(tabs?.param ?? "tool", id);
    for (const [k, v] of Object.entries(tabs?.keep ?? {})) next.set(k, v);
    return route(next.toString());
  };
  return (
    <div className="grid min-w-0 gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {tabs ? (
          <TabRow label={tabs.label} items={tabs.options.map((o) => ({ ...o, href: href(o.id), current: o.id === tabs.selected }))} />
        ) : block.caption ? (
          <span className="t-tag uppercase text-muted-foreground">{block.caption}</span>
        ) : (
          <span />
        )}
        <Copy text={block.lines.join("\n")} />
      </div>
      <pre id={block.id} className="t-mono-sm m-0 overflow-x-auto rounded-box bg-primary px-6 py-4 text-primary-foreground">
        {block.lines.join("\n")}
      </pre>
    </div>
  );
}

function StepForm({ block, act }: { block: Extract<Block, { type: "form" }>; act: Act }) {
  const [refusal, setRefusal] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <div className="grid gap-2">
      <form
        data-action={block.action}
        className="flex flex-wrap items-end gap-4"
        onSubmit={async (e) => {
          e.preventDefault();
          const fields = Object.fromEntries(new FormData(e.currentTarget).entries());
          setBusy(true);
          setRefusal(await act(block.action, { ...block.hidden, ...fields }).finally(() => setBusy(false)));
        }}
      >
        {block.fields.map((f) => {
          const id = `${block.action}-${f.name}-${f.placeholder ?? ""}`;
          return (
            <div key={f.name} className="min-w-0 flex-1 basis-[var(--col-sm)]">
              <Field id={id} label={f.label}>
                {f.options ? (
                  <Select name={f.name} defaultValue={f.options[0]?.id}>
                    <SelectTrigger id={id}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {f.options.map((o) => (
                        <SelectItem key={o.id} value={o.id}>
                          {o.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input id={id} name={f.name} type={f.secret ? "password" : "text"} placeholder={f.placeholder} required autoComplete="off" className="t-mono" />
                )}
              </Field>
            </div>
          );
        })}
        <Button type="submit" disabled={busy}>
          {block.button}
        </Button>
      </form>
      <Refusal text={refusal} />
      {block.after ? <p className="t-small m-0 text-muted-foreground">{block.after}</p> : null}
    </div>
  );
}

// Policy lines as the policy reads them, with the way to add them: a draft, or Copy and the file's path.
function PolicyLines({ block }: { block: Extract<Block, { type: "policy" }> }) {
  return (
    <div className="grid gap-4">
      <div id={block.id} className="t-mono-sm grid overflow-x-auto rounded-box bg-well py-3">
        {block.marks.map((l, i) => (
          <div key={i} data-kind={l.kind} className={cn("flex gap-4 px-6 whitespace-pre", l.kind === "add" && "bg-lime text-on-lime", l.kind === "del" && "text-destructive-text line-through")}>
            <span aria-hidden="true" className="w-8 flex-none text-right">
              {l.n}
            </span>
            <span>{l.text}</span>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-4">
        {block.way.kind === "draft" ? (
          <a className={cn(buttonVariants(), "no-underline")} href={block.way.href}>
            {block.way.label}
          </a>
        ) : block.way.kind === "copy" ? (
          <>
            <Copy text={block.plain} />
            <span className="t-small text-muted-foreground">
              <Inline text={block.way.text} />
            </span>
          </>
        ) : (
          <span className="t-small text-muted-foreground">{block.way.text}</span>
        )}
      </div>
    </div>
  );
}

// The live strip: where requests come from, the gate, where they go, and the newest three. Only the newest disc
// moves, and it is drawn again only when a new request arrives, so each new request crosses the gate once.
function LiveStrip({ live }: { live: Live }) {
  const tags = (items: string[]) =>
    items.map((t) => (
      <span key={t} className="t-mono-sm inline-flex min-h-7 items-center rounded-pill border border-input px-3">
        {t}
      </span>
    ));
  return (
    <section aria-label="Live traffic" className="grid gap-4 rounded-panel bg-card p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="t-sm m-0">Live</h2>
        <p data-live-count className="t-small m-0 text-muted-foreground">
          {live.count}
        </p>
      </div>
      <div aria-hidden="true" className="grid grid-cols-[1fr_2fr_1fr] items-center gap-4">
        <div className="flex flex-wrap gap-2">{tags(live.tools)}</div>
        <div className="flow-lanes" style={{ height: `calc(var(--space-8) * ${Math.max(1, live.rows.length)})` }}>
          <span className="flow-gate" />
          {live.rows.map((r, i) => (
            <span
              key={i === 0 ? r.id : `${i}`}
              className={cn("flow-disc", i === 0 && "flow-disc--new")}
              data-outcome={r.refused ? "stop" : "pass"}
              style={{ ["--lane" as string]: i }}
            />
          ))}
        </div>
        <div className="flex flex-wrap justify-end gap-2">{tags(live.providers)}</div>
      </div>
      <div className="grid gap-2">
        {live.rows.map((r) => (
          <div key={r.id} className="t-mono-sm grid grid-cols-[auto_auto_1fr_auto] items-center gap-4">
            <span>{r.time}</span>
            <span>{r.person}</span>
            <span className="min-w-0 break-all">{r.model}</span>
            {r.refused ? <Badge className="border-destructive text-destructive-text">Refused: {r.code}</Badge> : <span className="t-small">Allowed</span>}
          </div>
        ))}
      </div>
      <a className="t-small justify-self-start" href="/console/requests">
        All requests
      </a>
    </section>
  );
}

// The five steps of a rollout, and the first one not done, opened.
function FiveSteps({ stages }: { stages: Stages }) {
  const c = stages.current;
  return (
    <div data-stages className="grid gap-4">
      <ol className="m-0 grid list-none grid-cols-2 gap-2 p-0 md:grid-cols-5">
        {stages.steps.map((s) => (
          <li
            key={s.name}
            data-state={s.state}
            aria-current={s.state === "current" ? "step" : undefined}
            className={cn(
              "grid gap-1 rounded-box border border-border p-4",
              s.state === "done" && "bg-card",
              s.state === "current" && "border-foreground",
            )}
          >
            <span className="t-md">{s.name}</span>
            <span className="t-small text-muted-foreground">{s.word}</span>
          </li>
        ))}
      </ol>
      {c ? (
        <section className="grid gap-8 rounded-panel bg-card p-6 md:grid-cols-[2fr_1fr]">
          <div className="grid content-start gap-4">
            <p className="t-tag m-0 uppercase text-muted-foreground">
              Step {c.n} of 5
            </p>
            <h2 className="t-md m-0">{c.title}</h2>
            <p className="t-lead m-0">{c.lead}</p>
            <p className="t-body m-0 text-muted-foreground">{c.why}</p>
            <div className="flex flex-wrap items-center gap-4">
              <a className={cn(buttonVariants(), "no-underline")} href={c.action.href}>
                {c.action.label}
              </a>
              <a className="t-small" href={c.guide.href}>
                {c.guide.label}
              </a>
            </div>
          </div>
          <div className="grid content-start gap-2">
            <p className="t-tag m-0 uppercase text-muted-foreground">Done when</p>
            <dl className="m-0 grid gap-4">
              {c.when.map((w) => (
                <div key={w.text}>
                  <dt className="t-body">{w.text}</dt>
                  <dd className="t-small m-0 text-muted-foreground">{w.value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>
      ) : null}
    </div>
  );
}

function Others({ state, act }: { state: State; act: Act }) {
  if (!state.others?.length) return null;
  return (
    <div className="grid gap-4">
      <h2 className="t-sm m-0">Also start with</h2>
      <div className="grid gap-2">
        {state.others.map((t) => (
          <div key={t.id} className="flex flex-wrap items-center gap-4 rounded-box border border-border p-4">
            <div className="grid min-w-0 flex-1 gap-1">
              <span className="flex flex-wrap items-center gap-2">
                <span className="t-body-strong">{t.name}</span>
                {t.enterprise ? <Badge>Enterprise</Badge> : null}
              </span>
              <span className="t-small text-muted-foreground">
                {t.steps} steps. Covers {t.covers}.
              </span>
            </div>
            {state.may_choose ? (
              <Button variant="outline" size="sm" onClick={() => act("pick", { choice: t.id })}>
                Start
              </Button>
            ) : (
              <a className={buttonVariants({ variant: "outline", size: "sm" })} href={route(`track=${t.id}`)}>
                Show
              </a>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
