import { Fragment } from "react";
import { TriangleAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Head, Loading, Panel, Problem } from "@/components/page";
import { Copy } from "@/components/copy";
import { Person } from "@/components/person";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import type { PageProps } from "@/pages";

type Tab = { name: string; label: string };
type Point = { at: string; shown: string; percent: number; mark: string | null; now: boolean };
type Part = { values: string[]; requests: string; tokens: string; usd: string; estimated: string | null };
type Row = {
  value: string;
  unnamed: boolean;
  href: string;
  requests: string;
  refused: string;
  errors: string;
  tokens: string;
  usd: string;
  estimated: string | null;
  p50: string;
  p95: string;
  parts: Part[];
};
type Forecast = { label: string; text: string; percent: number; over: boolean; note: string };
type Data = {
  empty?: { title: string; body: string; action: { label: string; href: string } | null; docs: string } | null;
  lead: string;
  window: string;
  stats: { figure: string; label: string }[];
  metric: string;
  metrics: Tab[];
  chart_title: string;
  chart: { label: string; top: string; half: string; points: Point[] } | null;
  by: string;
  by_label: string;
  ranking_title: string;
  bys: Tab[];
  more: Tab[];
  ranking: Row[];
  then: string;
  then_label: string;
  est_tip: string;
  link: string;
  agent: string;
  forecasts: Forecast[] | null;
  trend: { name: string; value: string; label: string } | null;
};

const WINDOWS: Tab[] = [
  { name: "24h", label: "24 hours" },
  { name: "7d", label: "7 days" },
  { name: "month", label: "This month" },
  { name: "30d", label: "30 days" },
];
// What a ranking can be split by: a person's spend by the tools and models it went to, a tool's by its people.
const SPLITS: Tab[] = [
  { name: "", label: "No split" },
  { name: "agent", label: "Coding agent" },
  { name: "model", label: "Model" },
  { name: "agent,model", label: "Coding agent and model" },
  { name: "person", label: "Person" },
];
const LEAD = "Requests, cost and refusals over time, by team, person, model or provider.";
const UP_FRONT = ["team", "person", "model", "provider"];

/// Picks a window, metric or breakdown and keeps every filter, as the old page's tab links did. `from` goes: a window
/// is picked by its length, and a start date from a link would pin it. An empty value removes the parameter.
function pick(query: URLSearchParams, name: string, value: string) {
  const next = new URLSearchParams(query);
  next.delete("from");
  if (value) next.set(name, value);
  else next.delete(name);
  window.location.hash = `#/usage?${next}`;
  // A Trend button sits in the ranking, below the chart it changes: bring the chart into view, or the click looks
  // like it did nothing.
  if (name === "trend") document.getElementById("usage-chart")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

/// `edged`: on the page's own background, where the accent fill alone does not show which one is picked.
function Tabs({ label, tabs, current, onPick, edged }: { label: string; tabs: Tab[]; current: string; onPick: (name: string) => void; edged?: boolean }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {tabs.map((t) => (
        <Button key={t.name} variant="ghost" size="sm" aria-pressed={t.name === current} className={cn(t.name === current && "bg-accent", t.name === current && edged && "border border-input")} onClick={() => onPick(t.name)}>
          {t.label}
        </Button>
      ))}
    </div>
  );
}

export function Analytics({ query }: PageProps) {
  // Live: the page reads the log again every 5 seconds, so a request shows in the totals, chart and ranking as it
  // arrives. Nothing on this page is a form that a redraw could lose.
  const { data, error, reload } = useData<Data>(`analytics${query.size ? `?${query}` : ""}`, 5000);
  const filtered = [...query.keys()].some((k) => !["window", "by", "metric"].includes(k));

  if (error) {
    return (
      <>
        <Head title="Analytics" lead={LEAD} />
        <Problem text={error} retry={reload} />
        {filtered ? (
          <Button variant="outline" asChild className="justify-self-start">
            <a href="#/usage">Show everything</a>
          </Button>
        ) : null}
      </>
    );
  }
  if (!data) {
    return (
      <>
        <Head title="Analytics" lead={LEAD} />
        <Loading rows={6} />
      </>
    );
  }
  if (data.empty !== undefined) {
    const empty = data.empty;
    return (
      <>
        <Head title="Analytics" lead={LEAD} />
        {empty ? (
          <Panel title={empty.title}>
            <p className="t-body m-0 text-muted-foreground">{empty.body}</p>
            <div className="flex flex-wrap gap-2">
              {empty.action ? (
                <Button asChild>
                  <a href={empty.action.href}>{empty.action.label}</a>
                </Button>
              ) : null}
              <Button variant="outline" asChild>
                <a href={empty.docs}>Read the docs page</a>
              </Button>
            </div>
          </Panel>
        ) : null}
      </>
    );
  }

  // More stays open while one of its own breakdowns is picked, as the old page's details did.
  const moreOpen = !UP_FRONT.includes(data.by);
  const splits = SPLITS.filter((t) => !t.name.split(",").includes(data.by));
  // Unnamed traffic is a problem to fix, not a team or person in the race: pinned above the ranking, not numbered.
  const ranking = [...data.ranking.filter((r) => r.unnamed), ...data.ranking.filter((r) => !r.unnamed)];
  const csv = new URLSearchParams(query);
  csv.set("format", "csv");
  return (
    <>
      <Head
        title="Analytics"
        lead={data.lead}
        actions={
          <>
            <Copy text={`${location.origin}/console/app/${data.link}`} label="Copy link" />
            <Button variant="outline" size="sm" asChild>
              <a href={`/console/api/analytics?${csv}`} download>
                Download CSV
              </a>
            </Button>
            <Copy text={data.agent} label="Copy for your agent" />
          </>
        }
      />
      <Tabs label="Window" tabs={WINDOWS} current={data.window} onPick={(v) => pick(query, "window", v)} edged />
      <section className="grid gap-4 rounded-panel bg-card p-6 sm:grid-cols-3">
        {data.stats.map((s) => (
          <div key={s.label} className="grid gap-1">
            <p className="t-lg m-0 tabular-nums">{s.figure}</p>
            <p className="t-small m-0 text-muted-foreground">{s.label}</p>
          </div>
        ))}
      </section>
      <div id="usage-chart" className="scroll-mt-16">
      <Panel title={data.chart_title}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <Tabs label="Metric" tabs={data.metrics} current={data.metric} onPick={(v) => pick(query, "metric", v)} />
          {data.trend ? (
            <div className="flex items-center gap-2">
              <span className="t-small text-muted-foreground">Chart shows</span>
              <Button size="sm" aria-label={`Remove the chart filter ${data.trend.label}`} onClick={() => pick(query, "trend", "")}>
                {data.trend.label}
                <X aria-hidden />
              </Button>
            </div>
          ) : null}
        </div>
        {data.chart ? <Chart chart={data.chart} /> : <p className="t-small m-0 text-muted-foreground">No requests in this window.</p>}
      </Panel>
      </div>
      <Panel title={data.ranking_title}>
        <div className="flex flex-wrap items-start gap-1">
          <Tabs label="Group by" tabs={data.bys} current={data.by} onPick={(v) => pick(query, "by", v)} />
          {data.more.length ? (
            <details open={moreOpen} className="flex flex-wrap gap-1">
              <summary className="t-small inline-flex min-h-8 cursor-pointer list-none items-center rounded-pill px-4 hover:bg-accent">More</summary>
              <Tabs label="More breakdowns" tabs={data.more} current={data.by} onPick={(v) => pick(query, "by", v)} />
            </details>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="t-small text-muted-foreground">Split by</span>
          <Tabs label="Split by" tabs={splits} current={data.then} onPick={(v) => pick(query, "then", v)} />
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{data.by_label}</TableHead>
              <TableHead className="text-right">Requests</TableHead>
              <TableHead className="text-right">Refused</TableHead>
              <TableHead className="text-right">Errors</TableHead>
              <TableHead className="text-right">Tokens</TableHead>
              <TableHead className="text-right">USD</TableHead>
              <TableHead className="text-right">p50</TableHead>
              <TableHead className="text-right">p95</TableHead>
              <TableHead>
                <span className="sr-only">Trend</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {ranking.map((r) => (
              <Fragment key={r.value}>
                <TableRow className={cn(r.unnamed && "bg-accent")}>
                  <TableCell>
                    {r.unnamed ? null : <span className="text-muted-foreground tabular-nums">{ranking.filter((x) => !x.unnamed).indexOf(r) + 1}. </span>}
                    {r.unnamed ? (
                      <>
                        <span className="t-body-strong inline-flex items-center gap-2 whitespace-nowrap">
                          <TriangleAlert aria-hidden="true" className="size-4 flex-none text-destructive-text" />
                          Unnamed traffic
                        </span>{" "}
                        <a href={r.href} className="t-small">
                          See them
                        </a>
                        {" or "}
                        <a href="#/coding?issue=1&token=1" className="t-small">
                          hand out person tokens
                        </a>
                      </>
                    ) : data.by === "person" ? (
                      <Person name={r.value} href={r.href} />
                    ) : (
                      <a href={r.href}>{r.value}</a>
                    )}
                  </TableCell>
                  {[r.requests, r.refused, r.errors, r.tokens].map((v, j) => (
                    <TableCell key={j} className="t-mono-sm whitespace-nowrap text-right tabular-nums">
                      {v}
                    </TableCell>
                  ))}
                  <Usd usd={r.usd} estimated={r.estimated} tip={data.est_tip} />
                  {[r.p50, r.p95].map((v, j) => (
                    <TableCell key={j} className="t-mono-sm whitespace-nowrap text-right tabular-nums">
                      {v}
                    </TableCell>
                  ))}
                  <TableCell className="text-right">
                    {r.value === "(none)" ? null : (
                      <TrendButton query={query} by={data.by} value={r.value} trend={data.trend} />
                    )}
                  </TableCell>
                </TableRow>
                {r.parts.map((p) => (
                  <TableRow key={p.values.join("/")} className="text-muted-foreground">
                    <TableCell className="pl-8">
                      <span className="t-small">{p.values.map((v) => (v === "" ? "(none)" : v)).join(", ")}</span>
                    </TableCell>
                    <TableCell className="t-mono-sm whitespace-nowrap text-right tabular-nums">{p.requests}</TableCell>
                    <TableCell />
                    <TableCell />
                    <TableCell className="t-mono-sm whitespace-nowrap text-right tabular-nums">{p.tokens}</TableCell>
                    <Usd usd={p.usd} estimated={p.estimated} tip={data.est_tip} />
                    <TableCell />
                    <TableCell />
                    <TableCell />
                  </TableRow>
                ))}
              </Fragment>
            ))}
          </TableBody>
        </Table>
      </Panel>
      {data.forecasts ? <Forecasts forecasts={data.forecasts} /> : null}
    </>
  );
}

/// Filters the day chart to one value of the ranking, or back to everything when it already is: one team's,
/// person's, app's, coding agent's or model's trend, kept in the link.
function TrendButton({ query, by, value, trend }: { query: URLSearchParams; by: string; value: string; trend: Data["trend"] }) {
  const on = trend?.name === by && trend.value === value;
  return (
    <Button
      variant="ghost"
      size="sm"
      aria-pressed={on}
      aria-label={on ? `Show everything in the chart again` : `Show ${value} alone in the chart`}
      className={cn(on && "bg-accent")}
      onClick={() => pick(query, "trend", on ? "" : `${by}:${value}`)}
    >
      Trend
    </Button>
  );
}

/// A cost, and under it the part of it that is an estimate (sent with a subscription login), so billed and estimated
/// spend are never read as one.
function Usd({ usd, estimated, tip }: { usd: string; estimated: string | null; tip: string }) {
  return (
    <TableCell className="t-mono-sm whitespace-nowrap text-right tabular-nums">
      {usd}
      {estimated ? (
        <span className="t-small block text-muted-foreground" title={tip}>
          {estimated} est.
        </span>
      ) : null}
    </TableCell>
  );
}

/// Bars for each hour or day with their scale. Muted, so the eye lands on the last bar: now, in lime, edged in text
/// so it holds on a light panel. Capped in width so one day is not one wide block, and spread over the width so a week
/// does not huddle at the left.
function Chart({ chart }: { chart: NonNullable<Data["chart"]> }) {
  return (
    <div role="img" aria-label={chart.label} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2">
      <div className="t-mono-sm flex flex-col justify-between text-right text-muted-foreground">
        <span>{chart.top}</span>
        <span>{chart.half}</span>
        <span>0</span>
      </div>
      <div className="relative flex h-[calc(var(--space-24)*2.5)] items-end justify-around gap-1 border-b border-input md:gap-2">
        <span className="absolute inset-x-0 bottom-1/2 border-t border-border" />
        <span className="absolute inset-x-0 bottom-full border-t border-border" />
        {chart.points.map((p) => (
          <div
            key={p.at}
            title={`${p.at}: ${p.shown}`}
            className={cn("relative min-w-0 max-w-[var(--space-6)] flex-1 rounded-t-small", p.now ? "border border-b-0 border-foreground bg-lime" : "bg-input")}
            style={{ height: `${p.percent}%` }}
          />
        ))}
      </div>
      <div className="t-mono-sm col-start-2 flex justify-around gap-1 text-muted-foreground md:gap-2">
        {chart.points.map((p) => (
          <span key={p.at} className="flex min-w-0 max-w-[var(--space-6)] flex-1 justify-center whitespace-nowrap">
            {p.mark ?? ""}
          </span>
        ))}
      </div>
    </div>
  );
}

function Forecasts({ forecasts }: { forecasts: Forecast[] }) {
  return (
    <Panel title="Budget forecasts">
      {forecasts.length === 0 ? (
        <div className="grid justify-items-start gap-2 py-6">
          <p className="t-body-strong m-0">No budgets yet</p>
          <p className="t-body m-0 text-muted-foreground">The policy sets no budget, so nothing runs out.</p>
          <Button asChild>
            <a href="#/policy">Add a budget</a>
          </Button>
        </div>
      ) : (
        forecasts.map((f) => (
          <div key={f.label + f.note} className="grid gap-1">
            <div className="flex flex-wrap justify-between gap-4">
              <span className="t-mono-lg">{f.label}</span>
              <span className="t-mono-sm">{f.text}</span>
            </div>
            <div role="meter" aria-valuenow={f.percent} aria-valuemin={0} aria-valuemax={100} aria-label={`${f.label} budget used`} className="h-1 rounded-pill bg-border">
              <div className={cn("h-1 rounded-pill", f.over ? "bg-destructive" : "bg-foreground")} style={{ width: `${f.percent}%` }} />
            </div>
            <span className="t-small text-muted-foreground">{f.note}</span>
          </div>
        ))
      )}
    </Panel>
  );
}
