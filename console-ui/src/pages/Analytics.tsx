import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Head, Panel, Problem } from "@/components/page";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import type { PageProps } from "@/pages";

type Tab = { name: string; label: string };
type Point = { at: string; shown: string; percent: number; mark: string | null; now: boolean };
type Row = { value: string; href: string; requests: string; refused: string; errors: string; tokens: string; usd: string; p50: string; p95: string };
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
  forecasts: Forecast[] | null;
};

const WINDOWS: Tab[] = [
  { name: "24h", label: "24 hours" },
  { name: "7d", label: "7 days" },
  { name: "30d", label: "30 days" },
];
const UP_FRONT = ["team", "person", "model", "provider"];

/// Picks a window, metric or breakdown and keeps every filter, as the old page's tab links did. `from` goes: a window
/// is picked by its length, and a start date from a link would pin it.
function pick(query: URLSearchParams, name: string, value: string) {
  const next = new URLSearchParams(query);
  next.delete("from");
  next.set(name, value);
  window.location.hash = `#/analytics?${next}`;
}

function Tabs({ label, tabs, current, onPick }: { label: string; tabs: Tab[]; current: string; onPick: (name: string) => void }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {tabs.map((t) => (
        <Button key={t.name} variant="ghost" size="sm" aria-pressed={t.name === current} className={cn(t.name === current && "bg-accent")} onClick={() => onPick(t.name)}>
          {t.label}
        </Button>
      ))}
    </div>
  );
}

export function Analytics({ query }: PageProps) {
  // Live: the page reads the log again every 5 seconds, so a request shows in the totals, chart and ranking as it
  // arrives. Nothing on this page is a form that a redraw could lose.
  const { data, error } = useData<Data>(`analytics${query.size ? `?${query}` : ""}`, 5000);
  const filtered = [...query.keys()].some((k) => !["window", "by", "metric"].includes(k));

  if (error) {
    return (
      <>
        <Head title="Analytics" lead="" />
        <Problem text={error} />
        {filtered ? (
          <Button variant="outline" asChild className="justify-self-start">
            <a href="#/analytics">Show everything</a>
          </Button>
        ) : null}
      </>
    );
  }
  if (!data) return <Head title="Analytics" lead="" />;
  if (data.empty !== undefined) {
    const empty = data.empty;
    return (
      <>
        <Head title="Analytics" lead="" />
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
  return (
    <>
      <Head title="Analytics" lead={data.lead} />
      <Tabs label="Window" tabs={WINDOWS} current={data.window} onPick={(v) => pick(query, "window", v)} />
      <section className="grid grid-cols-3 gap-4 rounded-panel bg-card p-6">
        {data.stats.map((s) => (
          <div key={s.label} className="grid gap-1">
            <p className="t-lg m-0 tabular-nums">{s.figure}</p>
            <p className="t-small m-0 text-muted-foreground">{s.label}</p>
          </div>
        ))}
      </section>
      <Panel title={data.chart_title}>
        <Tabs label="Metric" tabs={data.metrics} current={data.metric} onPick={(v) => pick(query, "metric", v)} />
        {data.chart ? <Chart chart={data.chart} /> : <p className="t-small m-0 text-muted-foreground">No requests in this window.</p>}
      </Panel>
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
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.ranking.map((r, i) => (
              <TableRow key={r.value}>
                <TableCell>
                  {i + 1}. <a href={r.href}>{r.value}</a>
                </TableCell>
                {[r.requests, r.refused, r.errors, r.tokens, r.usd, r.p50, r.p95].map((v, j) => (
                  <TableCell key={j} className="t-mono-sm text-right tabular-nums">
                    {v}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
      {data.forecasts ? <Forecasts forecasts={data.forecasts} /> : null}
    </>
  );
}

/// Bars for each hour or day with their scale. Muted, so the eye lands on the last bar: now, in lime, edged in text
/// so it holds on a light panel. Capped in width so one day is not one wide block.
function Chart({ chart }: { chart: NonNullable<Data["chart"]> }) {
  return (
    <div role="img" aria-label={chart.label} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2">
      <div className="t-mono-sm flex flex-col justify-between text-right text-muted-foreground">
        <span>{chart.top}</span>
        <span>{chart.half}</span>
        <span>0</span>
      </div>
      <div className="relative flex h-[calc(var(--space-24)*2.5)] items-end gap-1 border-b border-input md:gap-2">
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
      <div className="t-mono-sm col-start-2 flex gap-1 text-muted-foreground md:gap-2">
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
            <a href="/console/policy">Add a budget to the policy</a>
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
