import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Head, Panel, Problem } from "@/components/page";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";

type Link = { label: string; href: string };
type Day = { day: number; percent: number | null; title: string; label: boolean; mark: boolean };
type Meter = { label: string; text: string; percent: number; over: boolean; note: string };
type Notice = { title: string; body: string; action: Link; docs?: string; lines?: string[] };
type Data = {
  lead: string;
  error?: string;
  empty?: Notice | null;
  action?: Link | null;
  month?: string;
  chart?: { label: string; caption: string; scale: string[]; pace: number | null; mark: number | null; days: Day[] };
  spenders?: { name: string; sent: string; mostly: string; href: string }[];
  budgets?: { problem?: Notice; meters?: Meter[] };
  models?: { model: string; usd: string; provider: string; priced: string; requests: string; tokens: string }[];
  stopped?: string;
  note?: string;
};

export function Spend() {
  // Live: the page reads the log again every 5 seconds, so a request's spend shows without a reload.
  const { data, error } = useData<Data>("spend", 5000);
  return (
    <>
      <Head
        title="Spend"
        lead={data?.lead ?? "What each team spends, by model."}
        actions={
          data?.action ? (
            <Button variant="outline" asChild>
              <a href={data.action.href}>{data.action.label}</a>
            </Button>
          ) : null
        }
      />
      {error ? <Problem text={error} /> : null}
      {data?.error ? <Problem text={data.error} /> : null}
      {data?.empty ? <NoticePanel notice={data.empty} /> : null}
      {data?.chart ? (
        <>
          <Panel title="Spend per day, USD" note={data.chart.caption}>
            <Chart chart={data.chart} />
          </Panel>
          <div className="grid gap-6 lg:grid-cols-2">
            <Panel title={`Who spent most in ${data.month}`}>
              {data.spenders?.length ? (
                <ul className="m-0 grid list-none gap-4 p-0">
                  {data.spenders.map((p) => (
                    <li key={p.name} className="flex flex-wrap items-center justify-between gap-4">
                      <div className="grid gap-1">
                        <span className="t-body-strong">{p.name}</span>
                        <span className="t-small text-muted-foreground">
                          {p.sent}, most of it on <span className="t-mono whitespace-nowrap">{p.mostly}</span>.
                        </span>
                      </div>
                      <Button variant="ghost" size="sm" asChild>
                        <a href={p.href}>See these requests</a>
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="t-small m-0 text-muted-foreground">Nobody has spent anything in {data.month} yet.</p>
              )}
            </Panel>
            <Panel title="Budgets">
              {data.budgets?.problem ? <NoticeBody notice={data.budgets.problem} /> : null}
              {data.budgets?.meters?.map((m) => <MeterRow key={m.label + m.note} meter={m} />)}
            </Panel>
          </div>
          <Panel title="Spend by model" note={data.note}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Model</TableHead>
                  <TableHead className="text-right">USD</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead className="text-right">Requests</TableHead>
                  <TableHead className="text-right">Tokens</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.models?.map((m) => (
                  <TableRow key={m.model}>
                    <TableCell className="whitespace-nowrap">{m.model}</TableCell>
                    <TableCell className="text-right tabular-nums">{m.usd}</TableCell>
                    <TableCell>
                      {m.provider}
                      <span className="block text-muted-foreground">{m.priced}</span>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{m.requests}</TableCell>
                    <TableCell className="text-right tabular-nums">{m.tokens}</TableCell>
                  </TableRow>
                ))}
                {/* Refused requests never reached a provider, so they cost nothing; their count is the point. */}
                <TableRow>
                  <TableCell>Stopped before sending</TableCell>
                  <TableCell className="text-right tabular-nums">0.00</TableCell>
                  <TableCell />
                  <TableCell className="text-right tabular-nums">{data.stopped}</TableCell>
                  <TableCell className="text-right tabular-nums">0</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </Panel>
        </>
      ) : null}
    </>
  );
}

function NoticePanel({ notice }: { notice: Notice }) {
  return (
    <Panel title={notice.title}>
      <NoticeBody notice={notice} bare />
    </Panel>
  );
}

// `bare`: the title is already the panel's heading.
function NoticeBody({ notice, bare }: { notice: Notice; bare?: boolean }) {
  return (
    <div className="grid justify-items-start gap-4">
      {bare ? null : <p className="t-body-strong m-0">{notice.title}</p>}
      <p className="t-body m-0 text-muted-foreground">{notice.body}</p>
      {notice.lines ? (
        <pre className="t-mono m-0 w-full overflow-x-auto rounded-box bg-well px-6 py-3">{notice.lines.join("\n")}</pre>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button asChild>
          <a href={notice.action.href}>{notice.action.label}</a>
        </Button>
        {notice.docs ? (
          <Button variant="outline" asChild>
            <a href={notice.docs}>Read the docs page</a>
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function MeterRow({ meter }: { meter: Meter }) {
  return (
    <div className="grid gap-1">
      <div className="flex flex-wrap justify-between gap-4">
        <span className="t-mono-lg">{meter.label}</span>
        <span className="t-mono-sm">{meter.text}</span>
      </div>
      <div
        role="meter"
        aria-valuenow={meter.percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`${meter.label} budget used`}
        className="h-1 rounded-pill bg-border"
      >
        <div className={cn("h-1 rounded-pill", meter.over ? "bg-destructive" : "bg-foreground")} style={{ width: `${meter.percent}%` }} />
      </div>
      <span className={cn("t-small", meter.over ? "text-destructive-text" : "text-muted-foreground")}>{meter.note}</span>
    </div>
  );
}

// One bar per day of the month, the dashed pace that keeps every monthly budget inside its limit, and the day the
// first budget ran out in the flame color. The label reads the chart out for a screen reader.
function Chart({ chart }: { chart: NonNullable<Data["chart"]> }) {
  return (
    <div role="img" aria-label={chart.label} className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-1">
      <div className="t-mono-sm flex flex-col justify-between text-right text-muted-foreground">
        {chart.scale.map((s, i) => (
          <span key={i}>{s}</span>
        ))}
      </div>
      <div className="relative flex h-40 items-end gap-px border-b border-border">
        <span className="absolute inset-x-0 top-0 border-t border-border" />
        <span className="absolute inset-x-0 top-1/2 border-t border-border" />
        {chart.pace !== null ? (
          <span className="absolute inset-x-0 border-t border-dashed border-input" style={{ bottom: `${chart.pace}%` }} />
        ) : null}
        {chart.days.map((d) => (
          <div key={d.day} title={d.title} className="flex h-full flex-1 items-end">
            {d.percent !== null ? (
              <div className={cn("w-full rounded-small", d.mark ? "bg-destructive" : "bg-foreground")} style={{ height: `${d.percent}%` }} />
            ) : null}
          </div>
        ))}
      </div>
      <span />
      <div className="t-mono-sm flex gap-px text-muted-foreground">
        {chart.days.map((d) => (
          <span key={d.day} className={cn("flex-1 text-center", d.mark && "text-destructive-text")}>
            {d.label ? d.day : ""}
          </span>
        ))}
      </div>
    </div>
  );
}
