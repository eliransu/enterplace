import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Loading, Panel, Problem } from "@/components/page";
import { goTo, useData } from "@/lib/use";
import { Setup } from "./Setup";
import { isService, KeyDialogs, KeyTable, ReadOnly, useKeys } from "./People";
import type { PageProps } from "@/pages";

const ROUTE = "/apps";

// Internal apps, custom agents and cloud agents: each calls models with its own service key, so its requests, budget
// and models are its own.
export function Apps({ query }: PageProps) {
  const keys = useKeys(query);
  const services = (keys.data?.entries ?? []).filter(isService);
  const may = !!keys.data?.may.issue;
  const make = may ? (
    <Button onClick={() => goTo(ROUTE, { issue: "1" })}>
      Make a service key
    </Button>
  ) : null;
  return (
    <>
      <Head
        title="Service keys"
        lead="Internal apps, custom agents and cloud agents that call models through Enterplace, each with its own service key."
        actions={services.length ? make : null}
      />
      <ReadOnly data={keys.data} />
      {keys.error ? <Problem text={keys.error} retry={keys.reload} /> : null}
      {!keys.data && !keys.error ? <Loading rows={3} /> : null}
      {keys.data?.entries ? (
        <Panel
          title="Service keys"
          note="A budget, models and tokens per minute per app are on its key: Edit."
        >
          {services.length ? (
            <KeyTable
              entries={services}
              route={ROUTE}
              readOnly={keys.data.read_only}
              change={keys.change}
              noun="App or agent"
            />
          ) : (
            <Empty
              title="No service keys yet"
              body="Make one key per app or agent and keep it in that app's secret store. Its requests, spend and limits are then its own."
            >
              {make}
            </Empty>
          )}
        </Panel>
      ) : null}
      {services.length ? <Spend names={services.map((s) => s.name)} /> : null}
      <section aria-label="Connect" className="grid gap-4">
        <h2 className="t-sm m-0">Connect an app or an agent</h2>
        <Setup query={query} base={ROUTE} track="apps" />
      </section>
      <KeyDialogs route={ROUTE} query={query} keys={keys} service />
    </>
  );
}

type Ranked = {
  ranking?: {
    value: string;
    requests: string;
    refused: string;
    usd: string;
    href: string;
    parts: { values: string[]; usd: string; requests: string }[];
  }[];
};

/// What each app spent this month and on which models: a service key's requests are recorded under its name.
function Spend({ names }: { names: string[] }) {
  const view = "by=person&then=model&window=month";
  const { data, error, reload } = useData<Ranked>(`analytics?${view}`);
  if (error) return <Problem text={error} retry={reload} />;
  if (!data) return <Loading rows={2} />;
  const rows = (data.ranking ?? []).filter((r) => names.includes(r.value));
  return (
    <Panel
      title="Spend this month"
      note="From the 1st, UTC. Billed at API prices: a service key never uses a subscription login."
      actions={
        <Button variant="outline" size="sm" asChild>
          <a href={`#/usage?${view}`}>Open in Usage</a>
        </Button>
      }
    >
      {rows.length === 0 ? (
        <Empty title="Nothing spent this month" body="Once an app sends a request with its service key, its spend and models show here." />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>App or agent</TableHead>
              <TableHead>Models</TableHead>
              <TableHead className="text-right">Requests</TableHead>
              <TableHead className="text-right">Refused</TableHead>
              <TableHead className="text-right">Cost, USD</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.value}>
                <TableCell>
                  <a href={r.href}>{r.value}</a>
                </TableCell>
                <TableCell className="t-small">
                  {r.parts.map((p) => `${p.values[0] || "(none)"} ${p.usd}`).join(", ")}
                </TableCell>
                <TableCell className="text-right tabular-nums">{r.requests}</TableCell>
                <TableCell className="text-right tabular-nums">{r.refused}</TableCell>
                <TableCell className="text-right tabular-nums">{r.usd}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}
