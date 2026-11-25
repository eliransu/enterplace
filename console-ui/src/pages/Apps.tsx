import { Button } from "@/components/ui/button";
import { Empty, Head, Loading, Panel, Problem } from "@/components/page";
import { goTo } from "@/lib/use";
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
        title="Apps and agents"
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
      <section aria-label="Connect" className="grid gap-4">
        <h2 className="t-sm m-0">Connect an app or an agent</h2>
        <Setup query={query} base={ROUTE} track="apps" />
      </section>
      <KeyDialogs route={ROUTE} query={query} keys={keys} service />
    </>
  );
}
