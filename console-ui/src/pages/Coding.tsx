import { useState } from "react";
import { TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Empty, Head, Loading, Panel, Problem } from "@/components/page";
import { api, type Me } from "@/lib/api";
import { count, goTo, useData } from "@/lib/use";
import { Setup } from "./Setup";
import { isService, KeyDialogs, KeyTable, ReadOnly, useKeys } from "./People";
import { CODING_TOOLS, nameWarning, unnamedIn, type Ranking } from "./Overview";
import type { PageProps } from "@/pages";

const ROUTE = "/coding";

export function Coding({ query }: PageProps) {
  const keys = useKeys(query);
  const people = (keys.data?.entries ?? []).filter((e) => !isService(e));
  const may = !!keys.data?.may.issue;
  return (
    <>
      <Head
        title="Coding agents"
        lead="Claude Code, Codex, Cursor, Copilot and the rest. Every request is recorded under the person who sent it."
        actions={
          may ? (
            <Button onClick={() => goTo(ROUTE, { issue: "1", token: "1" })}>
              Hand out a person token
            </Button>
          ) : null
        }
      />
      <Names />
      <section aria-label="Connect" className="grid gap-4">
        <h2 className="t-sm m-0">Connect a coding agent</h2>
        <Setup query={query} base={ROUTE} track="coding" />
      </section>
      <Tools />
      <ReadOnly data={keys.data} />
      {keys.error ? <Problem text={keys.error} retry={keys.reload} /> : null}
      {!keys.data && !keys.error ? <Loading rows={3} /> : null}
      {keys.data?.entries ? (
        <Panel
          title="People"
          note="Limits per person (a budget, models, tokens per minute) are on their key: Edit."
        >
          {people.length ? (
            <KeyTable
              entries={people}
              route={ROUTE}
              readOnly={keys.data.read_only}
              noun="Person"
            />
          ) : (
            <Empty
              title="No people yet"
              body="Hand each developer a key or a person token, so their coding agent's requests carry their name."
            >
              {may ? (
                <Button onClick={() => goTo(ROUTE, { issue: "1", token: "1" })}>
                  Hand out a person token
                </Button>
              ) : null}
            </Empty>
          )}
        </Panel>
      ) : null}
      <KeyDialogs route={ROUTE} query={query} keys={keys} />
    </>
  );
}

/// "Every request needs a name": on, a request with no person token is refused; off, it is recorded as unnamed. Shown
/// only when the gateway says where it stands (`names` in /me), so an older gateway shows nothing it cannot keep.
function Names() {
  const { data: me, change } = useData<Me>("me");
  const { data: persons } = useData<Ranking>("analytics?by=person&window=24h");
  const [asking, setAsking] = useState(false);
  const n = me?.names;
  if (!me || !n) return null;
  const seen = unnamedIn(persons);
  const warning = nameWarning(me, seen);
  const set = (required: boolean) =>
    change(() => api.put("policy/identity", { required }));
  const mayChange = me.edit_policy;
  // With no provider that takes subscription logins every request carries a key, which names its person: nothing
  // to switch, only requests that came with no valid key at all to point out.
  if (!n.passthrough && !warning) return null;
  return (
    <Panel title="Names">
      {n.passthrough ? (
      <div className="flex flex-wrap items-start gap-4">
        <Switch
          id="names-required"
          checked={n.required}
          disabled={!mayChange}
          onCheckedChange={(on) => (on && seen > 0 ? setAsking(true) : set(on))}
          aria-describedby="names-said"
          className="mt-1"
        />
        <div className="grid min-w-0 flex-1 gap-1">
          <label htmlFor="names-required" className="t-body-strong">
            Every request needs a name
          </label>
          <p
            id="names-said"
            className="t-small m-0 max-w-measure text-muted-foreground"
          >
            {n.required
              ? "On: a Claude Code request without a person token is refused, so every request names who sent it."
              : "Off: requests without a person token go through and are recorded as unnamed. Use this only for a rollout period."}
            {mayChange ? "" : " Your role may not change the policy."}
          </p>
        </div>
      </div>
      ) : null}
      {warning ? (
        <div
          role="status"
          className="flex flex-wrap items-center gap-4 rounded-box border border-input p-4"
        >
          <TriangleAlert aria-hidden="true" className="size-4 flex-none" />
          <div className="grid min-w-0 flex-1 gap-1">
            <span className="t-body-strong">{warning.title}</span>
            <span className="t-small text-muted-foreground">
              {warning.body}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {seen > 0 ? (
              <Button variant="outline" size="sm" asChild>
                <a href="#/requests?person=unknown">See them</a>
              </Button>
            ) : null}
            <Button
              size="sm"
              onClick={() => goTo(ROUTE, { issue: "1", token: "1" })}
            >
              Hand out person tokens
            </Button>
          </div>
        </div>
      ) : null}
      <AlertDialog open={asking} onOpenChange={setAsking}>
        <AlertDialogContent>
          <AlertDialogTitle>Refuse requests without a name?</AlertDialogTitle>
          <AlertDialogDescription>
            {count(seen, "request")} in the last 24 hours came without a person
            token. From now on, a request like them is refused until its sender
            sets a person token.
          </AlertDialogDescription>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => set(true)}>
              Require a name
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Panel>
  );
}

/// Which coding agents sent requests in the last 7 days, read from the user agent each request came with.
function Tools() {
  const { data, error, reload } = useData<Ranking>(
    "analytics?by=agent&window=7d",
  );
  if (error) return <Problem text={error} retry={reload} />;
  if (!data) return <Loading rows={2} />;
  const rows = (data.ranking ?? []).filter((r) => CODING_TOOLS.includes(r.value));
  return (
    <Panel title="Tools in use, last 7 days">
      {rows.length === 0 ? (
        <Empty
          title="No coding agent seen yet"
          body="Once a developer's coding agent sends a request through Enterplace, it shows here with how much it was used."
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-1/3">Tool</TableHead>
              <TableHead className="text-right">Requests</TableHead>
              <TableHead className="text-right">Refused</TableHead>
              <TableHead className="text-right">Cost, USD</TableHead>
              <TableHead>
                <span className="sr-only">Open</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.value}>
                <TableCell>
                  <span className="block max-w-col-md truncate" title={r.value}>
                    {r.value}
                  </span>
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {r.requests}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {r.refused}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {r.usd}
                </TableCell>
                <TableCell className="text-right">
                  <Button variant="ghost" size="sm" asChild>
                    <a href={`#/requests?agent=${encodeURIComponent(r.value)}`}>
                      Requests
                    </a>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}
