import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Empty,
  Form,
  Head,
  Loading,
  Panel,
  Problem,
  Refusal,
} from "@/components/page";
import { Copy } from "@/components/copy";
import { TeamPicker } from "@/components/team-picker";
import { api, Refused } from "@/lib/api";
import { count, goTo, num, useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import type { PageProps } from "@/pages";

type Fix =
  | { kind: "restore"; scope: string; value: string }
  | { kind: "command"; text: string }
  | { kind: "reissue"; name: string; team: string }
  | { kind: "refusals"; href: string }
  | null;
type Status = {
  tag: string;
  kind: string;
  notes: string[];
  meter: { text: string; percent: number; over: boolean } | null;
  fix: Fix;
};
type Fields = {
  expires: string;
  budget: string;
  per: string;
  models: string;
  tpm: string;
  replaced_by: string | null;
};
export type Entry = {
  name: string;
  team: string;
  admin: boolean;
  kind: string;
  sha256: string;
  hash: string;
  requests: number;
  last: string;
  status: Status;
  editable: boolean;
  fields: Fields;
  /// Every limit a request with this key counts against, with where each is set.
  limits?: string[];
};
export type Keys = {
  keys_file: string;
  keys_path: string;
  read_only: boolean;
  may: {
    issue: boolean;
    revoke: boolean;
    restore: boolean;
    full_admin: boolean;
  };
  start_command: string;
  stop_agent: string;
  bring?: Bring;
  docs: string;
  empty: {
    title: string;
    body: string;
    action: { label: string; href: string };
    docs: string;
  } | null;
  error?: string;
  lead?: string;
  entries?: Entry[];
};
type Made = {
  key: string;
  name: string;
  team: string;
  rotated?: boolean;
  lines?: string[];
  until?: string;
  message?: string;
  keys_path?: string;
};
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

const PER_PAGE = 50;

/// The kind of key as the admin reads it: an app's key is a service key.
export const kindOf = (e: Entry) =>
  e.kind === "workload key" ? "service key" : e.kind;
export const isService = (e: Entry) => e.kind === "workload key";

/// The keys file, read again every 5 seconds unless a dialog on `query` is open, and the key shown once after a change.
export function useKeys(query: URLSearchParams) {
  const dialog =
    query.get("issue") ||
    query.get("import") ||
    query.get("revoke") ||
    query.get("edit") ||
    query.get("stop");
  const [made, setMade] = useState<Made | null>(null);
  const keys = useData<Keys>("people", 5000, !!dialog || !!made);
  return { ...keys, made, setMade };
}

export function People({ query }: PageProps) {
  const keys = useKeys(query);
  const { data, error, reload } = keys;
  const [q, setQ] = useState(query.get("q") ?? "");
  const [page, setPage] = useState(Number(query.get("page")) || 1);

  // A revoke done on the server-rendered page, or a link that names one, says so once.
  useEffect(() => {
    const revoked = query.get("revoked");
    if (revoked) {
      const hash = query.get("hash");
      toast(
        `The key of ${revoked}${hash ? `, key hash ${hash}` : ""} is revoked. Requests with it are refused within 2 seconds.`,
      );
      goTo("/people");
    }
  }, [query]);

  const entries = data?.entries ?? [];
  const needle = q.trim().toLowerCase();
  const shown = useMemo(
    () =>
      entries.filter(
        (e) =>
          !needle ||
          e.name.toLowerCase().includes(needle) ||
          e.team.toLowerCase().includes(needle),
      ),
    [entries, needle],
  );
  const pages = Math.max(1, Math.ceil(shown.length / PER_PAGE));
  const at = Math.min(page, pages);
  const onlyAdmins = entries.length > 0 && entries.every((e) => e.admin);

  return (
    <>
      <Head
        title="People"
        lead={
          data?.lead ??
          "Everyone and everything with a key: people, their person tokens, and service keys."
        }
        actions={
          <>
            {data?.may.restore ? (
              <Button
                variant="outline"
                onClick={() => goTo("/people", { stop: "1" })}
              >
                Stop traffic
              </Button>
            ) : null}
            {data?.may.issue ? (
              <Button
                variant="outline"
                onClick={() => goTo("/people", { import: "1" })}
              >
                Import a list
              </Button>
            ) : null}
            {data?.may.issue ? (
              <Button onClick={() => goTo("/people", { issue: "1" })}>
                Issue a key
              </Button>
            ) : null}
          </>
        }
      />
      <ReadOnly data={data} />
      {data?.bring ? <Bring bring={data.bring} /> : null}
      {data?.may.issue && query.get("import") ? (
        <ImportDialog
          agent={data.bring?.import_agent ?? ""}
          close={() => {
            goTo("/people");
            reload();
          }}
        />
      ) : null}
      {error ? <Problem text={error} retry={reload} /> : null}
      {data?.error ? <Problem text={data.error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={5} /> : null}
      {data?.entries ? (
        <>
          {entries.length === 0 || onlyAdmins ? <FirstKey data={data} /> : null}
          {entries.length === 0 ? null : (
            <Panel
              title={count(entries.length, "key")}
              note="A key reaches the models, and what it spends is its holder's. A person token reaches no model: it only names a person, beside their own Claude login. A service key is a key for an app or agent. An admin key also signs in to this console."
              actions={
                <Input
                  type="search"
                  aria-label="Search people and keys"
                  placeholder="Name or team"
                  value={q}
                  onChange={(e) => {
                    setQ(e.target.value);
                    setPage(1);
                  }}
                  className="w-full sm:max-w-col-md"
                />
              }
            >
              {shown.length === 0 ? (
                <Empty
                  title={`Nothing matches "${q.trim()}"`}
                  body="No name or team in the keys file has that text."
                >
                  <Button variant="outline" onClick={() => setQ("")}>
                    Show everyone
                  </Button>
                </Empty>
              ) : (
                <>
                  <KeyTable
                    entries={shown.slice((at - 1) * PER_PAGE, at * PER_PAGE)}
                    route="/people"
                    readOnly={data.read_only}
                    change={keys.change}
                  />
                  {shown.length > PER_PAGE ? (
                    <div className="flex items-center justify-between gap-4">
                      <span className="t-small text-muted-foreground">
                        Page {at} of {pages}, {count(shown.length, "key")}
                      </span>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={at <= 1}
                          onClick={() => setPage(at - 1)}
                        >
                          Previous
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={at >= pages}
                          onClick={() => setPage(at + 1)}
                        >
                          Next
                        </Button>
                      </div>
                    </div>
                  ) : null}
                </>
              )}
            </Panel>
          )}
        </>
      ) : null}
      <KeyDialogs route="/people" query={query} keys={keys} />
    </>
  );
}

export function ReadOnly({ data }: { data: Keys | null }) {
  return data?.read_only ? (
    <div role="status" className="t-body rounded-panel border border-input p-4">
      You are signed in read only: you can see the keys, not issue or revoke
      them. Ask an admin, or ask to be added to an admin group at the identity
      provider.
    </div>
  ) : null;
}

function FirstKey({ data }: { data: Keys }) {
  if (data.read_only || !data.empty) {
    return (
      <Panel>
        <Empty
          title="No keys yet"
          body="Every request through Enterplace carries a key that names a person or an app. An admin issues them."
        />
      </Panel>
    );
  }
  return (
    <Panel title={data.empty.title}>
      <p className="t-body m-0 max-w-measure text-muted-foreground">
        {data.empty.body}
      </p>
      <div className="flex flex-wrap items-center gap-2 rounded-box bg-well px-6 py-3">
        <span className="t-mono min-w-0 flex-1 break-all">
          {data.start_command}
        </span>
        <Copy text={data.start_command} />
      </div>
      <div className="flex flex-wrap gap-2">
        <Button asChild>
          <a href={data.empty.action.href}>{data.empty.action.label}</a>
        </Button>
        <Button variant="outline" asChild>
          <a href={data.empty.docs}>Read the docs page</a>
        </Button>
      </div>
    </Panel>
  );
}

/// Keys as rows: who, what state the key is in, its use, and Edit. Revoke is in the editor, away from the row, so one
/// click on a row never ends a key.
export function KeyTable({
  entries,
  route,
  readOnly,
  change,
  noun = "Name",
}: {
  entries: Entry[];
  route: string;
  readOnly: boolean;
  change: Change;
  noun?: string;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-1/3">{noun}</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Key hash</TableHead>
          <TableHead className="text-right">Requests</TableHead>
          <TableHead>Last request</TableHead>
          <TableHead>
            <span className="sr-only">Actions</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {entries.map((e) => (
          <TableRow key={e.sha256}>
            <TableCell>
              <span className="block max-w-col-md truncate" title={e.name}>
                {e.name}
              </span>
              <span className="block text-muted-foreground">
                {kindOf(e)}
                {e.team ? `, team ${e.team}` : ""}
              </span>
            </TableCell>
            <TableCell className="whitespace-normal">
              <StatusCell status={e.status} />
            </TableCell>
            <TableCell>{e.hash}</TableCell>
            <TableCell className="text-right tabular-nums">
              {num(e.requests)}
            </TableCell>
            <TableCell className="whitespace-nowrap">{e.last}</TableCell>
            <TableCell>
              <div className="flex flex-wrap justify-end gap-2">
                <FixAction fix={e.status.fix} route={route} change={change} />
                {e.editable && !readOnly ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => goTo(route, { edit: e.sha256 })}
                  >
                    Edit
                  </Button>
                ) : null}
              </div>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/// The dialogs a key list opens from its route's query: issue (`?issue=1`, with `name`, `team` and `token` to fill
/// it), edit (`?edit=<sha256>`), revoke (`?revoke=<sha256>`), stop traffic (`?stop=1`, with `scope` and `value`),
/// and the new key, shown once.
export function KeyDialogs({
  route,
  query,
  keys,
  service,
}: {
  route: string;
  query: URLSearchParams;
  keys: ReturnType<typeof useKeys>;
  service?: boolean;
}) {
  const { data, change, made, setMade } = keys;
  const entries = data?.entries ?? [];
  const editing = entries.find((e) => e.sha256 === query.get("edit"));
  const revoking = entries.find((e) => e.sha256 === query.get("revoke"));
  const close = () => goTo(route);
  return (
    <>
      {data?.may.issue && query.get("issue") ? (
        <IssueDialog
          name={query.get("name") ?? ""}
          team={query.get("team") ?? ""}
          token={query.get("token") === "1"}
          service={!!service}
          fullAdmin={data.may.full_admin}
          entries={entries}
          route={route}
          onMade={setMade}
          close={close}
        />
      ) : null}
      {data && editing ? (
        <EditDialog
          entry={editing}
          route={route}
          mayRevoke={!!data.may.revoke}
          mayStop={!!data.may.restore}
          onMade={setMade}
          change={change}
          close={close}
        />
      ) : null}
      {data && revoking ? (
        <RevokeDialog
          entry={revoking}
          keysPath={data.keys_path}
          change={change}
          close={close}
        />
      ) : null}
      {data?.may.restore && query.get("stop") ? (
        <StopDialog
          agent={data.stop_agent}
          entries={entries}
          scope={query.get("scope") ?? "person"}
          value={query.get("value") ?? ""}
          change={change}
          close={close}
        />
      ) : null}
      {made ? (
        <MadeDialog
          made={made}
          service={!!service}
          onClose={() => setMade(null)}
        />
      ) : null}
    </>
  );
}

function StatusCell({ status }: { status: Status }) {
  return (
    <div className="grid gap-2">
      <span>
        <Badge
          className={cn(
            status.kind === "refused" && "border-destructive",
            status.kind === "allow" &&
              "border-transparent pl-0 text-muted-foreground",
          )}
        >
          {status.tag}
        </Badge>
        {status.notes.map((n) => (
          <span key={n} className="block text-muted-foreground">
            {n}
          </span>
        ))}
      </span>
      {status.meter ? (
        <div className="grid min-w-48 gap-1">
          <div className="flex justify-between gap-4">
            <span className="t-small whitespace-nowrap text-muted-foreground">
              Key budget
            </span>
            <span className="t-mono-sm">{status.meter.text}</span>
          </div>
          <div
            role="meter"
            aria-valuenow={status.meter.percent}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Key budget used"
            className="h-1 rounded-pill bg-border"
          >
            <div
              className={cn(
                "h-1 rounded-pill",
                status.meter.over ? "bg-destructive" : "bg-foreground",
              )}
              style={{ width: `${status.meter.percent}%` }}
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}

function FixAction({
  fix,
  route,
  change,
}: {
  fix: Fix;
  route: string;
  change: Change;
}) {
  if (!fix) return null;
  switch (fix.kind) {
    // In place: the answer says it in a toast and the list reads again, with no jump to the Audit log.
    case "restore": {
      const { scope, value } = fix;
      return (
        <Button
          size="sm"
          onClick={() =>
            change(() => api.post("audit/restore", { scope, value }))
          }
        >
          Restore traffic
        </Button>
      );
    }
    case "command":
      return (
        <span className="flex items-center gap-2">
          <span className="t-mono-sm whitespace-normal">{fix.text}</span>
          <Copy text={fix.text} />
        </span>
      );
    case "reissue":
      return (
        <Button
          variant="outline"
          size="sm"
          onClick={() =>
            goTo(route, { issue: "1", name: fix.name, team: fix.team })
          }
        >
          Issue a new key
        </Button>
      );
    case "refusals":
      return (
        <Button variant="outline" size="sm" asChild>
          <a href={fix.href}>See its refusals</a>
        </Button>
      );
  }
}

/// Sends a change that answers with a new key: the key comes back once, so it goes to a dialog, not a toast.
async function makeKey(path: string, body: unknown): Promise<Made | string> {
  try {
    return (await api.post(path, body)) as unknown as Made;
  } catch (e) {
    if (e instanceof Refused) return e.message;
    throw e;
  }
}

function IssueDialog(props: {
  name: string;
  team: string;
  token: boolean;
  service: boolean;
  fullAdmin: boolean;
  entries: Entry[];
  route: string;
  onMade: (m: Made) => void;
  close: () => void;
}) {
  const { service, fullAdmin, entries, route, onMade, close } = props;
  // A second service key under a name that has one is asked about first: rotating is usually what was meant.
  const [second, setSecond] = useState(false);
  const [name, setName] = useState(props.name);
  const [team, setTeam] = useState(props.team);
  const [expires, setExpires] = useState("");
  const [budget, setBudget] = useState("");
  const [per, setPer] = useState("month");
  const [admin, setAdmin] = useState(false);
  const [personToken, setPersonToken] = useState(props.token);
  const [refused, setRefused] = useState("");
  const teams = [...new Set(entries.map((e) => e.team).filter(Boolean))].sort();
  const existing = service
    ? entries.find((e) => isService(e) && e.name === name.trim())
    : undefined;
  const submit = async () => {
    if (existing && !second) {
      setSecond(true);
      return;
    }
    const made = await makeKey("people/issue", {
      name,
      team,
      expires,
      budget,
      per,
      admin,
      person_token: personToken,
      workload: service,
    });
    if (typeof made === "string") setRefused(made);
    else {
      close();
      onMade(made);
    }
  };
  const what = service ? "service key" : personToken ? "person token" : "key";
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent>
        <DialogTitle>
          {service
            ? "Make a service key"
            : personToken
              ? "Hand out a person token"
              : "Issue a key"}
        </DialogTitle>
        <DialogDescription>
          {service
            ? "A service key names an app or an agent, not a person. Keep it in the app's secret store. It is shown once: Enterplace keeps only its hash."
            : personToken
              ? "A person token names the person on every request their coding agent sends with their own Claude login. It reaches no model on its own. It is shown once."
              : "A key lets a person send requests through Enterplace under their name. It is shown once: Enterplace keeps only its hash."}
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field
            id="issue-name"
            label={service ? "App or agent" : "Person"}
            hint="Letters, digits, dots, dashes and underscores."
          >
            <Input
              id="issue-name"
              className="t-mono"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setSecond(false);
              }}
              placeholder={service ? "support-bot" : "maya.cohen"}
              pattern="[A-Za-z0-9._\-]+"
              required
              autoFocus
              autoComplete="off"
            />
          </Field>
          <Field
            id="issue-team"
            label={service ? "Team that owns it" : "Team"}
            hint="Pick a team, or press Create team to start a new one."
          >
            <TeamPicker
              id="issue-team"
              value={team}
              onChange={setTeam}
              teams={teams}
            />
          </Field>
          <Field id="issue-expires" label="Expires, optional">
            <Input
              id="issue-expires"
              type="date"
              className="t-mono"
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
            />
          </Field>
          {personToken ? null : (
            <BudgetField
              id="issue-budget"
              budget={budget}
              per={per}
              setBudget={setBudget}
              setPer={setPer}
              hint={`Most the ${what} may spend, on top of its rule's budget. With a budget, a request holds what its longest possible answer could cost before it is sent: set max_tokens on each request, or one near the limit is refused.`}
            />
          )}
          {service ? null : (
            <label className="t-body flex min-h-11 items-center gap-3">
              <Checkbox
                checked={personToken}
                onCheckedChange={(c) => setPersonToken(c === true)}
              />
              Person token: names the person for Claude subscriptions, reaches
              no model on its own
            </label>
          )}
          {fullAdmin && !service && !personToken ? (
            <label className="t-body flex min-h-11 items-center gap-3">
              <Checkbox
                checked={admin}
                onCheckedChange={(c) => setAdmin(c === true)}
              />
              Admin: may sign in to this console and issue and revoke keys
            </label>
          ) : null}
          <Refusal text={refused} />
          {existing && second ? (
            <div
              role="alert"
              className="grid gap-2 rounded-box border border-input p-4"
            >
              <p className="t-body m-0">
                {existing.name} already has a service key, key hash{" "}
                {existing.hash}. Make a second key that works beside it, or
                rotate the one it has: a new key, with the old one working for a
                grace period.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => goTo(route, { edit: existing.sha256 })}
                >
                  Rotate its key instead
                </Button>
              </div>
            </div>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button type="submit">
              {existing && second
                ? "Make a second key"
                : service
                  ? "Make service key"
                  : personToken
                    ? "Make person token"
                    : "Issue key"}
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function BudgetField(props: {
  id: string;
  budget: string;
  per: string;
  setBudget: (v: string) => void;
  setPer: (v: string) => void;
  hint: string;
}) {
  const { id, budget, per, setBudget, setPer, hint } = props;
  // A period the policy reads but this form does not offer (a week, 6h) is kept as its own choice.
  const periods = [
    "day",
    "month",
    ...(per && per !== "day" && per !== "month" ? [per] : []),
  ];
  return (
    <Field id={id} label="Budget, USD, optional" hint={hint}>
      <div className="flex gap-2">
        <Input
          id={id}
          type="number"
          min={0}
          step="any"
          inputMode="decimal"
          className="t-mono min-w-0 flex-1"
          value={budget}
          onChange={(e) => setBudget(e.target.value)}
          placeholder="20"
        />
        <Select value={per} onValueChange={setPer}>
          <SelectTrigger aria-label="Budget period" className="w-auto">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {periods.map((p) => (
              <SelectItem key={p} value={p}>
                a {p}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </Field>
  );
}

function EditDialog({
  entry,
  route,
  mayRevoke,
  mayStop,
  onMade,
  change,
  close,
}: {
  entry: Entry;
  route: string;
  mayRevoke: boolean;
  mayStop: boolean;
  onMade: (m: Made) => void;
  change: Change;
  close: () => void;
}) {
  const f = entry.fields;
  const [expires, setExpires] = useState(f.expires);
  const [budget, setBudget] = useState(f.budget);
  const [per, setPer] = useState(f.per);
  const [models, setModels] = useState(f.models);
  const [tpm, setTpm] = useState(f.tpm);
  const [admin, setAdmin] = useState(entry.admin);
  const [grace, setGrace] = useState("24h");
  const [refused, setRefused] = useState("");
  const save = async () => {
    const answer = await change(() =>
      api.post("people/edit", {
        sha256: entry.sha256,
        expires,
        budget,
        per,
        models,
        tpm,
        admin,
      }),
    );
    if (answer) setRefused(answer);
    else close();
  };
  const rotate = async () => {
    const made = await makeKey("people/rotate", {
      sha256: entry.sha256,
      grace,
    });
    if (typeof made === "string") setRefused(made);
    else {
      close();
      onMade(made);
    }
  };
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent className="max-w-wide">
        <DialogTitle>Edit the key of {entry.name}</DialogTitle>
        <DialogDescription>
          The key itself does not change and is never shown again: only what it
          may do. Every gateway uses the new settings within 2 seconds.
        </DialogDescription>
        <dl className="t-mono m-0 grid grid-cols-[auto_1fr] gap-x-6 gap-y-2">
          <dt className="t-tag uppercase text-muted-foreground">Name</dt>
          <dd className="m-0 break-all">{entry.name}</dd>
          <dt className="t-tag uppercase text-muted-foreground">Team</dt>
          <dd className="m-0">{entry.team}</dd>
          <dt className="t-tag uppercase text-muted-foreground">Key hash</dt>
          <dd className="m-0">{entry.hash}</dd>
        </dl>
        {entry.limits?.length ? (
          <div className="grid gap-2">
            <span className="t-tag uppercase text-muted-foreground">Limits that apply to this key</span>
            <ul className="t-small m-0 grid gap-1 pl-6">
              {entry.limits.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
            <a className="t-small" href="#/policy?at=limits">
              Change team and person limits in Rules and limits
            </a>
          </div>
        ) : null}
        <Form className="grid gap-6" onSubmit={save}>
          {/* An expiry with a time (an enterplace login key) stays text: a date input cannot show it. */}
          <Field id="key-expires" label="Expires, optional">
            <Input
              id="key-expires"
              type={expires.length <= 10 ? "date" : "text"}
              className="t-mono"
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
            />
          </Field>
          <BudgetField
            id="key-budget"
            budget={budget}
            per={per}
            setBudget={setBudget}
            setPer={setPer}
            hint="Most the key may spend, on top of its rule's budget. Empty for none. With a budget, a request holds what its longest possible answer could cost before it is sent: set max_tokens on each request, or one near the limit is refused."
          />
          <Field
            id="key-models"
            label="Models, optional"
            hint="Only these models, separated by commas. Empty for what its rule allows."
          >
            <Input
              id="key-models"
              className="t-mono"
              value={models}
              onChange={(e) => setModels(e.target.value)}
              placeholder="gpt-4o-mini, o3"
              autoComplete="off"
            />
          </Field>
          <Field id="key-tpm" label="Tokens per minute, optional">
            <Input
              id="key-tpm"
              type="number"
              min={1}
              step={1}
              inputMode="numeric"
              className="t-mono"
              value={tpm}
              onChange={(e) => setTpm(e.target.value)}
            />
          </Field>
          <label className="t-body flex min-h-11 items-center gap-3">
            <Checkbox
              checked={admin}
              onCheckedChange={(c) => setAdmin(c === true)}
            />
            Admin: may sign in to this console and use the admin API
          </label>
          <Refusal text={refused} />
          <DialogFooter className="justify-between">
            <div className="flex flex-wrap gap-2">
              {mayStop ? (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() =>
                    goTo(route, {
                      stop: "1",
                      scope: "person",
                      value: entry.name,
                    })
                  }
                >
                  Stop traffic now
                </Button>
              ) : null}
              {mayRevoke ? (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => goTo(route, { revoke: entry.sha256 })}
                >
                  Revoke key
                </Button>
              ) : null}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" onClick={close}>
                Cancel
              </Button>
              <Button type="submit">Save</Button>
            </div>
          </DialogFooter>
        </Form>
        {/* Rotation is its own form: it makes a new key, where the form above changes what this one may do. */}
        {f.replaced_by ? (
          <p className="t-body m-0 rounded-panel bg-card p-6">
            This key was rotated and replaced by key {f.replaced_by}. It stops
            working at {f.expires}. Rotate the new key instead, or revoke this
            one.
          </p>
        ) : (
          <Form
            className="grid gap-4 rounded-panel bg-card p-6"
            onSubmit={rotate}
          >
            <h3 className="t-sm m-0">Rotate key</h3>
            <p className="t-small m-0 text-muted-foreground">
              Makes a new key with the same settings and shows it once. The old
              key keeps working for the time below.
            </p>
            <Field
              id="key-grace"
              label="Old key works for"
              hint="For example 24h or 7d."
            >
              <Input
                id="key-grace"
                className="t-mono"
                value={grace}
                onChange={(e) => setGrace(e.target.value)}
                required
                autoComplete="off"
              />
            </Field>
            <Button
              type="submit"
              variant="outline"
              className="justify-self-end"
            >
              Rotate the key
            </Button>
          </Form>
        )}
      </DialogContent>
    </Dialog>
  );
}

const STOP_SCOPES: Record<string, string> = {
  person: "A person",
  team: "A team",
  model: "A model",
  key_prefix: "A key (first 8 hex of its hash)",
  all: "Everyone",
};

type Bring = {
  on: boolean;
  state: string;
  agent: string;
  docs: string;
  scim_docs: string;
  import_agent?: string;
};

type Imported = {
  message: string;
  errors?: { line: number; error: string }[];
  issued?: { name: string; team: string; key: string }[];
  lines?: string;
  csv?: string;
};

/// Import a list of people: every line is checked first and nothing is issued while one is wrong; then the keys are
/// shown once, with one Copy all and a CSV download.
const DRAFT = "enterplace.import-draft";
const draft = {
  read: () => {
    try {
      return localStorage.getItem(DRAFT) ?? "";
    } catch {
      return "";
    }
  },
  write: (text: string) => {
    try {
      if (text) localStorage.setItem(DRAFT, text);
      else localStorage.removeItem(DRAFT);
    } catch {
      // Private window or blocked storage: the list just is not kept across a refresh.
    }
  },
};

function ImportDialog({ agent, close }: { agent: string; close: () => void }) {
  // The pasted list survives a refresh until the import succeeds.
  const [text, setTextState] = useState(draft.read);
  const setText = (t: string) => {
    setTextState(t);
    draft.write(t);
  };
  const [copied, setCopied] = useState(false);
  const [warned, setWarned] = useState(false);
  const [result, setResult] = useState<Imported | null>(null);
  const [refused, setRefused] = useState("");
  const load = (file: File | undefined) => {
    if (!file) return;
    file
      .text()
      .then(setText, () =>
        toast.error(
          "The file could not be read. Pick a CSV file and try again.",
        ),
      );
  };
  const submit = async () => {
    try {
      const done = (await api.post("people/import", {
        text,
      })) as unknown as Imported;
      setResult(done);
      if (done.issued) draft.write("");
      setRefused("");
    } catch (e) {
      if (e instanceof Refused) setRefused(e.message);
      else throw e;
    }
  };
  const download = () => {
    if (!result?.csv) return;
    const url = URL.createObjectURL(
      new Blob([result.csv], { type: "text/csv" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "enterplace-keys.csv";
    a.click();
    URL.revokeObjectURL(url);
    setCopied(true);
  };
  const issued = result?.issued;
  const done = () => {
    if (copied || warned) close();
    else setWarned(true);
  };
  return (
    <Dialog open onOpenChange={(open) => !open && !issued && close()}>
      <DialogContent {...(issued ? showOnce : {})}>
        <DialogTitle>{issued ? "The new keys" : "Import a list"}</DialogTitle>
        <DialogDescription>
          {issued
            ? `${result?.message} Enterplace keeps only their hashes.`
            : "One person per line: name, team, an optional monthly budget in dollars, and an optional kind (key, or person for a person token). Every line is checked first; nothing is issued while one is wrong."}
        </DialogDescription>
        {issued ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Copy
                text={result?.lines ?? ""}
                label="Copy all"
                onCopied={() => setCopied(true)}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={download}
              >
                Download CSV
              </Button>
            </div>
            <pre className="t-mono-sm m-0 max-h-80 overflow-auto rounded-box bg-well px-6 py-3">
              {result?.lines}
            </pre>
            <NotCopied shown={warned && !copied} />
            <DialogFooter>
              <Button onClick={done}>
                {warned && !copied ? "Close without copying" : "Done"}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <Form className="grid gap-6" onSubmit={submit}>
            <Field
              id="import-file"
              label="A CSV file, optional"
              hint="Its text replaces the list below."
            >
              <Input
                id="import-file"
                type="file"
                accept=".csv,text/csv,text/plain"
                className="py-2"
                onChange={(e) => load(e.target.files?.[0])}
              />
            </Field>
            <Field id="import-text" label="People">
              <textarea
                id="import-text"
                className="t-mono min-h-24 w-full rounded-box border border-input bg-background px-6 py-3 text-foreground hover:border-foreground"
                rows={8}
                spellCheck={false}
                autoComplete="off"
                placeholder={
                  "name,team,budget,kind\nmaya.cohen,payments,50,key\ndana.levi,payments,,person"
                }
                value={text}
                onChange={(e) => setText(e.target.value)}
                required
              />
            </Field>
            {result?.errors?.length ? (
              <div role="alert" className="grid gap-1">
                <p className="t-body-strong m-0">{result.message}</p>
                <ul className="t-small m-0 grid list-disc gap-1 pl-6">
                  {result.errors.map((e) => (
                    <li key={`${e.line} ${e.error}`}>
                      {e.line ? `Line ${e.line}: ` : ""}
                      {e.error}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            <Refusal text={refused} />
            <DialogFooter>
              {agent ? <Copy text={agent} label="Copy for your agent" /> : null}
              <Button type="button" variant="outline" onClick={close}>
                Cancel
              </Button>
              <Button type="submit">Check and issue</Button>
            </DialogFooter>
          </Form>
        )}
      </DialogContent>
    </Dialog>
  );
}

/// How a whole company gets keys without an admin issuing each one: the paths, which is on, and the agent prompt.
export function Bring({ bring }: { bring: Bring }) {
  return (
    <Panel
      title="Bring everyone in"
      actions={<Copy text={bring.agent} label="Copy for your agent" />}
    >
      <div className="grid gap-4">
        <p className="t-body m-0">{bring.state}</p>
        <ul className="t-body m-0 grid list-disc gap-2 pl-6">
          <li>
            Single sign-on and <span className="t-mono">enterplace login</span>,
            for a whole company: each developer signs in once and gets their own
            expiring key, named by their email, in the team their groups map to.
          </li>
          <li>
            SCIM, in Enterplace Enterprise with a store: your identity provider
            adds people and teams, and removing someone revokes their keys.
          </li>
          <li>
            A list of people: Import a list here (pasted or a CSV file), or{" "}
            <span className="t-mono">enterplace key import people.csv</span> on
            the gateway's machine. A few people or apps: Issue a key.
          </li>
        </ul>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" asChild>
            <a href={bring.docs}>Read Single sign-on</a>
          </Button>
          <Button variant="outline" size="sm" asChild>
            <a href={bring.scim_docs}>Read SCIM provisioning</a>
          </Button>
        </div>
      </div>
    </Panel>
  );
}

/// A kill switch: refuses every request of a person, a team, a key or a model, or all of them, within 2 seconds,
/// until Restore traffic on the Audit log. Recorded with the reason, which the people stopped see in their tool.
function StopDialog(props: {
  agent: string;
  entries: Entry[];
  scope: string;
  value: string;
  change: Change;
  close: () => void;
}) {
  const { change, close } = props;
  const [scope, setScope] = useState(
    STOP_SCOPES[props.scope] ? props.scope : "person",
  );
  const [value, setValue] = useState(props.value);
  const [reason, setReason] = useState("");
  const [refused, setRefused] = useState("");
  // What a stop can name, from the keys: the server refuses any name no key and no request ever had.
  const choices = [
    ...new Set(
      props.entries.map((e) =>
        scope === "team"
          ? e.team
          : scope === "key_prefix"
            ? e.sha256.slice(0, 8)
            : e.name,
      ),
    ),
  ]
    .filter(Boolean)
    .sort();
  const submit = async () => {
    const answer = await change(() =>
      api.post("audit/stop", {
        scope,
        value: scope === "all" ? "" : value,
        reason,
      }),
    );
    if (answer) setRefused(answer);
    else close();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent>
        <DialogTitle>Stop traffic now</DialogTitle>
        <DialogDescription>
          Every gateway refuses the requests within 2 seconds, with the reason
          below, until someone presses Restore traffic on the Audit log. The
          stop is recorded with your name.
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field id="stop-scope" label="Stop">
            <Select value={scope} onValueChange={setScope}>
              <SelectTrigger id="stop-scope">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(STOP_SCOPES).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {scope === "all" ? null : (
            <Field
              id="stop-value"
              label={
                scope === "model"
                  ? "Model, as callers send it"
                  : scope === "key_prefix"
                    ? "Key hash"
                    : scope === "team"
                      ? "Team"
                      : "Person or app"
              }
            >
              <Input
                id="stop-value"
                className="t-mono"
                value={value}
                onChange={(e) => {
                  setValue(e.target.value);
                  setRefused("");
                }}
                list={scope === "model" ? undefined : "stop-choices"}
                aria-invalid={!!refused || undefined}
                required
                autoComplete="off"
              />
              <datalist id="stop-choices">
                {choices.map((c) => (
                  <option key={c} value={c} />
                ))}
              </datalist>
            </Field>
          )}
          <Field
            id="stop-reason"
            label="Reason"
            hint="The people stopped see it in their tool, and the audit log keeps it."
          >
            <Input
              id="stop-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Key leaked in a public repository"
              maxLength={500}
              required
              autoComplete="off"
            />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Copy text={props.agent} label="Copy for your agent" />
            <Button type="button" variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button type="submit">Stop traffic</Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function RevokeDialog({
  entry,
  keysPath,
  change,
  close,
}: {
  entry: Entry;
  keysPath: string;
  change: Change;
  close: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [refused, setRefused] = useState("");
  const submit = async () => {
    const answer = await change(() =>
      api.post("people/revoke", { sha256: entry.sha256, confirm: typed }),
    );
    if (answer) setRefused(answer);
    else close();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent>
        <DialogTitle>Revoke the key of {entry.name}?</DialogTitle>
        <DialogDescription>
          The key stops working. Its entry, key hash {entry.hash}, is removed
          from {keysPath}. A running gateway refuses the key within 2 seconds,
          and console sessions signed in with it end now. This cannot be undone:{" "}
          {entry.name} would need a new key. Type{" "}
          <span className="t-mono">{entry.name}</span> to confirm.
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field id="revoke-type" label="Name, to confirm">
            <Input
              id="revoke-type"
              className="t-mono"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              required
              autoFocus
              autoComplete="off"
              aria-invalid={!!refused}
            />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={typed !== entry.name}
            >
              Revoke key
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function MadeDialog({
  made,
  service,
  onClose,
}: {
  made: Made;
  service: boolean;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [warned, setWarned] = useState(false);
  const token = made.key.startsWith("enterplace_u_");
  const done = () => {
    if (copied || warned) onClose();
    else setWarned(true);
  };
  // An app gets its address, not the coding agents' lines.
  const lines = service
    ? `# OpenAI SDKs\nexport OPENAI_BASE_URL=${window.location.origin}/v1\nexport OPENAI_API_KEY=${made.key}\n# Anthropic SDKs\nexport ANTHROPIC_BASE_URL=${window.location.origin}\nexport ANTHROPIC_API_KEY=${made.key}`
    : (made.lines ?? []).join("\n");
  return (
    <Dialog open>
      <DialogContent {...showOnce}>
        <DialogTitle>
          {token
            ? "The new person token"
            : service
              ? "The new service key"
              : "The new key"}
        </DialogTitle>
        <DialogDescription>
          {made.until
            ? `For ${made.name}, team ${made.team}, with the settings of the key it replaces. It is shown once and is not stored anywhere: copy it now. ${made.message ?? ""}`
            : `For ${made.name}, team ${made.team}. It is shown once and is not stored anywhere: copy it now. A running gateway accepts it within 2 seconds.${made.rotated ? ` ${made.name} already had a key. Both work until the old one is revoked.` : ""}`}
        </DialogDescription>
        <div className="flex flex-wrap items-center gap-3 rounded-box bg-well px-6 py-3">
          <span id="new-key" className="t-mono min-w-0 flex-1 break-all">
            {made.key}
          </span>
          <Copy text={made.key} onCopied={() => setCopied(true)} />
        </div>
        {lines ? (
          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-4">
              <span className="t-small text-muted-foreground">
                {service
                  ? "Set these where the app runs:"
                  : token
                    ? "Paste these in the shell where Claude Code runs. Keep your own Claude login: the token only names you."
                    : "The lines for each tool, with this key and this gateway's address:"}
              </span>
              <Copy text={lines} onCopied={() => setCopied(true)} />
            </div>
            <pre className="t-mono-sm m-0 overflow-x-auto rounded-box bg-well px-6 py-3">
              {lines}
            </pre>
          </div>
        ) : null}
        <NotCopied shown={warned && !copied} />
        <DialogFooter>
          <Button onClick={done}>
            {warned && !copied ? "Close without copying" : "Done"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// A dialog with a secret shown once closes only with its own button: not with Escape or a click outside.
const showOnce = {
  onEscapeKeyDown: (e: Event) => e.preventDefault(),
  onInteractOutside: (e: Event) => e.preventDefault(),
};

function NotCopied({ shown }: { shown: boolean }) {
  return shown ? (
    <p role="alert" className="t-small m-0 text-destructive-text">
      You have not copied it yet. It is never shown again: once closed, a new
      one has to be made.
    </p>
  ) : null;
}
