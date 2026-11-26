import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { Sheet as Side, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Head, Loading, Panel, Problem, Refusal } from "@/components/page";
import { Person, unnamed } from "@/components/person";
import { Copy } from "@/components/copy";
import { api, part, Refused, UNNAMED } from "@/lib/api";
import { failureText } from "@/lib/failures";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import type { PageProps } from "@/pages";

// `error`: let through, and the provider failed it; its code and status are worded by lib/failures.
type Tag = { kind: string; text: string; code?: string; status?: number | null; provider?: string };
type Filter = { name: string; label: string; value: string; kind: string; more: boolean };
type Row = {
  id: string;
  time: string;
  person: string;
  team: string;
  model: string;
  provider: string;
  outcome: Tag;
  proof: Tag | null;
  tokens: string;
  cost: string;
  estimate: boolean;
  latency: string;
};
type EmptyState = {
  title: string;
  body: string;
  action: { label: string; href: string } | null;
  docs?: string;
  command?: string;
  notes?: string[];
};
type Data = {
  lead: string;
  filters: Filter[];
  more_open: boolean;
  /// The values the newest requests hold for each filter field, offered as the field is typed in.
  values?: Record<string, string[]>;
  rows: Row[];
  est_header: string;
  est_tip: string;
  empty: EmptyState | null;
  pager: { text: string; page: number; newer: boolean; older: boolean };
};
type Pair = [string, string];
type Sheet = {
  id: string;
  title: string;
  failed: Tag | null;
  outcome?: Tag;
  facts: Pair[];
  details: Pair[];
  proof: { facts: Pair[]; text: string; audit: string };
  body: boolean;
};
type Kept = { id: string; lead: string; facts: Pair[]; request: string; answer: string };

// `unnamed` is no outcome of its own: allowed, with no person named, as the chip reads it.
const OUTCOMES: Pair[] = [
  ["", "All"],
  ["allowed", "Allowed"],
  ["unnamed", "Allowed, unnamed"],
  ["refused", "Refused"],
  ["error", "Errors"],
];

/// Moves the # route's query to `next`, so a filter, a page or an open request is a link that can be shared.
function setQuery(next: URLSearchParams) {
  const kept = new URLSearchParams([...next].filter(([, v]) => v));
  window.location.hash = `#/requests${kept.size ? `?${kept}` : ""}`;
}

/// The query with `name` set to `value` (or cleared), back on the first page unless the page itself changes.
function with_(query: URLSearchParams, name: string, value: string) {
  const next = new URLSearchParams(query);
  next.set(name, value);
  if (name !== "page" && name !== "record") next.delete("page");
  return next;
}

// The tag kinds the API sends, as the console's Tag colors them: a refusal or a failed proof stands out.
// Lime marks a request that passed, flame one that was stopped: the only two colors in the console.
function TagOf({ tag }: { tag: Tag }) {
  return (
    <Badge className={cn((tag.kind === "refused" || tag.kind === "block" || tag.kind === "error") && "border-destructive text-destructive-text", tag.kind === "allow" && "border-transparent pl-0 text-muted-foreground")}>
      {tag.kind === "allow" ? <span aria-hidden="true" className="size-2 rounded-pill border border-foreground bg-lime" /> : null}
      {tag.kind === "warn" ? <span aria-hidden="true" className="size-2 rounded-pill border-2 border-current" /> : null}
      {tag.kind === "error" ? failureText(tag) : tag.text}
    </Badge>
  );
}

export function Requests({ query }: PageProps) {
  const record = query.get("record") ?? "";
  const list = new URLSearchParams(query);
  list.delete("record");
  // Live: the list is read again every 5 seconds, unless a request's sheet is open over it.
  const { data, error, reload } = useData<Data>(`requests${list.size ? `?${list}` : ""}`, 5000, !!record);

  return (
    <>
      <Head title="Requests" lead={data?.lead ?? "Every request, newest first. New ones appear as they arrive."} />
      {error ? (
        <Panel title="This did not load">
          <Problem text={error} retry={reload} />
          <Button variant="outline" className="justify-self-start" onClick={() => setQuery(new URLSearchParams())}>
            Show everything
          </Button>
        </Panel>
      ) : null}
      {!data && !error ? <Loading rows={8} /> : null}
      {data ? (
        <section className="grid gap-6 rounded-panel bg-card p-6">
          {/* Keyed by the query, so a new link refills the fields and a poll never resets what is being typed. */}
          {data.empty && !list.size ? null : <Filters key={list.toString()} data={data} query={list} />}
          {data.empty ? <EmptyPanel empty={data.empty} /> : <RowsTable data={data} query={list} />}
        </section>
      ) : null}
      {record ? <RecordSheet id={record} onClose={() => setQuery(list)} /> : null}
    </>
  );
}

function Filters({ data, query }: { data: Data; query: URLSearchParams }) {
  const [id, setId] = useState(query.get("id") ?? "");
  // From the link, not from the answer: a new link refills the fields before the list for it has loaded.
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(data.filters.map((f) => [f.name, query.get(f.name) ?? ""])));
  const outcome = query.get("outcome") ?? "";
  const unnamedOn = outcome === "allowed" && query.get("person") === UNNAMED;
  const pressed = (value: string) => (value === "unnamed" ? unnamedOn : outcome === value && !unnamedOn);
  const pick = (value: string) => {
    if (value === "unnamed") return setQuery(with_(with_(query, "outcome", "allowed"), "person", UNNAMED));
    setQuery(with_(unnamedOn ? with_(query, "person", "") : query, "outcome", value));
  };
  const apply = (e: React.FormEvent) => {
    e.preventDefault();
    const next = new URLSearchParams(Object.entries(values));
    next.set("outcome", outcome);
    next.set("id", id);
    setQuery(next);
  };
  const field = (f: Filter) => (
    <div key={f.name} className="min-w-0 flex-1 basis-[calc(var(--space-24)+var(--space-10))]">
      <Field id={`f-${f.name}`} label={f.label}>
        <Input
          id={`f-${f.name}`}
          name={f.name}
          type={f.kind}
          className="t-mono min-w-0"
          value={values[f.name] ?? ""}
          onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
          autoComplete="off"
          list={data.values?.[f.name]?.length ? `v-${f.name}` : undefined}
        />
      </Field>
      {data.values?.[f.name]?.length ? (
        <datalist id={`v-${f.name}`}>
          {data.values[f.name].map((v) => (
            <option key={v} value={v} />
          ))}
        </datalist>
      ) : null}
    </div>
  );
  return (
    <form className="grid gap-4" onSubmit={apply}>
      <div className="flex flex-wrap items-center gap-4">
        <Input
          type="search"
          aria-label="Decision ID"
          placeholder="Decision ID"
          value={id}
          onChange={(e) => setId(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && apply(e)}
          className="t-mono max-w-col-md"
        />
        <div role="group" aria-label="Show" className="flex flex-wrap gap-2">
          {OUTCOMES.map(([value, label]) => (
            <Button key={value} type="button" size="sm" variant={pressed(value) ? "default" : "outline"} aria-pressed={pressed(value)} onClick={() => pick(value)}>
              {label}
            </Button>
          ))}
        </div>
      </div>
      <div className="flex flex-wrap items-end gap-4">
        {data.filters.filter((f) => !f.more).map(field)}
        <div className="flex gap-2">
          <Button type="submit" variant="outline">
            Filter
          </Button>
          <Button type="button" variant="outline" onClick={() => setQuery(new URLSearchParams())}>
            Clear
          </Button>
        </div>
      </div>
      {/* Folded until asked for, and open while one of its own filters is set, so a set filter is never hidden. */}
      <details open={data.more_open} className="grid gap-4">
        <summary className="t-small cursor-pointer underline">More filters</summary>
        <div className="flex flex-wrap items-end gap-4 pt-4">{data.filters.filter((f) => f.more).map(field)}</div>
      </details>
    </form>
  );
}

function EmptyPanel({ empty }: { empty: EmptyState }) {
  return (
    <div className="grid justify-items-start gap-4 py-6">
      <p className="t-body-strong m-0">{empty.title}</p>
      <p className="t-body m-0 text-muted-foreground">{empty.body}</p>
      {empty.notes?.[0] ? <p className="t-small m-0 text-muted-foreground">{empty.notes[0]}</p> : null}
      {empty.command ? (
        <div className="flex w-full flex-wrap items-center gap-2 rounded-box bg-well px-6 py-3">
          <span className="t-mono min-w-0 flex-1 break-all">{empty.command}</span>
          <Copy text={empty.command} />
        </div>
      ) : null}
      {empty.notes?.slice(1).map((n) => (
        <p key={n} className="t-small m-0 text-muted-foreground">
          {n}
        </p>
      ))}
      <div className="flex flex-wrap gap-2">
        {empty.action ? (
          <Button asChild>
            <a href={empty.action.href}>{empty.action.label}</a>
          </Button>
        ) : null}
        {empty.docs ? (
          <Button variant="outline" asChild>
            <a href={empty.docs}>Read the docs page</a>
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function RowsTable({ data, query }: { data: Data; query: URLSearchParams }) {
  // A person, team, model or provider is a link to the same list narrowed to it.
  const narrow = (name: string, value: string) =>
    value ? (
      <a href={`#/requests?${with_(query, name, value)}`} className="text-foreground">
        {value}
      </a>
    ) : null;
  const { pager } = data;
  return (
    <>
      <Table className="t-mono-sm" long>
        <TableHeader>
          <TableRow>
            <TableHead>Time (UTC)</TableHead>
            <TableHead>Person</TableHead>
            <TableHead>Outcome</TableHead>
            <TableHead>Model</TableHead>
            <TableHead className="text-right">Tokens</TableHead>
            <TableHead className="text-right" title={data.est_tip}>
              {data.est_header}
            </TableHead>
            <TableHead className="text-right">Latency</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.rows.map((r) => (
            // The whole row opens its sheet; the time stays the link a keyboard reaches. A link inside opens itself.
            <TableRow key={r.id} className="cursor-pointer" onClick={(e) => (e.target as HTMLElement).closest("a") || setQuery(with_(query, "record", r.id))}>
              <TableCell>
                <a href={`#/requests?${with_(query, "record", r.id)}`} aria-label={`Open request ${r.id}`} className="text-foreground">
                  {r.time}
                </a>
              </TableCell>
              <TableCell>
                {unnamed(r.person) ? <Person name={r.person} /> : narrow("person", r.person)}
                <span className="block text-muted-foreground">{narrow("team", r.team)}</span>
              </TableCell>
              <TableCell>
                <span className="flex flex-wrap gap-2">
                  <TagOf tag={r.outcome} />
                  {/* Proof shows only where it fails. */}
                  {r.proof ? <TagOf tag={r.proof} /> : null}
                </span>
              </TableCell>
              <TableCell className="whitespace-normal">
                {narrow("model", r.model)}
                <span className="block text-muted-foreground">{narrow("provider", r.provider)}</span>
              </TableCell>
              <TableCell className="text-right tabular-nums">{r.tokens}</TableCell>
              <TableCell className="text-right tabular-nums" title={r.estimate ? data.est_tip : undefined}>
                {r.cost}
              </TableCell>
              <TableCell className="text-right tabular-nums">{r.latency}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <span className="t-small text-muted-foreground">{pager.text}</span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={!pager.newer} onClick={() => setQuery(with_(query, "page", String(pager.page - 1)))}>
            Newer requests
          </Button>
          <Button variant="outline" size="sm" disabled={!pager.older} onClick={() => setQuery(with_(query, "page", String(pager.page + 1)))}>
            Older requests
          </Button>
        </div>
      </div>
    </>
  );
}

function Facts({ facts }: { facts: Pair[] }) {
  return (
    <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] gap-x-6 gap-y-2">
      {facts.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="t-tag uppercase text-muted-foreground">{label}</dt>
          <dd className="t-mono-sm m-0 break-all">{label === "Person" && unnamed(value) ? <Person name={value} /> : value}</dd>
        </div>
      ))}
    </dl>
  );
}

function RecordSheet({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useData<Sheet>(`requests/${part(id)}`);
  const [kept, setKept] = useState<Kept | null>(null);
  const [refused, setRefused] = useState("");
  // The view is recorded before the body is sent, so it is asked for only on this click, never on open.
  const read = async () => {
    try {
      setKept((await api.post("requests/body", { id })) as unknown as Kept);
      setRefused("");
    } catch (e) {
      if (e instanceof Refused) setRefused(e.message);
      else throw e;
    }
  };
  return (
    <Side open onOpenChange={(open) => !open && onClose()}>
      <SheetContent>
        <SheetTitle>{data?.title ?? (error ? "No request has this ID" : "Request")}</SheetTitle>
        <SheetDescription className="t-mono-sm">{id}</SheetDescription>
        {error ? <Problem text={error} /> : null}
        {data ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              {data.outcome ? <TagOf tag={data.outcome} /> : null}
              {data.failed ? <TagOf tag={data.failed} /> : null}
              {/* The whole record as text, for a ticket or a chat: every fact, detail and proof line. */}
              <Copy text={recordText(data)} label="Copy the record" />
              {data.outcome?.kind === "error" ? (
                <Button variant="outline" size="sm" asChild>
                  <a href="#/deployments">Test connection</a>
                </Button>
              ) : null}
            </div>
            <Facts facts={data.facts} />
            {data.body ? (
              <div className="grid justify-items-start gap-2">
                {kept ? null : <Button onClick={read}>Read the kept body</Button>}
                <p className="t-small m-0 text-muted-foreground">Its rule keeps the redacted request and answer. Reading them is recorded in the audit log, and only the rule's viewers may.</p>
                <Refusal text={refused} />
              </div>
            ) : null}
            {kept ? (
              <div className="grid gap-4">
                <p className="t-small m-0 text-muted-foreground">{kept.lead}</p>
                <Facts facts={kept.facts} />
                <h3 className="t-sm m-0">Request, as sent</h3>
                <pre className="t-mono-sm m-0 overflow-x-auto rounded-box bg-well px-6 py-3">{kept.request}</pre>
                <h3 className="t-sm m-0">Answer</h3>
                <pre className="t-mono-sm m-0 overflow-x-auto rounded-box bg-well px-6 py-3">{kept.answer}</pre>
              </div>
            ) : null}
            <details open className="grid gap-4">
              <summary className="t-small cursor-pointer underline">Details</summary>
              <div className="pt-4">
                <Facts facts={data.details} />
              </div>
            </details>
            <details className="grid gap-4">
              <summary className="t-small cursor-pointer underline">Proof</summary>
              <div className="grid justify-items-start gap-4 pt-4">
                <Facts facts={data.proof.facts} />
                <p className="t-small m-0 text-muted-foreground">{data.proof.text}</p>
                <Button variant="outline" size="sm" asChild>
                  <a href={data.proof.audit}>Open its audit record</a>
                </Button>
              </div>
            </details>
          </>
        ) : null}
      </SheetContent>
    </Side>
  );
}

function recordText(sheet: Sheet) {
  const lines = (pairs: Pair[]) => pairs.map(([label, value]) => `${label}: ${value}`);
  const outcome = sheet.outcome ? [`Outcome: ${sheet.outcome.kind === "error" ? failureText(sheet.outcome) : sheet.outcome.text}`] : [];
  return [sheet.title, `Request: ${sheet.id}`, ...outcome, ...lines(sheet.facts), ...lines(sheet.details), ...lines(sheet.proof.facts)].join("\n");
}
