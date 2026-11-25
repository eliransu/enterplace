import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Loading, Problem, Stat } from "@/components/page";
import { Person } from "@/components/person";
import { Copy } from "@/components/copy";
import { api } from "@/lib/api";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import type { PageProps } from "@/pages";

type Tag = { kind: string; word: string; detail: string };
type Row = { id: string; who: string; sub: string; verdict: Tag; time: string; open: string; model: string; title: string; selected: boolean };
type Kill = { label: string; since: string; by: string; reason: string; scope: string; value: string; command: string };
type Verified = {
  state: "none" | "ok" | "broken";
  text: string;
  last_hash?: string;
  note?: string;
  banner?: string;
  open?: { label: string; record: string } | null;
  recent?: boolean;
};
type Line = { n: number; text: string; kind: string };
type Sheet = {
  missing?: boolean;
  id?: string;
  verdict?: Tag;
  title: string;
  lead: string;
  request?: { method: string; path: string; id: string } | null;
  facts?: { label: string; text: string; tag?: Tag }[];
  snippet?: { note: string | null; lines: Line[] } | null;
  actions?: { label: string; href: string; quiet: boolean }[];
  broken?: string | null;
};
type Data = {
  lead: string;
  chain: string;
  chains: { label: string; chain: string; shown: boolean }[];
  empty: { title: string; body: string; action: { label: string; href: string }; docs: string } | null;
  total: number;
  kills: Kill[];
  kills_error: string | null;
  may_restore: boolean;
  verified?: Verified;
  stats?: { checked: string; refused: string; blocked: string } | null;
  models?: string[];
  show?: string;
  shows?: { value: string; label: string }[];
  noun?: string;
  rows?: Row[];
  matched?: number;
  pager?: { text: string; page: number; pages: number };
  caution?: boolean;
  record?: Sheet | null;
};

// The filters, the chain and the open record are the # route's query, so the old page's links and its redirect
// open the same view, and a record is a link that can be shared.
const KEYS = ["verdict", "q", "model", "chain", "page", "record"];

function setQuery(query: URLSearchParams, change: Record<string, string>) {
  const next = new URLSearchParams();
  for (const key of KEYS) {
    const value = key in change ? change[key] : (query.get(key) ?? "");
    if (value) next.set(key, value);
  }
  window.location.hash = `#/audit${next.size ? `?${next}` : ""}`;
}

export function Audit({ query }: PageProps) {
  const ask = new URLSearchParams(KEYS.flatMap((k) => (query.get(k) ? [[k, query.get(k) ?? ""]] : [])));
  const open = !!query.get("record");
  // Live: the list reads the chain again every 5 seconds while no record is open, as the gateway writes records.
  const { data, error, change, reload } = useData<Data>(`audit${ask.size ? `?${ask}` : ""}`, 5000, open);
  const [q, setQ] = useState(query.get("q") ?? "");
  useEffect(() => setQ(query.get("q") ?? ""), [query]);

  const verify = () => change(() => api.post("audit/verify", { chain: data?.chain ?? "" }));

  return (
    <>
      {data?.kills_error ? <Problem text={data.kills_error} /> : null}
      {data?.kills.length ? <Kills kills={data.kills} mayRestore={data.may_restore} change={change} /> : null}
      {data?.verified?.state === "broken" ? <Broken verified={data.verified} query={query} /> : null}
      <Head
        title="Audit log"
        lead={data?.lead ?? "Every decision and admin change, in one chain."}
        actions={data?.chains.map((c) => (
          <Button key={c.label} variant={c.shown ? "default" : "outline"} size="sm" onClick={() => setQuery(new URLSearchParams(), { chain: c.chain })}>
            {c.label}
          </Button>
        ))}
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={8} /> : null}
      {data?.empty ? <Start empty={data.empty} /> : null}
      {data && data.total > 0 && data.rows ? (
        <>
          {data.stats ? (
            <section className="grid gap-6 rounded-panel bg-card p-6 sm:grid-cols-3">
              <Stat figure={data.stats.checked} label="requests checked today" />
              <Stat figure={data.stats.refused} label="refused today" />
              <Stat figure={data.stats.blocked} label="blocked by a guardrail today" />
            </section>
          ) : null}
          <form
            className="flex flex-wrap items-center gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              setQuery(query, { q: q.trim(), page: "", record: "" });
            }}
          >
            <Input type="search" aria-label="Search the audit log" placeholder="Person, team, ID or key hash" value={q} onChange={(e) => setQ(e.target.value)} className="max-w-col-md" />
            <div role="group" aria-label="Show" className="flex flex-wrap gap-1">
              {data.shows?.map((s) => (
                <Button
                  key={s.value}
                  type="button"
                  size="sm"
                  variant={s.value === data.show ? "default" : "ghost"}
                  aria-pressed={s.value === data.show}
                  onClick={() => setQuery(query, { verdict: s.value === "all" ? "" : s.value, page: "", record: "" })}
                >
                  {s.label}
                </Button>
              ))}
            </div>
            <Select value={query.get("model") || "*"} onValueChange={(m) => setQuery(query, { model: m === "*" ? "" : m, page: "", record: "" })}>
              <SelectTrigger aria-label="Model" className="w-auto">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="*">Every model</SelectItem>
                {data.models?.map((m) => (
                  <SelectItem key={m} value={m}>
                    {m}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </form>
          {data.rows.length === 0 ? (
            <section className="grid gap-4 rounded-panel bg-card p-6">
              <Empty title="No decision matches" body="No decision matches this person, team, ID, key hash or model in the audit log." />
              <Button variant="outline" className="justify-self-start" onClick={() => setQuery(new URLSearchParams(), { chain: query.get("chain") ?? "" })}>
                Show every decision
              </Button>
            </section>
          ) : (
            <section className="grid gap-4 rounded-panel bg-card p-6">
              {data.caution ? <p className="t-small m-0 text-muted-foreground">Records from the one named above onwards cannot be trusted until it is explained.</p> : null}
              <Rows data={data} query={query} />
              {data.pager ? <Pager pager={data.pager} noun={data.noun ?? "decisions"} query={query} /> : null}
            </section>
          )}
          {data.verified ? <ChainLine verified={data.verified} verify={verify} /> : null}
        </>
      ) : data && data.total === 0 && !error ? (
        <Button variant="outline" className="justify-self-start" onClick={verify}>
          Verify chain now
        </Button>
      ) : null}
      {data?.record ? <RecordSheet sheet={data.record} onClose={() => setQuery(query, { record: "" })} /> : null}
    </>
  );
}

function Start({ empty }: { empty: NonNullable<Data["empty"]> }) {
  return (
    <section className="grid gap-4 rounded-panel bg-card p-6">
      <Empty title={empty.title} body={empty.body} />
      <div className="flex flex-wrap gap-2">
        <Button asChild>
          <a href={empty.action.href}>{empty.action.label}</a>
        </Button>
        <Button variant="outline" asChild>
          <a href={empty.docs}>Read the docs page</a>
        </Button>
      </div>
    </section>
  );
}


// The console's Tag in its kinds: a refusal edged in flame, a block filled with it, an allow without a border.
export function VerdictTag({ tag }: { tag: Tag }) {
  return (
    <Badge
      className={cn(
        tag.kind === "refused" && "border-destructive",
        tag.kind === "block" && "border-destructive bg-destructive text-destructive-foreground",
        tag.kind === "allow" && "border-transparent pl-0 text-muted-foreground",
      )}
    >
      {tag.kind === "mask" ? <span aria-hidden="true" className="w-2 border-t-2 border-current" /> : null}
      {tag.kind === "warn" ? <span aria-hidden="true" className="size-2 rounded-pill border-2 border-current" /> : null}
      {tag.word}
      {tag.detail ? <span className="t-mono-sm normal-case">{tag.detail}</span> : null}
    </Badge>
  );
}

function Rows({ data, query }: { data: Data; query: URLSearchParams }) {
  const changes = data.show === "changes";
  return (
    <Table long>
      <TableHeader>
        <TableRow>
          <TableHead>{changes ? "Who" : "Person or app"}</TableHead>
          {changes ? <TableHead>Change and reason</TableHead> : <TableHead>Verdict</TableHead>}
          <TableHead>Time</TableHead>
          {changes ? null : <TableHead>Model</TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.rows?.map((r) => (
          <TableRow key={r.id} aria-selected={r.selected || undefined} className={cn(r.selected && "[&>td]:bg-well")}>
            <TableCell className="break-words whitespace-normal">
              {changes ? r.who : <Person name={r.who} />}
              {r.sub ? <span className="block text-muted-foreground">{r.sub}</span> : null}
            </TableCell>
            <TableCell className="whitespace-normal">
              {changes ? <span className="t-body block">{r.title}</span> : null}
              {r.verdict.kind === "allow" ? (
                <span className="inline-flex items-center gap-2">
                  <span aria-hidden="true" className="size-2 rounded-pill border border-foreground bg-lime" />
                  <VerdictTag tag={r.verdict} />
                </span>
              ) : (
                <VerdictTag tag={r.verdict} />
              )}
            </TableCell>
            <TableCell>
              {/* The row opens on its time: the ID is in the sheet, a 26-character ID is no label for a row. */}
              <a href={`#/audit?${withRecord(query, r.id)}`} aria-label={r.open} data-record={r.id} className="text-foreground">
                {r.time}
              </a>
            </TableCell>
            {changes ? null : <TableCell>{r.model}</TableCell>}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function withRecord(query: URLSearchParams, record: string) {
  const next = new URLSearchParams();
  for (const key of KEYS) if (query.get(key) && key !== "record") next.set(key, query.get(key) ?? "");
  next.set("record", record);
  return next.toString();
}

function Pager({ pager, noun, query }: { pager: NonNullable<Data["pager"]>; noun: string; query: URLSearchParams }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4">
      <span className="t-small text-muted-foreground">{pager.text}</span>
      {pager.pages > 1 ? (
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={pager.page <= 1} onClick={() => setQuery(query, { page: String(pager.page - 1), record: "" })}>
            Newer {noun}
          </Button>
          <Button variant="outline" size="sm" disabled={pager.page >= pager.pages} onClick={() => setQuery(query, { page: String(pager.page + 1), record: "" })}>
            Older {noun}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

// Verify sits with the chain's line under the records: it checks the data, it is not the page's main action.
function ChainLine({ verified, verify }: { verified: Verified; verify: () => void }) {
  const line = useRef<HTMLDivElement>(null);
  // Just after Verify chain now, focus goes to its result, so it is read out instead of the page top.
  useEffect(() => {
    if (verified.recent) line.current?.focus();
  }, [verified.recent, verified.text]);
  return (
    <div ref={line} tabIndex={-1} className="grid justify-items-start gap-2" aria-live="polite">
      <span className={cn("t-small", verified.state === "none" || verified.state === "broken" ? "text-muted-foreground" : "")}>{verified.text}</span>
      {verified.last_hash ? (
        <div className="flex w-full flex-wrap items-center gap-3 rounded-box bg-well px-6 py-3">
          <span id="last-hash" className="t-mono-sm min-w-0 flex-1 break-all">
            {verified.last_hash}
          </span>
          <Copy text={verified.last_hash} />
        </div>
      ) : null}
      {verified.note ? <span className="t-small text-muted-foreground">{verified.note}</span> : null}
      <Button variant="outline" size="sm" onClick={verify}>
        Verify chain now
      </Button>
    </div>
  );
}

function Broken({ verified, query }: { verified: Verified; query: URLSearchParams }) {
  return (
    <div role="alert" className="flex flex-wrap items-center justify-between gap-4 rounded-panel border border-destructive p-6">
      <span className="t-body">{verified.banner}</span>
      {verified.open ? (
        <Button size="sm" asChild>
          <a href={`#/audit?${withRecord(query, verified.open.record)}`}>{verified.open.label}</a>
        </Button>
      ) : null}
    </div>
  );
}

type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

// One line per switch on now, as the KillSwitch design reads, and the way to turn it off.
function Kills({ kills, mayRestore, change }: { kills: Kill[]; mayRestore: boolean; change: Change }) {
  return (
    <div role="alert" className="grid gap-3 rounded-panel border border-destructive p-6">
      {kills.map((k) => (
        <div key={`${k.scope}:${k.value}`} className="flex flex-wrap items-center justify-between gap-4">
          <span className="t-body">
            Traffic stopped for <span className="t-mono">{k.label}</span> since {k.since} by {k.by}: {k.reason}
          </span>
          {mayRestore ? (
            <Button size="sm" onClick={() => change(() => api.post("audit/restore", { scope: k.scope, value: k.value }))}>
              Restore traffic
            </Button>
          ) : (
            <span className="t-mono-sm">{k.command}</span>
          )}
        </div>
      ))}
    </div>
  );
}

function RecordSheet({ sheet, onClose }: { sheet: Sheet; onClose: () => void }) {
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        className="max-w-wide"
        // The sheet opens from a link, not a dialog trigger: focus goes back to that row's link when it closes.
        onCloseAutoFocus={(e) => {
          const row = document.querySelector<HTMLElement>(`a[data-record="${sheet.id}"]`);
          if (row) {
            e.preventDefault();
            row.focus();
          }
        }}
      >
        {sheet.verdict ? (
          <div>
            <VerdictTag tag={sheet.verdict} />
          </div>
        ) : null}
        {sheet.broken ? <Problem text={sheet.broken} /> : null}
        <DialogTitle>{sheet.title}</DialogTitle>
        <DialogDescription>{sheet.lead}</DialogDescription>
        {sheet.request ? (
          <div aria-label="The request" className="t-mono grid gap-1 rounded-box bg-well px-6 py-3">
            <span>
              {sheet.request.method} {sheet.request.path}
            </span>
            <span className="text-muted-foreground">Decision {sheet.request.id}</span>
          </div>
        ) : null}
        {sheet.facts?.length ? (
          <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-6 gap-y-2">
            {sheet.facts.map((f, i) => (
              <div key={`${f.label}-${i}`} className="contents">
                <dt className="t-tag uppercase text-muted-foreground">{f.label}</dt>
                <dd className="t-mono-sm m-0 grid min-w-0 justify-items-start gap-1 break-all">
                  {f.tag ? <VerdictTag tag={f.tag} /> : null}
                  <span>{f.text}</span>
                </dd>
              </div>
            ))}
          </dl>
        ) : null}
        {sheet.snippet ? <Snippet snippet={sheet.snippet} /> : null}
        {sheet.actions?.length ? (
          <div className="flex flex-wrap gap-2">
            {sheet.actions.map((a) => (
              <Button key={a.label} variant={a.quiet ? "outline" : "default"} size="sm" asChild>
                <a href={a.href}>{a.label}</a>
              </Button>
            ))}
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

// The rule's lines as the policy reads them, or what a change did to it: + added, - removed, the deciding line marked.
function Snippet({ snippet }: { snippet: NonNullable<Sheet["snippet"]> }) {
  return (
    <div className="grid gap-2">
      {snippet.note ? <p className="t-small m-0 text-muted-foreground">{snippet.note}</p> : null}
      {snippet.lines.length ? (
        <div className="t-mono-sm grid overflow-x-auto rounded-box bg-well py-3">
          {snippet.lines.map((l, i) => (
            <div
              key={i}
              data-kind={l.kind || undefined}
              className={cn("flex gap-4 px-6 whitespace-pre", (l.kind === "hit" || l.kind === "add") && "bg-lime text-on-lime", l.kind === "del" && "text-destructive-text")}
            >
              <span aria-hidden="true" className="w-8 flex-none text-right text-muted-foreground">
                {l.kind === "add" ? "+" : l.kind === "del" ? "-" : l.n}
              </span>
              <span>{l.text}</span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
