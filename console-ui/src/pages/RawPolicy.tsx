import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Form, Head, Loading, Panel, Problem, Refusal } from "@/components/page";
import { Confirm } from "@/components/confirm";
import { api, Refused } from "@/lib/api";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import { VerdictTag } from "./Audit";
import type { PageProps } from "@/pages";

type Tag = { kind: string; word: string; detail: string };
type Item = { name: string; meta: string; line?: number };
type Raw = {
  file: string;
  failed?: { title: string; body: string };
  path: string;
  version: number | null;
  tag: string;
  lead: string;
  lines: { n: number; text: string; problems: string[] }[];
  problems: string[];
  foot: string;
  edit: boolean;
  store: boolean;
  banner: string | null;
  rules?: Item[];
  providers?: Item[];
  replicas?: { host: string; meta: string; healthy: boolean }[];
  next?: { title: string; body: string; action: { label: string; href: string }; docs: string; act: boolean } | null;
};
type Line = { n: number; text: string; kind: string };
type Version = { id: number; tag: Tag; by: string; at: string; note: string; decided: string };
type Detail = { id: number; tag: Tag; facts: [string, string][]; from: string; diff: Line[]; own: string | null; actions: string[]; text: string };
type Versions = { lead: string; file?: { title: string; body: string }; edit?: boolean; versions?: Version[]; detail?: Detail | null };
type Draft = { lead: string; text: string; note: string; base: number; hours: number; save: string };
type Run = { tag: Tag; summary: string; note: string; tables: { title: string; count: number; rows: Record<string, string>[] }[] };

// The policy's lines, numbered: + added, - removed, the asked-for line marked, and each problem under its line.
function Code({ lines, hit }: { lines: Line[]; hit?: number }) {
  return (
    <div className="t-mono-sm grid overflow-x-auto rounded-box bg-well py-3">
      {lines.map((l, i) => (
        <div
          key={i}
          id={l.kind === "note" ? undefined : `line-${l.n}`}
          data-kind={l.kind || undefined}
          className={cn(
            "flex gap-4 px-6 whitespace-pre",
            (l.n === hit || l.kind === "add") && l.kind !== "note" && "bg-card font-semibold",
            l.kind === "del" && "text-muted-foreground line-through",
            l.kind === "error" && "text-destructive-text",
            l.kind === "note" && "whitespace-pre-wrap text-destructive-text",
          )}
        >
          <span aria-hidden="true" className="w-8 flex-none text-right text-muted-foreground">
            {l.kind === "add" ? "+" : l.kind === "del" ? "-" : l.kind === "note" ? "" : l.n}
          </span>
          <span>{l.text}</span>
        </div>
      ))}
    </div>
  );
}

function List({ items }: { items: { key: string; title: string; meta: string; side?: React.ReactNode }[] }) {
  return (
    <div className="grid gap-4">
      {items.map((i) => (
        <div key={i.key} className="flex flex-wrap items-start justify-between gap-2">
          <div className="grid min-w-0 gap-1">
            <span className="t-body-strong">{i.title}</span>
            <span className="t-small text-muted-foreground">{i.meta}</span>
          </div>
          {i.side}
        </div>
      ))}
    </div>
  );
}

export function RawPolicy({ query }: PageProps) {
  // Live: the page reads the policy again every 5 seconds, so a new version or a fixed file shows without a reload.
  const { data, error, reload } = useData<Raw>("policy/raw", 5000);
  const hit = Number(query.get("line") ?? "") || undefined;
  const loaded = !!data?.lines;
  useEffect(() => {
    if (loaded && hit) document.getElementById(`line-${hit}`)?.scrollIntoView({ block: "center" });
  }, [loaded, hit]);
  const lines: Line[] = (data?.lines ?? []).flatMap((l) => [
    { n: l.n, text: l.text, kind: l.problems.length ? "error" : "" },
    ...l.problems.map((p) => ({ n: l.n, text: `Line ${l.n}: ${p}`, kind: "note" })),
  ]);
  return (
    <>
      <Head
        title="Policy file"
        lead={data?.lead ?? data?.failed?.body ?? "One file decides every request."}
        actions={
          <>
            {data?.edit ? (
              <Button asChild>
                <a href="#/policy/edit">Edit</a>
              </Button>
            ) : null}
            {data?.store ? (
              <Button variant="outline" asChild>
                <a href="/console/policy/export">Export YAML</a>
              </Button>
            ) : null}
          </>
        }
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={8} /> : null}
      {data?.failed ? (
        <Panel title={data.failed.title}>
          <p className="t-body m-0 text-muted-foreground">{data.failed.body}</p>
        </Panel>
      ) : null}
      {data?.problems?.length ? <Problem text={data.problems.join(" ")} /> : null}
      {data?.banner ? (
        <div role="status" className="t-body rounded-panel border border-input p-4">
          {data.banner}
        </div>
      ) : null}
      {data?.next ? (
        <Panel title={data.next.title}>
          <p className="t-body m-0 text-muted-foreground">{data.next.body}</p>
          <div className="flex flex-wrap gap-2">
            {data.next.act ? (
              <Button asChild>
                <a href={data.next.action.href}>{data.next.action.label}</a>
              </Button>
            ) : null}
            <Button variant="outline" asChild>
              <a href={data.next.docs}>Read the docs page</a>
            </Button>
          </div>
        </Panel>
      ) : null}
      {data?.lines ? (
        <div className="grid items-start gap-8 lg:grid-cols-[2fr_1fr]">
          <Panel title={data.file} note={data.foot} actions={<VerdictTag tag={{ kind: data.version ? "allow" : "", word: data.tag, detail: "" }} />}>
            <Code lines={lines} hit={hit} />
          </Panel>
          {data.rules ? (
            <aside aria-label="About this file" className="grid gap-8">
              <Panel title="Rules">
                <List
                  items={data.rules.map((r) => ({
                    key: r.name,
                    title: r.name,
                    meta: r.meta,
                    side: (
                      <Button variant="outline" size="sm" asChild>
                        <a href={`#/policy/raw?line=${r.line}`}>Line {r.line}</a>
                      </Button>
                    ),
                  }))}
                />
              </Panel>
              <Panel title="Providers" note="A provider key stays in its environment variable and is never shown here.">
                <List items={(data.providers ?? []).map((p) => ({ key: p.name, title: p.name, meta: p.meta }))} />
              </Panel>
              {data.replicas?.length ? (
                <Panel title="Gateways" note="A gateway is silent when it wrote no heartbeat to the store in 10 seconds.">
                  <List
                    items={data.replicas.map((r, i) => ({
                      key: `${r.host} ${i}`,
                      title: r.host,
                      meta: r.meta,
                      side: <VerdictTag tag={r.healthy ? { kind: "", word: "Healthy", detail: "" } : { kind: "warn", word: "Silent", detail: "" }} />,
                    }))}
                  />
                </Panel>
              ) : null}
            </aside>
          ) : null}
        </div>
      ) : null}
    </>
  );
}

// ---------------------------------------------------------------- versions

function Report({ run }: { run: Run }) {
  return (
    <Panel title="Dry run" actions={<VerdictTag tag={run.tag} />} note={run.note}>
      <p className="t-body m-0">{run.summary}</p>
      {run.tables.map((t) =>
        t.count === 0 ? (
          <p key={t.title} className="t-small m-0 text-muted-foreground">
            {t.title}: none.
          </p>
        ) : (
          <div key={t.title} className="grid gap-2">
            <h3 className="t-tag m-0 uppercase">
              {t.title}: {t.count}
            </h3>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Who</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Decision</TableHead>
                  <TableHead>Rule</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {t.rows.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell>{r.time}</TableCell>
                    <TableCell>
                      {r.person}
                      <span className="block text-muted-foreground">{r.team}</span>
                    </TableCell>
                    <TableCell>{r.model}</TableCell>
                    <TableCell>{r.decision}</TableCell>
                    <TableCell className="whitespace-normal">{r.rule}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ),
      )}
    </Panel>
  );
}

/// A button that waits for what it started: disabled until the gateway answers, so it is never sent twice.
function Busy({ run, children, ...props }: Omit<React.ComponentProps<typeof Button>, "onClick"> & { run: () => Promise<unknown> }) {
  const [busy, setBusy] = useState(false);
  return (
    <Button
      {...props}
      disabled={busy || props.disabled}
      aria-busy={busy || undefined}
      onClick={async () => {
        setBusy(true);
        try {
          await run();
        } finally {
          setBusy(false);
        }
      }}
    >
      {children}
    </Button>
  );
}

/// A dry run of `text` over the last `hours`: the report, or the refusal as a toast.
async function dryRun(text: string, hours: number | string): Promise<Run | null> {
  try {
    const done = (await api.post("policy/dry-run", { text, hours })) as unknown as { message: string; run: Run };
    toast(done.message);
    return done.run;
  } catch (e) {
    if (e instanceof Refused) {
      toast.error(e.message, { duration: 10000 });
      return null;
    }
    throw e;
  }
}

export function PolicyVersions({ query }: PageProps) {
  const version = query.get("version") ?? "";
  const { data, error, change, reload } = useData<Versions>(`policy/versions${version ? `?version=${encodeURIComponent(version)}` : ""}`, 5000);
  const [run, setRun] = useState<Run | null>(null);
  useEffect(() => setRun(null), [version]);
  const detail = data?.detail;
  const act = (action: string) => detail && change(() => api.post(`policy/versions/${detail.id}/${action}`, {}));
  const labels: Record<string, [string, "default" | "outline" | "destructive"]> = {
    approve: ["Approve and put live", "default"],
    reject: ["Reject", "outline"],
    rollback: ["Roll back to this version", "outline"],
  };
  return (
    <>
      <Head
        title="Versions"
        lead={data?.lead ?? ""}
        actions={
          data?.versions ? (
            <>
              {data.edit ? (
                <Button asChild>
                  <a href="#/policy/edit">Edit the policy</a>
                </Button>
              ) : null}
              <Button variant="outline" asChild>
                <a href="/console/policy/export">Export YAML</a>
              </Button>
            </>
          ) : null
        }
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={5} /> : null}
      {data?.file ? (
        <Panel title={data.file.title}>
          <p className="t-body m-0 text-muted-foreground">{data.file.body}</p>
          <div>
            <Button asChild>
              <a href="#/policy/raw">Open the policy</a>
            </Button>
          </div>
        </Panel>
      ) : null}
      {detail ? (
        <Panel title={`Version ${detail.id}`} actions={<VerdictTag tag={detail.tag} />}>
          <dl className="m-0 grid gap-x-6 gap-y-2 sm:grid-cols-[auto_1fr]">
            {detail.facts.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="t-small text-muted-foreground">{k}</dt>
                <dd className="t-body m-0">{v}</dd>
              </div>
            ))}
          </dl>
          <h3 className="t-tag m-0 uppercase">Changes from {detail.from}</h3>
          {detail.diff.length ? <Code lines={detail.diff} /> : <p className="t-small m-0 text-muted-foreground">The same text as the version it was drafted on.</p>}
          {detail.own ? <p className="t-small m-0 text-muted-foreground">{detail.own}</p> : null}
          {detail.actions.length ? (
            <div className="flex flex-wrap gap-2">
              {detail.actions.map((a) =>
                a === "dry_run" ? (
                  <Busy key={a} variant="outline" run={async () => setRun(await dryRun(detail.text, 24))}>
                    Dry run, last 24 hours
                  </Busy>
                ) : a === "rollback" || a === "reject" ? (
                  <Confirm
                    key={a}
                    label={labels[a][0]}
                    title={a === "rollback" ? `Roll back to version ${detail.id}?` : `Reject version ${detail.id}?`}
                    detail={
                      a === "rollback"
                        ? `Every gateway serves version ${detail.id} within 2 seconds. The versions after it stay in the history.`
                        : "It never goes live. Its text stays in the history, and the decision is recorded with your name."
                    }
                    onConfirm={() => act(a)}
                  />
                ) : (
                  <Busy key={a} variant={labels[a]?.[1] ?? "outline"} run={async () => act(a)}>
                    {labels[a]?.[0] ?? a}
                  </Busy>
                ),
              )}
            </div>
          ) : null}
        </Panel>
      ) : null}
      {run ? <Report run={run} /> : null}
      {data?.versions ? (
        <Panel title="Versions">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Version</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Saved</TableHead>
                <TableHead>Note</TableHead>
                <TableHead>Approved or rejected</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.versions.map((v) => (
                <TableRow key={v.id} aria-selected={detail?.id === v.id || undefined} className={cn(detail?.id === v.id && "[&>td]:bg-well")}>
                  <TableCell className="whitespace-nowrap">
                    <a href={`#/policy/versions?version=${v.id}`}>Version {v.id}</a>
                  </TableCell>
                  <TableCell>
                    <VerdictTag tag={v.tag} />
                  </TableCell>
                  <TableCell>
                    {v.by}
                    <span className="block whitespace-nowrap text-muted-foreground">{v.at}</span>
                  </TableCell>
                  <TableCell className="whitespace-normal">{v.note}</TableCell>
                  <TableCell className="whitespace-normal">{v.decided}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      ) : null}
    </>
  );
}

// ---------------------------------------------------------------- the editor

export function PolicyEditor({ query }: PageProps) {
  const add = query.get("add") ?? "";
  const hoursAsked = query.get("hours") ?? "";
  const params = new URLSearchParams(Object.entries({ add, hours: hoursAsked }).filter(([, v]) => v));
  // No polling: the draft is the person's until they save it. A version saved since is refused, not overwritten.
  const { data, error, reload } = useData<Draft>(`policy/editor${params.size ? `?${params}` : ""}`);
  return (
    <>
      <Head title="Edit the policy" lead={data?.lead ?? ""} />
      {error ? (
        <>
          <Problem text={error} retry={reload} />
          <div>
            <Button variant="outline" asChild>
              <a href="#/policy/raw">Open the policy</a>
            </Button>
          </div>
        </>
      ) : null}
      {!data && !error ? <Loading rows={8} /> : null}
      {data ? <EditorForm key={`${data.base} ${add}`} draft={data} /> : null}
    </>
  );
}

function EditorForm({ draft }: { draft: Draft }) {
  const [text, setText] = useState(draft.text);
  const [note, setNote] = useState(draft.note);
  const [hours, setHours] = useState(String(draft.hours));
  const [refused, setRefused] = useState("");
  const [run, setRun] = useState<Run | null>(null);
  const load = (file: File | undefined) => {
    if (!file) return;
    file.text().then(setText, () => toast.error("The file could not be read. Pick a YAML file and try again."));
  };
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const done = (await api.post("policy/save", { text, base: draft.base, note })) as { message: string; version?: number };
      toast(done.message);
      window.location.hash = `#/policy/versions?version=${done.version ?? ""}`;
    } catch (err) {
      if (err instanceof Refused) {
        toast.error(err.message, { duration: 10000 });
        setRefused(err.message);
      } else throw err;
    }
  };
  return (
    <>
      {run ? <Report run={run} /> : null}
      <Form className="grid gap-6 rounded-panel bg-card p-6" onSubmit={save}>
        <Field id="policy-file" label="Import a YAML file, optional" hint="Its text replaces the editor's. Nothing is saved until you save.">
          <Input id="policy-file" type="file" accept=".yaml,.yml,text/yaml" className="py-2" onChange={(e) => load(e.target.files?.[0])} />
        </Field>
        <Field id="policy-text" label="Policy">
          <textarea
            id="policy-text"
            className="t-mono min-h-24 w-full rounded-box border border-input bg-background px-6 py-3 text-foreground hover:border-foreground"
            rows={28}
            spellCheck={false}
            autoComplete="off"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </Field>
        <Field id="policy-note" label="What changed, for the history">
          <Input id="policy-note" value={note} maxLength={500} autoComplete="off" onChange={(e) => setNote(e.target.value)} />
        </Field>
        <Field id="dry-hours" label="Dry run over the last hours">
          <Input id="dry-hours" type="number" min={1} max={720} className="t-mono max-w-col-md" value={hours} onChange={(e) => setHours(e.target.value)} />
        </Field>
        <Refusal text={refused} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button type="button" variant="outline" asChild>
            <a href="#/policy/raw">Cancel</a>
          </Button>
          <Busy type="button" variant="outline" run={async () => setRun(await dryRun(text, hours))}>
            Dry run
          </Busy>
          <Button type="submit">{draft.save}</Button>
        </div>
      </Form>
    </>
  );
}
