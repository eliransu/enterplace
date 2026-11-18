import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Panel, Problem, Refusal } from "@/components/page";
import { Copy } from "@/components/copy";
import { api, Refused } from "@/lib/api";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import type { PageProps } from "@/pages";

type Fix =
  | { kind: "restore"; scope: string; value: string }
  | { kind: "command"; text: string }
  | { kind: "reissue"; name: string; team: string }
  | { kind: "refusals"; href: string }
  | null;
type Status = { tag: string; kind: string; notes: string[]; meter: { text: string; percent: number; over: boolean } | null; fix: Fix };
type Fields = { expires: string; budget: string; per: string; models: string; tpm: string; replaced_by: string | null };
type Entry = {
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
};
type Data = {
  keys_file: string;
  keys_path: string;
  read_only: boolean;
  may: { issue: boolean; revoke: boolean; restore: boolean; full_admin: boolean };
  start_command: string;
  docs: string;
  empty: { title: string; body: string; action: { label: string; href: string }; docs: string } | null;
  error?: string;
  lead?: string;
  entries?: Entry[];
};
type Made = { key: string; name: string; team: string; rotated?: boolean; lines?: string[]; until?: string; message?: string; keys_path?: string };

const PER_PAGE = 50;
const count = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/// Moves the # route's query to `next`, so a dialog or a search is a link that can be shared and reopened.
function setQuery(next: Record<string, string>) {
  const query = new URLSearchParams(Object.entries(next).filter(([, v]) => v));
  window.location.hash = `#/people${query.size ? `?${query}` : ""}`;
}

export function People({ query }: PageProps) {
  const dialog = query.get("issue") || query.get("revoke") || query.get("edit");
  const [made, setMade] = useState<Made | null>(null);
  // Live: the page reads the keys and the log again every 5 seconds, unless a dialog is open.
  const { data, error, change } = useData<Data>("people", 5000, !!dialog || !!made);
  const [q, setQ] = useState(query.get("q") ?? "");
  const [page, setPage] = useState(Number(query.get("page")) || 1);

  // A revoke done on the server-rendered page, or a link that names one, says so once.
  useEffect(() => {
    const revoked = query.get("revoked");
    if (revoked) {
      const hash = query.get("hash");
      toast(`The key of ${revoked}${hash ? `, key hash ${hash}` : ""} is revoked. Requests with it are refused within 2 seconds.`);
      setQuery({});
    }
  }, [query]);

  const entries = data?.entries ?? [];
  const shown = useMemo(() => entries.filter((e) => !q.trim() || e.name.includes(q.trim()) || e.team.includes(q.trim())), [entries, q]);
  const pages = Math.max(1, Math.ceil(shown.length / PER_PAGE));
  const at = Math.min(page, pages);
  const lead = data?.lead ?? `The keys in ${data?.keys_file ?? "the keys file"}.`;
  const may = data?.may;
  const editing = entries.find((e) => e.sha256 === query.get("edit"));
  const revoking = entries.find((e) => e.sha256 === query.get("revoke"));
  const onlyAdmins = entries.length > 0 && entries.every((e) => e.admin);

  return (
    <>
      <Head
        title="People and workloads"
        lead={lead}
        actions={
          may?.issue ? (
            <Button onClick={() => setQuery({ issue: "1" })}>Issue a key</Button>
          ) : null
        }
      />
      {data?.read_only ? (
        <div role="status" className="t-body rounded-panel border border-input p-4">
          You are signed in read only: you can see the keys, not issue or revoke them. Ask an admin, or ask to be added to an admin group at the identity provider.
        </div>
      ) : null}
      {error ? <Problem text={error} /> : null}
      {data?.error ? <Problem text={data.error} /> : null}
      {data?.entries ? (
        <>
          <Input
            type="search"
            aria-label="Search people and workloads"
            placeholder="Name or team"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(1);
            }}
            className="max-w-col-md"
          />
          {entries.length === 0 || onlyAdmins ? <Start data={data} /> : null}
          {entries.length === 0 ? null : shown.length === 0 ? (
            <Panel title={`Nothing matches "${q.trim()}"`}>
              <p className="t-body m-0 text-muted-foreground">No name or team in the keys file has that text.</p>
              <Button variant="outline" onClick={() => setQ("")} className="justify-self-start">
                Show everyone
              </Button>
            </Panel>
          ) : (
            <section className="grid gap-4 rounded-panel bg-card p-6">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Key hash</TableHead>
                    <TableHead className="text-right">Requests</TableHead>
                    <TableHead>Last request</TableHead>
                    <TableHead aria-label="Actions" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {shown.slice((at - 1) * PER_PAGE, at * PER_PAGE).map((e) => (
                    <TableRow key={e.sha256}>
                      <TableCell>
                        {e.name}
                        <span className="block text-muted-foreground">
                          {e.team}, {e.kind}
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <StatusCell status={e.status} />
                      </TableCell>
                      <TableCell>{e.hash}</TableCell>
                      <TableCell className="text-right tabular-nums">{e.requests.toLocaleString("en-US")}</TableCell>
                      <TableCell>{e.last}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <FixAction fix={e.status.fix} />
                          {/* Revoke is in the editor, away from the row: one click on a row never ends a key. */}
                          {e.editable && !data.read_only ? (
                            <Button variant="outline" size="sm" onClick={() => setQuery({ edit: e.sha256 })}>
                              Edit
                            </Button>
                          ) : null}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {shown.length > PER_PAGE ? (
                <div className="flex items-center justify-between gap-4">
                  <span className="t-small text-muted-foreground">
                    Page {at} of {pages}, {count(shown.length, "key")}
                  </span>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" disabled={at <= 1} onClick={() => setPage(at - 1)}>
                      Newer
                    </Button>
                    <Button variant="outline" size="sm" disabled={at >= pages} onClick={() => setPage(at + 1)}>
                      Older
                    </Button>
                  </div>
                </div>
              ) : null}
            </section>
          )}
        </>
      ) : null}
      {data && may?.issue && query.get("issue") ? (
        <IssueDialog name={query.get("name") ?? ""} team={query.get("team") ?? ""} fullAdmin={may.full_admin} onMade={setMade} change={change} />
      ) : null}
      {data && editing ? <EditDialog entry={editing} mayRevoke={!!may?.revoke} onMade={setMade} change={change} /> : null}
      {data && revoking ? <RevokeDialog entry={revoking} keysPath={data.keys_path} change={change} /> : null}
      {made ? <MadeDialog made={made} onClose={() => setMade(null)} /> : null}
    </>
  );
}

function Start({ data }: { data: Data }) {
  if (data.read_only || !data.empty) {
    return <Empty title="No keys yet" body="Every request through Enterplace carries a key that names a person or a workload. An admin issues them." />;
  }
  return (
    <Panel title={data.empty.title}>
      <p className="t-body m-0 text-muted-foreground">{data.empty.body}</p>
      <div className="flex flex-wrap items-center gap-2 rounded-box bg-well px-6 py-3">
        <span className="t-mono min-w-0 flex-1 break-all">{data.start_command}</span>
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

function StatusCell({ status }: { status: Status }) {
  return (
    <div className="grid gap-2">
      <span>
        <Badge className={cn(status.kind === "refused" && "border-destructive", status.kind === "allow" && "border-transparent pl-0 text-muted-foreground")}>{status.tag}</Badge>
        {status.notes.map((n) => (
          <span key={n} className="block text-muted-foreground">
            {n}
          </span>
        ))}
      </span>
      {status.meter ? (
        <div className="grid min-w-48 gap-1">
          <div className="flex justify-between gap-4">
            <span className="t-small text-muted-foreground">Key budget</span>
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
            <div className={cn("h-1 rounded-pill", status.meter.over ? "bg-destructive" : "bg-foreground")} style={{ width: `${status.meter.percent}%` }} />
          </div>
        </div>
      ) : null}
    </div>
  );
}

function FixAction({ fix }: { fix: Fix }) {
  if (!fix) return null;
  switch (fix.kind) {
    // A plain form to the console's own restore route, as the server-rendered pages send it.
    case "restore":
      return (
        <form method="post" action="/console/kills/restore">
          <input type="hidden" name="scope" value={fix.scope} />
          <input type="hidden" name="value" value={fix.value} />
          <Button size="sm" type="submit">
            Restore traffic
          </Button>
        </form>
      );
    case "command":
      return <span className="t-mono-sm whitespace-normal">{fix.text}</span>;
    case "reissue":
      return (
        <Button variant="outline" size="sm" onClick={() => setQuery({ issue: "1", name: fix.name, team: fix.team })}>
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

type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

/// Sends a change that answers with a new key: the key comes back once, so it goes to a dialog, not a toast.
async function makeKey(path: string, body: unknown): Promise<Made | string> {
  try {
    return await api.post(path, body) as unknown as Made;
  } catch (e) {
    if (e instanceof Refused) return e.message;
    throw e;
  }
}

function IssueDialog({ name: name0, team: team0, fullAdmin, onMade }: { name: string; team: string; fullAdmin: boolean; onMade: (m: Made) => void; change: Change }) {
  const [name, setName] = useState(name0);
  const [team, setTeam] = useState(team0);
  const [expires, setExpires] = useState("");
  const [budget, setBudget] = useState("");
  const [per, setPer] = useState("month");
  const [admin, setAdmin] = useState(false);
  const [personToken, setPersonToken] = useState(false);
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const made = await makeKey("people/issue", { name, team, expires, budget, per, admin, person_token: personToken });
    if (typeof made === "string") setRefused(made);
    else {
      setQuery({});
      onMade(made);
    }
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent>
        <DialogTitle>Issue a key</DialogTitle>
        <DialogDescription>A key lets a person or a workload send requests through Enterplace under their name. It is shown once: Enterplace keeps only its hash.</DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          <Field id="issue-name" label="Person or workload">
            <Input id="issue-name" className="t-mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="maya.cohen" required autoFocus autoComplete="off" />
          </Field>
          <Field id="issue-team" label="Team">
            <Input id="issue-team" className="t-mono" value={team} onChange={(e) => setTeam(e.target.value)} placeholder="payments" required autoComplete="off" />
          </Field>
          <Field id="issue-expires" label="Expires, optional">
            <Input id="issue-expires" type="date" className="t-mono" value={expires} onChange={(e) => setExpires(e.target.value)} />
          </Field>
          <BudgetField id="issue-budget" budget={budget} per={per} setBudget={setBudget} setPer={setPer} hint="Most the key may spend, on top of its rule's budget." />
          {fullAdmin ? (
            <label className="t-body flex min-h-11 items-center gap-3">
              <Checkbox checked={admin} onCheckedChange={(c) => setAdmin(c === true)} />
              Admin: may sign in to this console and issue and revoke keys
            </label>
          ) : null}
          <label className="t-body flex min-h-11 items-center gap-3">
            <Checkbox checked={personToken} onCheckedChange={(c) => setPersonToken(c === true)} />
            Person token: names the person for Claude subscriptions and reaches no model on its own
          </label>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit">Issue key</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function BudgetField(props: { id: string; budget: string; per: string; setBudget: (v: string) => void; setPer: (v: string) => void; hint: string }) {
  const { id, budget, per, setBudget, setPer, hint } = props;
  // A period the policy reads but this form does not offer (a week, 6h) is kept as its own choice.
  const periods = ["day", "month", ...(per && per !== "day" && per !== "month" ? [per] : [])];
  return (
    <Field id={id} label="Budget, USD, optional" hint={hint}>
      <div className="flex gap-2">
        <Input id={id} type="number" min={0} step="any" inputMode="decimal" className="t-mono min-w-0 flex-1" value={budget} onChange={(e) => setBudget(e.target.value)} placeholder="20" />
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

function EditDialog({ entry, mayRevoke, onMade, change }: { entry: Entry; mayRevoke: boolean; onMade: (m: Made) => void; change: Change }) {
  const f = entry.fields;
  const [expires, setExpires] = useState(f.expires);
  const [budget, setBudget] = useState(f.budget);
  const [per, setPer] = useState(f.per);
  const [models, setModels] = useState(f.models);
  const [tpm, setTpm] = useState(f.tpm);
  const [admin, setAdmin] = useState(entry.admin);
  const [grace, setGrace] = useState("24h");
  const [refused, setRefused] = useState("");
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.post("people/edit", { sha256: entry.sha256, expires, budget, per, models, tpm, admin }));
    if (answer) setRefused(answer);
    else setQuery({});
  };
  const rotate = async (e: React.FormEvent) => {
    e.preventDefault();
    const made = await makeKey("people/rotate", { sha256: entry.sha256, grace });
    if (typeof made === "string") setRefused(made);
    else {
      setQuery({});
      onMade(made);
    }
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent className="max-w-wide">
        <DialogTitle>Edit the key of {entry.name}</DialogTitle>
        <DialogDescription>The key itself does not change and is never shown again: only what it may do. Every gateway uses the new fields within 2 seconds.</DialogDescription>
        <dl className="t-mono m-0 grid grid-cols-[auto_1fr] gap-x-6 gap-y-2">
          <dt className="t-tag uppercase">Name</dt>
          <dd className="m-0">{entry.name}</dd>
          <dt className="t-tag uppercase">Team</dt>
          <dd className="m-0">{entry.team}</dd>
          <dt className="t-tag uppercase">Key hash</dt>
          <dd className="m-0">{entry.hash}</dd>
        </dl>
        <form className="grid gap-6" onSubmit={save}>
          {/* An expiry with a time (a enterplace login key) stays text: a date input cannot show it. */}
          <Field id="key-expires" label="Expires, optional">
            <Input id="key-expires" type={expires.length <= 10 ? "date" : "text"} className="t-mono" value={expires} onChange={(e) => setExpires(e.target.value)} />
          </Field>
          <BudgetField id="key-budget" budget={budget} per={per} setBudget={setBudget} setPer={setPer} hint="Most the key may spend, on top of its rule's budget. Empty for none." />
          <Field id="key-models" label="Models, optional">
            <Input id="key-models" className="t-mono" value={models} onChange={(e) => setModels(e.target.value)} placeholder="gpt-4o-mini, o3" autoComplete="off" />
          </Field>
          <Field id="key-tpm" label="Tokens per minute, optional">
            <Input id="key-tpm" type="number" min={1} step={1} inputMode="numeric" className="t-mono" value={tpm} onChange={(e) => setTpm(e.target.value)} />
          </Field>
          <label className="t-body flex min-h-11 items-center gap-3">
            <Checkbox checked={admin} onCheckedChange={(c) => setAdmin(c === true)} />
            Admin: may sign in to this console and use the admin API
          </label>
          <Refusal text={refused} />
          <DialogFooter>
            {mayRevoke ? (
              <Button type="button" variant="outline" onClick={() => setQuery({ revoke: entry.sha256 })}>
                Revoke key
              </Button>
            ) : null}
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit">Save</Button>
          </DialogFooter>
        </form>
        {/* Rotation is its own form: it makes a new key, where the form above changes what this one may do. */}
        {f.replaced_by ? (
          <p className="t-body m-0 rounded-panel bg-card p-6">
            This key was rotated and replaced by key {f.replaced_by}. It stops working at {f.expires}. Rotate the new key instead, or revoke this one.
          </p>
        ) : (
          <form className="grid gap-4 rounded-panel bg-card p-6" onSubmit={rotate}>
            <h3 className="t-sm m-0">Rotate key</h3>
            <p className="t-small m-0 text-muted-foreground">Makes a new key with the same settings and shows it once.</p>
            <Field id="key-grace" label="Old key works for">
              <Input id="key-grace" className="t-mono" value={grace} onChange={(e) => setGrace(e.target.value)} autoComplete="off" />
            </Field>
            <Button type="submit" className="justify-self-end">
              Rotate the key
            </Button>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function RevokeDialog({ entry, keysPath, change }: { entry: Entry; keysPath: string; change: Change }) {
  const [typed, setTyped] = useState("");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.post("people/revoke", { sha256: entry.sha256, confirm: typed }));
    if (answer) setRefused(answer);
    else setQuery({});
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent>
        <DialogTitle>Revoke this key?</DialogTitle>
        <DialogDescription>
          The key of {entry.name} stops working. Its entry, key hash {entry.hash}, is removed from {keysPath}. A running gateway refuses the key within 2 seconds, and console sessions signed in with it end now. This cannot be undone: {entry.name} would need a new key. Type{" "}
          <span className="t-mono">{entry.name}</span> to confirm.
        </DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          <Field id="revoke-type" label="Name, to confirm">
            <Input id="revoke-type" className="t-mono" value={typed} onChange={(e) => setTyped(e.target.value)} required autoFocus autoComplete="off" aria-invalid={!!refused} />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={typed !== entry.name}>
              Revoke key
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function MadeDialog({ made, onClose }: { made: Made; onClose: () => void }) {
  const lines = (made.lines ?? []).join("\n");
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>The new key</DialogTitle>
        <DialogDescription>
          {made.until
            ? `For ${made.name}, team ${made.team}, with the settings of the key it replaces. It is shown once and is not stored anywhere: copy it now. ${made.message ?? ""}`
            : `For ${made.name}, team ${made.team}. It is shown once and is not stored anywhere: copy it now. Its hash was added to ${made.keys_path ?? "the keys file"}, and a running gateway accepts it within 2 seconds.${made.rotated ? ` ${made.name} already had a key. Both work until the old entry is revoked.` : ""}`}
        </DialogDescription>
        <div className="flex flex-wrap items-center gap-3 rounded-box bg-well px-6 py-3">
          <span id="new-key" className="t-mono min-w-0 flex-1 break-all">
            {made.key}
          </span>
          <Copy text={made.key} />
        </div>
        {lines ? (
          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-4">
              <span className="t-small text-muted-foreground">The lines for each tool, with this key and this gateway's address:</span>
              <Copy text={lines} />
            </div>
            <pre className="t-mono-sm m-0 overflow-x-auto rounded-box bg-well px-6 py-3">{lines}</pre>
          </div>
        ) : null}
        <DialogFooter>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
