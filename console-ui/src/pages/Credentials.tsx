import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Problem, Refusal, Form, Loading } from "@/components/page";
import { api } from "@/lib/api";
import { useData } from "@/lib/use";
import type { PageProps } from "@/pages";

type Credential = { name: string; provider: string; fingerprint: string; used_by: string; added: string; rotated: string };
type Data = {
  lead: string;
  read_only: boolean;
  may_change: boolean;
  off?: { title: string; body: string };
  credentials?: Credential[];
  empty?: { title: string; body: string };
};
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

const DONE: Record<string, string> = {
  added: "is added. A provider can name it with credential: now.",
  rotated: "is rotated. Every gateway sends the new value within 2 seconds.",
  removed: "is removed.",
};

/// Moves the # route's query to `next`, so a dialog is a link that can be shared and reopened.
function setQuery(next: Record<string, string>) {
  const query = new URLSearchParams(Object.entries(next).filter(([, v]) => v));
  window.location.hash = `#/credentials${query.size ? `?${query}` : ""}`;
}

export function Credentials({ query }: PageProps) {
  const dialog = query.get("add") || query.get("rotate") || query.get("remove");
  // Live: a rotation made on another gateway or through the admin API shows within 5 seconds, unless a dialog is open.
  const { data, error, change, reload } = useData<Data>("credentials", 5000, !!dialog);

  // A change made on the server-rendered page, or a link that names one, says so once.
  useEffect(() => {
    const done = query.get("done");
    const name = query.get("name");
    if (done && name) {
      toast(`Credential ${name} ${DONE[done] ?? DONE.removed}`);
      setQuery({});
    }
  }, [query]);

  const may = !!data?.may_change;
  const list = data?.credentials;
  const add = may ? <Button onClick={() => setQuery({ add: "1" })}>Add a provider key</Button> : null;
  return (
    <>
      <Head title="Provider keys" lead={data?.lead ?? "Provider keys, stored encrypted. Never shown after saving."} actions={list ? add : null} />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={3} /> : null}
      {data?.off ? <Empty title={data.off.title} body={data.off.body} /> : null}
      {list && list.length === 0 && data?.empty ? (
        <section className="grid justify-items-start gap-4 rounded-panel bg-card p-6">
          <Empty title={data.empty.title} body={data.empty.body} />
          {add}
        </section>
      ) : null}
      {list && list.length > 0 ? (
        <section className="grid gap-4 rounded-panel bg-card p-6">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>Used by</TableHead>
                <TableHead>Added</TableHead>
                <TableHead>Rotated</TableHead>
                <TableHead aria-label="Change" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((c) => (
                <TableRow key={c.name}>
                  <TableCell>
                    {c.name}
                    <span className="block text-muted-foreground">{c.provider}</span>
                  </TableCell>
                  <TableCell className="t-mono-sm">{c.fingerprint}</TableCell>
                  <TableCell className="whitespace-normal">{c.used_by}</TableCell>
                  <TableCell className="whitespace-normal">{c.added}</TableCell>
                  <TableCell className="whitespace-normal">{c.rotated}</TableCell>
                  <TableCell>
                    {may ? (
                      <div className="flex flex-wrap gap-2">
                        <Button variant="outline" size="sm" onClick={() => setQuery({ rotate: c.name })}>
                          Rotate
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => setQuery({ remove: c.name })}>
                          Remove
                        </Button>
                      </div>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      ) : null}
      {may && query.get("add") ? <AddDialog change={change} /> : null}
      {may && query.get("rotate") ? <RotateDialog name={query.get("rotate") ?? ""} change={change} /> : null}
      {may && query.get("remove") ? <RemoveDialog name={query.get("remove") ?? ""} change={change} /> : null}
    </>
  );
}

// The provider key: a password field, so it is not shown on screen, and never filled back in after a refusal.
function Secret({ id, value, setValue }: { id: string; value: string; setValue: (v: string) => void }) {
  return (
    <Field id={id} label="Provider key" hint="Sealed in the store with the master key. It is never shown again, here or anywhere.">
      <Input id={id} type="password" className="t-mono" value={value} onChange={(e) => setValue(e.target.value)} required autoComplete="off" spellCheck={false} />
    </Field>
  );
}

function AddDialog({ change }: { change: Change }) {
  const [name, setName] = useState("");
  const [provider, setProvider] = useState("");
  const [value, setValue] = useState("");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.post("credentials/add", { name, provider, value }));
    if (answer) {
      setRefused(answer);
      setValue("");
    } else setQuery({});
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent>
        <DialogTitle>Add a provider credential</DialogTitle>
        <DialogDescription>
          The key Enterplace sends to a provider, kept in the store sealed with AES-256-GCM under the master key. After it is saved only its name and last 4 characters are shown.
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field id="credential-name" label="Name" hint="A provider in the policy names it with credential: and this name.">
            <Input id="credential-name" className="t-mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="openai-prod" required autoFocus autoComplete="off" />
          </Field>
          <Field id="credential-provider" label="Provider" hint="The vendor the key is for, so the list says which is which.">
            <Input id="credential-provider" className="t-mono" value={provider} onChange={(e) => setProvider(e.target.value)} placeholder="openai" required autoComplete="off" />
          </Field>
          <Secret id="credential-value" value={value} setValue={setValue} />
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit">Add credential</Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function RotateDialog({ name, change }: { name: string; change: Change }) {
  const [value, setValue] = useState("");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.post("credentials/rotate", { name, value }));
    if (answer) {
      setRefused(answer);
      setValue("");
    } else setQuery({});
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent>
        <DialogTitle>Rotate this credential?</DialogTitle>
        <DialogDescription>
          Every gateway on this store sends the new value of <span className="t-mono">{name}</span> within 2 seconds, with no restart. Requests already sent finish with the old one.
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Secret id="rotate-value" value={value} setValue={setValue} />
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit">Rotate</Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function RemoveDialog({ name, change }: { name: string; change: Change }) {
  const [typed, setTyped] = useState("");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.post("credentials/remove", { name, confirm: typed }));
    if (answer) setRefused(answer);
    else setQuery({});
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent>
        <DialogTitle>Remove this credential?</DialogTitle>
        <DialogDescription>
          The sealed value of <span className="t-mono">{name}</span> is deleted from the store. This cannot be undone. Type <span className="t-mono">{name}</span> to confirm.
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field id="remove-type" label="Name, to confirm">
            <Input id="remove-type" className="t-mono" value={typed} onChange={(e) => setTyped(e.target.value)} required autoFocus autoComplete="off" aria-invalid={!!refused} />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={typed !== name}>
              Remove credential
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
