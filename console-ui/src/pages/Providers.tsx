import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Panel, Problem, Refusal } from "@/components/page";
import { Remove } from "@/components/confirm";
import { api, part, type Me } from "@/lib/api";
import { useData, words } from "@/lib/use";

type Provider = { name: string; kind: string; url: string | null; key: string; models: string[]; retries: number | null; fallback: string | null };
type Preset = { id: string; name: string; local: boolean; needs_url: boolean; models: string[] };
type Data = { providers: Provider[]; catalog: Preset[]; sealing: boolean };

export function Providers({ me }: { me: Me | null }) {
  const { data, error, change } = useData<Data>("providers");
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Provider | null>(null);
  const may = !!me?.edit_policy;
  return (
    <>
      <Head
        title="Models and providers"
        lead="Each provider, the models it serves, and where a failed request goes next."
        actions={
          <Button disabled={!may || !data} onClick={() => setAdding(true)}>
            Add a provider
          </Button>
        }
      />
      {error ? <Problem text={error} /> : null}
      <Panel title="Providers" note="Prices per model are on the Prices page.">
        {data && data.providers.length === 0 ? (
          <Empty title="No providers yet" body="Add one from the catalog: paste its key and pick the models it serves." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Provider</TableHead>
                <TableHead>Models</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>On failure</TableHead>
                <TableHead>Change</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.providers.map((p) => (
                <TableRow key={p.name}>
                  <TableCell>
                    {p.name}
                    <span className="block text-muted-foreground">{p.kind}</span>
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    <div className="flex flex-wrap gap-1">
                      {p.models.map((m) => (
                        <Badge key={m} className="t-mono-sm normal-case">
                          {m}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>{p.key}</TableCell>
                  <TableCell>
                    {p.retries ? `${p.retries} retries` : "no retry"}
                    <span className="block text-muted-foreground">{p.fallback ? `then ${p.fallback}` : "no fallback"}</span>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" disabled={!may} onClick={() => setEditing(p)}>
                        Edit
                      </Button>
                      <Remove
                        what={p.name}
                        disabled={!may}
                        detail={`Requests stop going to ${p.name}. A sealed key stays under Credentials until you remove it there.`}
                        onConfirm={() => change(() => api.del(`providers/${part(p.name)}`))}
                      />
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>
      {data && adding ? <AddProvider data={data} me={me} onClose={() => setAdding(false)} change={change} /> : null}
      {data && editing ? <EditProvider provider={editing} others={data.providers} onClose={() => setEditing(null)} change={change} /> : null}
    </>
  );
}

type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

function AddProvider({ data, me, onClose, change }: { data: Data; me: Me | null; onClose: () => void; change: Change }) {
  const [preset, setPreset] = useState("openai");
  const chosen = data.catalog.find((p) => p.id === preset);
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [keyEnv, setKeyEnv] = useState("");
  const [url, setUrl] = useState("");
  const [models, setModels] = useState(chosen?.models.join(", ") ?? "");
  const seal = data.sealing && !!me?.credentials;
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.post("providers", { preset, name, key, key_env: keyEnv, url, models: words(models) }));
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>Add a provider</DialogTitle>
        <DialogDescription>Pick it from the catalog. Every gateway sends requests to it within 2 seconds.</DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          <Field id="preset" label="Provider">
            <Select
              value={preset}
              onValueChange={(v) => {
                setPreset(v);
                setModels(data.catalog.find((p) => p.id === v)?.models.join(", ") ?? "");
              }}
            >
              <SelectTrigger id="preset">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {data.catalog.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field id="name" label="Name, optional" hint={`Callers never see it. Leave empty for ${preset}.`}>
            <Input id="name" className="t-mono" value={name} onChange={(e) => setName(e.target.value)} placeholder={preset} autoComplete="off" />
          </Field>
          {chosen?.needs_url ? (
            <Field id="url" label="URL" hint="Your account's own address for this provider.">
              <Input id="url" className="t-mono" value={url} onChange={(e) => setUrl(e.target.value)} required />
            </Field>
          ) : null}
          {seal ? (
            <Field id="key" label="Provider key" hint="Stored encrypted under the master key. It is in no record and no page.">
              <Input id="key" type="password" className="t-mono" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" />
            </Field>
          ) : null}
          <Field
            id="key-env"
            label={seal ? "Or the environment variable that holds it" : "Environment variable that holds the key"}
            hint={seal ? undefined : "This gateway has no master key to seal a pasted key, or your role may not add one."}
          >
            <Input id="key-env" className="t-mono" value={keyEnv} onChange={(e) => setKeyEnv(e.target.value)} placeholder="OPENAI_API_KEY" autoComplete="off" />
          </Field>
          <Field id="models" label="Models" hint="The names callers send, separated by commas.">
            <Input id="models" className="t-mono" value={models} onChange={(e) => setModels(e.target.value)} required />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">Add provider</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditProvider({ provider, others, onClose, change }: { provider: Provider; others: Provider[]; onClose: () => void; change: Change }) {
  const [models, setModels] = useState(provider.models.join(", "));
  const [retries, setRetries] = useState(provider.retries?.toString() ?? "");
  const [fallback, setFallback] = useState(provider.fallback ?? "none");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() =>
      api.put(`providers/${part(provider.name)}`, { models: words(models), retries, fallback: fallback === "none" ? "" : fallback }),
    );
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>Edit {provider.name}</DialogTitle>
        <DialogDescription>The models it serves, and where a request goes when it keeps failing.</DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          <Field id="models" label="Models" hint="Separated by commas. * serves every model the provider has.">
            <Input id="models" className="t-mono" value={models} onChange={(e) => setModels(e.target.value)} required />
          </Field>
          <Field id="retries" label="Retries" hint="Tries again after a 429 or a 5xx, 0 to 10 times.">
            <Input id="retries" type="number" min={0} max={10} className="t-mono" value={retries} onChange={(e) => setRetries(e.target.value)} />
          </Field>
          <Field id="fallback" label="Fallback provider" hint="Takes the request when every retry failed. It must speak the same API.">
            <Select value={fallback} onValueChange={setFallback}>
              <SelectTrigger id="fallback">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                {others
                  .filter((o) => o.name !== provider.name)
                  .map((o) => (
                    <SelectItem key={o.name} value={o.name}>
                      {o.name}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">Save</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
