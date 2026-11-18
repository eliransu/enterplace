import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Head, Panel, Problem, Refusal } from "@/components/page";
import { api } from "@/lib/api";
import { useData } from "@/lib/use";
import type { PageProps } from "@/pages";

type Model = { model: string; provider: string; price: string; source: string; aliases: string; input: string; output: string };
type Data = {
  error?: string;
  lead: string;
  editable: boolean;
  base: number | null;
  file: string | null;
  docs: string;
  providers: string[];
  models: Model[];
  note: string;
  empty: { title: string; body: string };
};
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

/// Moves the # route's query to `next`, so a dialog is a link the old page's address can open.
function setQuery(next: Record<string, string>) {
  const query = new URLSearchParams(Object.entries(next).filter(([, v]) => v));
  window.location.hash = `#/prices${query.size ? `?${query}` : ""}`;
}

export function Prices({ query }: PageProps) {
  const adding = query.get("add") === "1";
  const pricing = query.get("price") ?? "";
  // Live: the page reads the policy again every 5 seconds, unless a dialog is open.
  const { data, error, change } = useData<Data>("prices", 5000, adding || !!pricing);
  const editable = !!data?.editable;
  const priced = data?.models?.find((m) => m.model === pricing);
  return (
    <>
      <Head
        title="Prices"
        lead={data?.lead ?? "Each model, its provider and its price."}
        actions={
          <>
            <Button variant="outline" asChild>
              <a href="#/providers">Providers and models</a>
            </Button>
            {editable ? <Button onClick={() => setQuery({ add: "1" })}>Add a model</Button> : null}
          </>
        }
      />
      {data?.file ? (
        <p className="t-small m-0 text-muted-foreground">
          Read only: prices come from <span className="t-mono">{data.file}</span>. <a href={data.docs}>How to edit here</a>
        </p>
      ) : null}
      {error ? <Problem text={error} /> : null}
      {data?.error ? <Problem text={data.error} /> : null}
      {data?.models ? (
        data.models.length === 0 ? (
          <Panel title={data.empty.title}>
            <p className="t-body m-0 text-muted-foreground">{data.empty.body}</p>
          </Panel>
        ) : (
          <Panel title="Models" note={data.note}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Model</TableHead>
                  <TableHead className="text-right">USD per 1M tokens, in / out</TableHead>
                  <TableHead>Aliases</TableHead>
                  {editable ? <TableHead>Change</TableHead> : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.models.map((m) => (
                  <TableRow key={`${m.provider} ${m.model}`}>
                    <TableCell>
                      {m.model}
                      <span className="block text-muted-foreground">{m.provider}</span>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {m.price}
                      <span className="block text-muted-foreground">{m.source}</span>
                    </TableCell>
                    <TableCell className="whitespace-normal">{m.aliases}</TableCell>
                    {editable ? (
                      <TableCell>
                        <Button variant="outline" size="sm" onClick={() => setQuery({ price: m.model })}>
                          Price
                        </Button>
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>
        )
      ) : null}
      {data && editable && adding ? (
        <AddDialog providers={data.providers} provider={query.get("provider") ?? ""} model={query.get("model") ?? ""} base={data.base} change={change} />
      ) : null}
      {data && editable && pricing ? <PriceDialog model={pricing} input={priced?.input ?? ""} output={priced?.output ?? ""} base={data.base} change={change} /> : null}
    </>
  );
}

function PriceFields(props: { id: string; input: string; output: string; setInput: (v: string) => void; setOutput: (v: string) => void }) {
  const { id, input, output, setInput, setOutput } = props;
  return (
    <>
      <Field id={`${id}-input`} label="Input, USD per 1M tokens">
        <Input id={`${id}-input`} type="number" min={0} step="any" inputMode="decimal" className="t-mono" value={input} onChange={(e) => setInput(e.target.value)} required />
      </Field>
      <Field id={`${id}-output`} label="Output, USD per 1M tokens">
        <Input id={`${id}-output`} type="number" min={0} step="any" inputMode="decimal" className="t-mono" value={output} onChange={(e) => setOutput(e.target.value)} required />
      </Field>
    </>
  );
}

function AddDialog(props: { providers: string[]; provider: string; model: string; base: number | null; change: Change }) {
  const [provider, setProvider] = useState(props.providers.includes(props.provider) ? props.provider : (props.providers[0] ?? ""));
  const [model, setModel] = useState(props.model);
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [aliases, setAliases] = useState("");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await props.change(() => api.post("prices/add", { provider, model, input, output, aliases, base: props.base }));
    if (answer) setRefused(answer);
    else setQuery({});
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent>
        <DialogTitle>Add a model</DialogTitle>
        <DialogDescription>
          Saved as a new policy version. It is checked as enterplace check checks a file and every gateway serves it within 2 seconds, or after a second admin approves it.
        </DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          <Field id="model-provider" label="Provider">
            <Select value={provider} onValueChange={setProvider}>
              <SelectTrigger id="model-provider">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {props.providers.map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field id="model-name" label="Model" hint="The name callers send, as the provider knows it.">
            <Input id="model-name" className="t-mono" value={model} onChange={(e) => setModel(e.target.value)} placeholder="gpt-4o-mini" required autoFocus autoComplete="off" />
          </Field>
          <PriceFields id="model" input={input} output={output} setInput={setInput} setOutput={setOutput} />
          <Field id="model-aliases" label="Aliases, optional" hint="Other names callers may send for this model, separated by commas.">
            <Input id="model-aliases" className="t-mono" value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="fast, default" autoComplete="off" />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit">Save version</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function PriceDialog(props: { model: string; input: string; output: string; base: number | null; change: Change }) {
  const [input, setInput] = useState(props.input);
  const [output, setOutput] = useState(props.output);
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await props.change(() => api.post("prices/price", { model: props.model, input, output, base: props.base }));
    if (answer) setRefused(answer);
    else setQuery({});
  };
  return (
    <Dialog open onOpenChange={(open) => !open && setQuery({})}>
      <DialogContent>
        <DialogTitle>Change the price</DialogTitle>
        <DialogDescription>
          What <span className="t-mono">{props.model}</span> costs, for budgets and the spend page. Saved as a new policy version.
        </DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          <PriceFields id="price" input={input} output={output} setInput={setInput} setOutput={setOutput} />
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setQuery({})}>
              Cancel
            </Button>
            <Button type="submit">Save version</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
