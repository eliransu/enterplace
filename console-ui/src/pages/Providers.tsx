import { useState } from "react";
import { useCheckedChange } from "@/components/policy-change";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
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
  Head,
  Panel,
  Problem,
  Refusal,
  Form,
  Loading,
} from "@/components/page";
import { Remove } from "@/components/confirm";
import { Copy } from "@/components/copy";
import { ChipsInput } from "@/components/chips-input";
import { api, part, type Me } from "@/lib/api";
import { useData } from "@/lib/use";
import { useProviderStatus } from "@/lib/status";
import { cn } from "@/lib/utils";

type Provider = {
  name: string;
  kind: string;
  url: string | null;
  key: string;
  models: string[];
  retries: number | null;
  fallback: string | null;
};
// key: whether the provider takes a key at all. "none" for the demo model and AWS, "optional" for a local server.
type Preset = {
  id: string;
  name: string;
  local: boolean;
  needs_url: boolean;
  key: "none" | "optional" | "required";
  models: string[];
};
type Data = {
  providers: Provider[];
  catalog: Preset[];
  sealing: boolean;
  agent?: string;
  master_key_agent: string;
  docs: string;
};

export function Providers({ me }: { me: Me | null }) {
  const { data, error, change: apply, reload } = useData<Data>("providers");
  // Each save shows its diff and a dry run of the last 24 hours first, and applies only on Apply.
  const [change, checking] = useCheckedChange(apply);
  const { status, reload: retest } = useProviderStatus();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Provider | null>(null);
  const [testing, setTesting] = useState("");
  const may = !!me?.edit_policy;
  const test = (provider: string) => {
    setTesting(provider);
    return apply(() => api.post("deployments", { provider })).finally(() => {
      setTesting("");
      retest();
    });
  };
  return (
    <>
      <Head
        title="Providers"
        lead="Each provider, the models it serves, and where a failed request goes next."
        actions={
          <>
            {data?.agent ? (
              <Copy text={data.agent} label="Copy for your agent" />
            ) : null}
            <Button disabled={!may || !data} onClick={() => setAdding(true)}>
              Add a provider
            </Button>
          </>
        }
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={3} /> : null}
      {data ? (
        <Panel
          title={
            data.providers.length
              ? `${data.providers.length} ${data.providers.length === 1 ? "provider" : "providers"}`
              : undefined
          }
          note="Status is the last connection test, which lists the provider's models and bills nothing. Prices per model are under Models and prices."
        >
          {data.providers.length === 0 ? (
            <Empty
              title="No providers yet"
              body="Add one from the catalog: its key and the models it serves. The demo model needs no key and answers with sample text."
            >
              {may ? (
                <Button onClick={() => setAdding(true)}>Add a provider</Button>
              ) : null}
            </Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Models</TableHead>
                  <TableHead>Key</TableHead>
                  <TableHead>On failure</TableHead>
                  <TableHead>Change</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.providers.map((p) => {
                  const s = status?.[p.name];
                  return (
                    <TableRow key={p.name}>
                      <TableCell>
                        {p.name}
                        <span className="block text-muted-foreground">
                          {p.kind}
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <Badge
                          className={cn(
                            s &&
                              !s.ok &&
                              "border-destructive text-destructive-text",
                            s?.ok &&
                              "border-transparent pl-0 text-muted-foreground",
                          )}
                        >
                          {s ? (s.ok ? "connected" : "failed") : "testing"}
                        </Badge>
                        {s ? (
                          <span className="block max-w-col-sm text-muted-foreground">
                            {s.text.replace(/^Failed: /, "")}
                          </span>
                        ) : null}
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
                        <span className="block text-muted-foreground">
                          {p.fallback ? `then ${p.fallback}` : "no fallback"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={!may || !!testing}
                            onClick={() => test(p.name)}
                          >
                            {testing === p.name ? "Testing" : "Test connection"}
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={!may}
                            onClick={() => setEditing(p)}
                          >
                            Edit
                          </Button>
                          <Remove
                            what={p.name}
                            disabled={!may}
                            detail={`Requests stop going to ${p.name}. A sealed key stays under Credentials until you remove it there.`}
                            onConfirm={() =>
                              change(() => api.del(`providers/${part(p.name)}`))
                            }
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Panel>
      ) : null}
      {data && adding ? (
        <AddProvider
          data={data}
          me={me}
          onClose={() => setAdding(false)}
          change={change}
        />
      ) : null}
      {data && editing ? (
        <EditProvider
          provider={editing}
          others={data.providers}
          onClose={() => setEditing(null)}
          change={change}
        />
      ) : null}
      {checking}
    </>
  );
}

type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

function AddProvider({
  data,
  me,
  onClose,
  change,
}: {
  data: Data;
  me: Me | null;
  onClose: () => void;
  change: Change;
}) {
  // The demo model first: it works on every install, a master key or not.
  const catalog = [...data.catalog].sort(
    (a, b) => Number(b.id === "demo") - Number(a.id === "demo"),
  );
  const start = data.sealing ? "openai" : "demo";
  const [typed, setTyped] = useState(
    catalog.find((p) => p.id === start)?.name ?? "",
  );
  const chosen = catalog.find((p) => p.name === typed || p.id === typed);
  const preset = chosen?.id ?? "";
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [keyEnv, setKeyEnv] = useState("");
  const [url, setUrl] = useState("");
  const [models, setModels] = useState<string[]>(chosen?.models ?? []);
  const seal = data.sealing && !!me?.credentials;
  // A pasted key by default; a variable only when asked for, or when no key can be kept here.
  const [useEnv, setUseEnv] = useState(!seal);
  const need = chosen?.key ?? "required";
  // With no master key a pasted key cannot be kept: such a provider is added only with its key in a variable.
  const blocked = need === "required" && !data.sealing && !keyEnv.trim();
  const [refused, setRefused] = useState("");
  const pick = (value: string) => {
    setTyped(value);
    const next = catalog.find((p) => p.name === value || p.id === value);
    if (next) setModels(next.models);
  };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() =>
      api.post(
        "providers",
        need === "none"
          ? { preset, name, url, models }
          : useEnv
            ? { preset, name, key_env: keyEnv, url, models }
            : { preset, name, key, url, models },
      ),
    );
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>Add a provider</DialogTitle>
        <DialogDescription>
          Pick it from the catalog. Every gateway sends requests to it within 2
          seconds, then tests its connection.
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field
            id="preset"
            label="Provider"
            hint={
              chosen
                ? undefined
                : `Type to search ${catalog.length} providers, then pick one from the list.`
            }
          >
            <Input
              id="preset"
              list="preset-list"
              value={typed}
              onChange={(e) => pick(e.target.value)}
              onFocus={(e) => e.target.select()}
              required
              autoComplete="off"
              aria-invalid={!!typed && !chosen}
            />
            <datalist id="preset-list">
              {catalog.map((p) => (
                <option key={p.id} value={p.name} />
              ))}
            </datalist>
          </Field>
          {chosen?.needs_url ? (
            <Field
              id="url"
              label="URL"
              hint="Your account's own address for this provider."
            >
              <Input
                id="url"
                className="t-mono"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </Field>
          ) : null}
          {need === "none" ? (
            <p className="t-small m-0 pl-6 text-muted-foreground">
              No key needed:{" "}
              {chosen?.id === "demo"
                ? "Enterplace answers it itself."
                : "Enterplace signs its requests with the cloud's own credentials where it runs."}
            </p>
          ) : (
            <>
              {data.sealing ? null : (
                <div
                  role="note"
                  className="grid justify-items-start gap-2 rounded-panel border border-border p-4"
                >
                  <p className="t-small m-0">
                    This gateway has no master key, so it cannot keep a pasted
                    key. Set one first, or name an environment variable that
                    already holds the key on every gateway.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Copy
                      text={data.master_key_agent}
                      label="Copy for your agent"
                    />
                    <Button variant="outline" size="sm" asChild>
                      <a href={data.docs}>How the master key works</a>
                    </Button>
                  </div>
                </div>
              )}
              {seal && !useEnv ? (
                <Field
                  id="key"
                  label={
                    need === "optional"
                      ? "Provider key, optional"
                      : "Provider key"
                  }
                  hint="Stored encrypted under the master key. It is in no record and no page."
                >
                  <Input
                    id="key"
                    type="password"
                    className="t-mono"
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                    autoComplete="off"
                    required={need === "required"}
                  />
                </Field>
              ) : (
                <Field
                  id="key-env"
                  label={
                    need === "optional"
                      ? "Environment variable that holds the key, optional"
                      : "Environment variable that holds the key"
                  }
                  hint="For example OPENROUTER_API_KEY. It must be set on every gateway."
                >
                  <Input
                    id="key-env"
                    className="t-mono"
                    value={keyEnv}
                    onChange={(e) => setKeyEnv(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    required={need === "required"}
                  />
                </Field>
              )}
              {seal ? (
                <button
                  type="button"
                  className="t-small -mt-3 cursor-pointer justify-self-start border-0 bg-transparent p-0 pl-6 text-muted-foreground underline"
                  onClick={() => setUseEnv(!useEnv)}
                >
                  {useEnv
                    ? "Paste the key instead"
                    : "The key is in an environment variable instead"}
                </button>
              ) : null}
            </>
          )}
          <Field
            id="models"
            label="Models"
            hint="The names callers send. Press Enter after each, or paste a list. * serves every model the provider has."
          >
            <ChipsInput
              id="models"
              values={models}
              onChange={setModels}
              suggestions={chosen?.models ?? []}
              placeholder={models.length ? "Add another model" : "anthropic/claude-sonnet-5-5"}
            />
          </Field>
          <details className="grid gap-4">
            <summary className="t-small cursor-pointer text-muted-foreground">
              More options
            </summary>
            <Field
              id="name"
              label="Name"
              hint={`Callers never see it. Leave empty for ${preset || "the catalog id"}. Set one to add the same provider twice, for two accounts.`}
            >
              <Input
                id="name"
                className="t-mono"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
          </details>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!chosen || blocked}>
              Add provider
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function EditProvider({
  provider,
  others,
  onClose,
  change,
}: {
  provider: Provider;
  others: Provider[];
  onClose: () => void;
  change: Change;
}) {
  const [models, setModels] = useState<string[]>(provider.models);
  const [retries, setRetries] = useState(provider.retries?.toString() ?? "");
  const [fallback, setFallback] = useState(provider.fallback ?? "none");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() =>
      api.put(`providers/${part(provider.name)}`, {
        models,
        retries,
        fallback: fallback === "none" ? "" : fallback,
      }),
    );
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>Edit {provider.name}</DialogTitle>
        <DialogDescription>
          The models it serves, and where a request goes when it keeps failing.
        </DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field
            id="models"
            label="Models"
            hint="Press Enter after each, or paste a list. * serves every model the provider has."
          >
            <ChipsInput id="models" values={models} onChange={setModels} />
          </Field>
          <Field
            id="retries"
            label="Retries"
            hint="Tries again after a 429 or a 5xx, 0 to 10 times."
          >
            <Input
              id="retries"
              type="number"
              min={0}
              max={10}
              className="t-mono"
              value={retries}
              onChange={(e) => setRetries(e.target.value)}
            />
          </Field>
          <Field
            id="fallback"
            label="Fallback provider"
            hint="Takes the request when every retry failed. It must speak the same API."
          >
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
        </Form>
      </DialogContent>
    </Dialog>
  );
}
