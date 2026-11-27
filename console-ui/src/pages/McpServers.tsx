import { useEffect, useState } from "react";
import { useCheckedChange } from "@/components/policy-change";
import { Copy } from "@/components/copy";
import { Setup } from "./Setup";
import { goTo } from "@/lib/use";
import type { PageProps } from "@/pages";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Panel, Problem, Refusal, Form, Loading, Cut } from "@/components/page";
import { Confirm, Remove } from "@/components/confirm";
import { EntityPicker, type Kind } from "@/components/team-picker";
import { Checkbox } from "@/components/ui/checkbox";
import { api, part } from "@/lib/api";
import { useData, words } from "@/lib/use";

type Access = { rule: string; allow: string[]; deny: string[]; everything: boolean };
type Server = {
  name: string;
  transport: string;
  url: string | null;
  command: string | null;
  args: string[];
  auth: string;
  auth_header: string;
  auth_env: string;
  access: Access[];
  disabled_tools: string[];
  /// The server's own access list; null while each rule's tools decide.
  grants: Grant[] | null;
};
type Grant = { kind: "team" | "person" | "app"; name: string; tools: string[] };
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

const AUTH: Record<string, string> = {
  none: "None",
  header: "Shared token from an environment variable",
  oauth: "Each person signs in (OAuth)",
};

export function McpServers({ me, query }: PageProps) {
  const { data, error, change: apply, reload } = useData<{ servers: Server[]; gateway: string; agent: string }>("mcp");
  // Each save shows its diff and a dry run of the last 24 hours first, and applies only on Apply.
  const [change, checking] = useCheckedChange(apply);
  const [picked, setForm] = useState<Server | "new" | null>(null);
  // `?add=1` opens Add a server, so Overview's next step is a link.
  const form = picked ?? (query.get("add") === "1" && me?.edit_policy ? "new" : null);
  const close = (added?: string) => {
    setForm(null);
    if (query.get("add")) goTo("/mcp");
    // A server just added: its tools, listed by Test as the dialog opens.
    if (added) setTools({ name: added, transport: "", url: null, command: null, args: [], auth: "", auth_header: "", auth_env: "", access: [], disabled_tools: [], grants: null });
  };
  const [tools, setTools] = useState<Server | null>(null);
  const [access, setAccess] = useState<string | null>(null);
  const accessed = data?.servers.find((s) => s.name === access);
  const may = !!me?.edit_policy;
  return (
    <>
      <Head
        title="MCP servers"
        lead="The MCP servers agents reach through Enterplace, their tools, and who may use each."
        actions={
          data ? (
            <>
              <Copy text={data.agent} label="Copy for your agent" />
              {data.servers.length ? (
                <Button disabled={!may} onClick={() => setForm("new")}>
                  Add a server
                </Button>
              ) : null}
            </>
          ) : null
        }
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={3} /> : null}
      {data ? (
      <Panel title={data.servers.length ? `${data.servers.length} ${data.servers.length === 1 ? "server" : "servers"}` : undefined} note="Tools lists each server's tools with a switch each. Their changes and stop switches are under MCP, Tools.">
        {data.servers.length === 0 ? (
          <Empty title="No MCP servers yet" body="Add one with its URL, or the program the gateway starts for it. Agents then reach its tools through Enterplace, and each call is recorded under the person who made it.">
            {may ? <Button onClick={() => setForm("new")}>Add a server</Button> : null}
          </Empty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Server</TableHead>
                <TableHead>Agents connect to</TableHead>
                <TableHead>Sign-in</TableHead>
                <TableHead>Who may use it</TableHead>
                <TableHead>Change</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.servers.map((s) => (
                <TableRow key={s.name}>
                  <TableCell>
                    {s.name}
                    <span className="block text-muted-foreground">{s.transport}</span>
                  </TableCell>
                  <TableCell>
                    <span className="flex items-center gap-2">
                      <Cut text={data.gateway} className="t-mono-sm" />
                      <Copy text={data.gateway} />
                    </span>
                    <Cut text={`forwards to ${s.url ?? [s.command, ...s.args].join(" ")}`} className="text-muted-foreground" />
                  </TableCell>
                  <TableCell>{s.auth === "header" ? `${s.auth_header} from ${s.auth_env}` : AUTH[s.auth] ?? s.auth}</TableCell>
                  <TableCell className="whitespace-normal">
                    {s.grants === null ? (
                      s.access.map((a) => (
                        <span key={a.rule} className="block">
                          rule {a.rule}: {summary(a)}
                        </span>
                      ))
                    ) : s.grants.length === 0 ? (
                      <span className="text-muted-foreground">No one: grant it under Access.</span>
                    ) : (
                      s.grants.map((g) => (
                        <span key={`${g.kind}-${g.name}`} className="block">
                          {g.kind} {g.name}: {g.tools.length ? g.tools.join(", ") : "every tool"}
                        </span>
                      ))
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" disabled={!may} onClick={() => setTools(s)}>
                        Tools
                      </Button>
                      <Button variant="outline" size="sm" disabled={!may} onClick={() => setAccess(s.name)}>
                        Access
                      </Button>
                      <Button variant="outline" size="sm" disabled={!may} onClick={() => setForm(s)}>
                        Edit
                      </Button>
                      <Remove
                        what={s.name}
                        disabled={!may}
                        detail={`Agents lose ${s.name}'s tools, and what each rule said of them goes too.`}
                        onConfirm={() => change(() => api.del(`mcp/${part(s.name)}`))}
                      />
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>
      ) : null}
      <section aria-label="Set up" className="grid gap-4">
        <h2 className="t-sm m-0">Set up MCP tools</h2>
        <Setup query={query} base="/mcp" track="mcp" />
      </section>
      {form ? <ServerForm server={form === "new" ? null : form} onClose={close} change={change} /> : null}
      {tools ? <ToolCatalog server={tools} onClose={() => setTools(null)} change={change} /> : null}
      {accessed ? <AccessDialog server={accessed} onClose={() => setAccess(null)} change={change} /> : null}
      {checking}
    </>
  );
}

function summary(a: Access) {
  const allow = a.allow.includes("*") ? "every tool" : a.allow.length ? a.allow.join(", ") : a.everything ? "every tool (rule allows *)" : "none";
  return a.deny.length ? `${allow}, except ${a.deny.join(", ")}` : allow;
}

function ServerForm({ server, onClose, change }: { server: Server | null; onClose: (added?: string) => void; change: Change }) {
  const [name, setName] = useState(server?.name ?? "");
  const [transport, setTransport] = useState(server?.transport ?? "http");
  const [url, setUrl] = useState(server?.url ?? "");
  const [command, setCommand] = useState(server?.command ?? "");
  const [args, setArgs] = useState(server?.args.join(", ") ?? "");
  const [auth, setAuth] = useState(server && server.auth in AUTH ? server.auth : "none");
  const [header, setHeader] = useState(server?.auth_header || "Authorization");
  const [env, setEnv] = useState(server?.auth_env ?? "");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = { name, transport, url, command, args: words(args), auth, auth_header: header, auth_env: env };
    const answer = await change(() => (server ? api.put(`mcp/${part(server.name)}`, body) : api.post("mcp", body)));
    if (answer) setRefused(answer);
    else onClose(server ? undefined : name);
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{server ? `Edit ${server.name}` : "Add an MCP server"}</DialogTitle>
        <DialogDescription>Agents see its tools as server.tool. Its tools are listed once it is added, each with a switch.</DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          {server ? null : (
            <Field id="name" label="Name" hint="Letters, digits, - and _, no dot. For example github.">
              <Input id="name" className="t-mono" value={name} onChange={(e) => setName(e.target.value)} required autoComplete="off" />
            </Field>
          )}
          <Field id="transport" label="Transport">
            <Select value={transport} onValueChange={setTransport}>
              <SelectTrigger id="transport">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="http">HTTP (Streamable HTTP)</SelectItem>
                <SelectItem value="sse">HTTP with SSE (older servers)</SelectItem>
                <SelectItem value="stdio">A program the gateway starts (stdio)</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {transport === "stdio" ? (
            <>
              <Field id="command" label="Command" hint="Absolute path, for example /usr/local/bin/mcp-server-git. The gateway runs it only if ENTERPLACE_MCP_STDIO_ALLOW lists it.">
                <Input id="command" className="t-mono" value={command} onChange={(e) => setCommand(e.target.value)} required />
              </Field>
              <Field id="args" label="Arguments, optional" hint="Separated by commas.">
                <Input id="args" className="t-mono" value={args} onChange={(e) => setArgs(e.target.value)} />
              </Field>
            </>
          ) : (
            <Field id="url" label="URL" hint="The server's own address, for example https://mcp.example.com/mcp. Agents still connect to Enterplace.">
              <Input id="url" className="t-mono" value={url} onChange={(e) => setUrl(e.target.value)} required />
            </Field>
          )}
          <Field id="auth" label="Sign-in">
            <Select value={auth} onValueChange={setAuth}>
              <SelectTrigger id="auth">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(AUTH).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {auth === "header" ? (
            <>
              <Field id="header" label="Header">
                <Input id="header" className="t-mono" value={header} onChange={(e) => setHeader(e.target.value)} />
              </Field>
              <Field id="env" label="Environment variable" hint="Holds the header's value on the gateway, for example GITHUB_MCP_TOKEN. The value never goes in the policy.">
                <Input id="env" className="t-mono" value={env} onChange={(e) => setEnv(e.target.value)} required />
              </Field>
            </>
          ) : null}
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onClose()}>
              Cancel
            </Button>
            <Button type="submit">{server ? "Save" : "Add server"}</Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

type Tool = { name: string; description: string; enabled: boolean };

/// The server's tools with a switch each: off is listed to no one and refused to everyone. Test lists them now; with
/// none known yet, it runs on open, so a server just added shows its tools.
function ToolCatalog({ server, onClose, change }: { server: Server; onClose: () => void; change: Change }) {
  const [tools, setTools] = useState<Tool[] | null>(null);
  const [off, setOff] = useState(() => new Set(server.disabled_tools));
  const [testing, setTesting] = useState(false);
  const [refused, setRefused] = useState("");
  const test = async () => {
    setTesting(true);
    setRefused("");
    try {
      const done = (await api.post("mcp-catalog", { server: server.name })) as unknown as { tools: Tool[] };
      setTools(done.tools);
    } catch (e) {
      setRefused((e as Error).message);
      setTools((t) => t ?? []);
    } finally {
      setTesting(false);
    }
  };
  useEffect(() => {
    api
      .get<{ servers: { name: string; tools: Tool[] }[] }>("mcp-catalog")
      .then((c) => {
        const known = c.servers.find((s) => s.name === server.name)?.tools ?? [];
        if (known.length) setTools(known);
        else void test();
      })
      .catch((e: Error) => setRefused(e.message));
    // Once, on open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const flip = (name: string, on: boolean) => {
    const next = new Set(off);
    if (on) next.delete(name);
    else next.add(name);
    setOff(next);
  };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.put(`mcp/${part(server.name)}/catalog`, { disabled: [...off].sort() }));
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-wide">
        <DialogTitle>Tools of {server.name}</DialogTitle>
        <DialogDescription>Switch a tool off and no one sees or calls it, whatever a rule or grant allows.</DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          {tools === null ? <Loading rows={2} /> : null}
          {tools && tools.length === 0 && !testing ? <Empty title="No tools listed yet" body="Press Test to ask the server for its tools." /> : null}
          {tools && tools.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tool</TableHead>
                  <TableHead>On</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tools.map((t) => (
                  <TableRow key={t.name}>
                    <TableCell className="whitespace-normal">
                      <label htmlFor={`tool-${t.name}`} className="t-mono">
                        {t.name}
                      </label>
                      <span className="block text-muted-foreground">{t.description || "No description."}</span>
                    </TableCell>
                    <TableCell>
                      <Switch id={`tool-${t.name}`} checked={!off.has(t.name)} onCheckedChange={(on) => flip(t.name, on)} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : null}
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" disabled={testing} onClick={() => void test()}>
              {testing ? "Testing" : "Test"}
            </Button>
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

const KINDS: Record<Grant["kind"], string> = { team: "Team", person: "Person", app: "App" };

/// Who may use one server: its grants, each revoked on its own, and a form to grant a team, person or app all of
/// its tools or the ones ticked. The first grant makes the list the server's; until then each rule's tools decide.
function AccessDialog({ server, onClose, change }: { server: Server; onClose: () => void; change: Change }) {
  const [kind, setKind] = useState<Grant["kind"]>("team");
  const [who, setWho] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [known, setKnown] = useState<string[]>([]);
  const [refused, setRefused] = useState("");
  useEffect(() => {
    api
      .get<{ servers: { name: string; tools: Tool[] }[] }>("mcp-catalog")
      .then((c) => setKnown((c.servers.find((s) => s.name === server.name)?.tools ?? []).filter((t) => t.enabled).map((t) => t.name)))
      .catch(() => setKnown([]));
  }, [server.name]);
  const tick = (tool: string, on: boolean) => {
    const next = new Set(picked);
    if (on) next.add(tool);
    else next.delete(tool);
    setPicked(next);
  };
  const grant = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.post(`mcp/${part(server.name)}/access`, { kind, name: who, tools: [...picked].sort() }));
    setRefused(answer);
    if (!answer) {
      setWho("");
      setPicked(new Set());
    }
  };
  const grants = server.grants;
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-wide">
        <DialogTitle>Who may use {server.name}</DialogTitle>
        <DialogDescription>
          {grants === null
            ? `Each rule's tools decide who may use ${server.name} today. Grant it here and only the teams, people and apps listed may use it.`
            : `Only the teams, people and apps listed may use ${server.name}, and only the tools named.`}
        </DialogDescription>
        {grants && grants.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Who</TableHead>
                <TableHead>Tools</TableHead>
                <TableHead>Change</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {grants.map((g) => (
                <TableRow key={`${g.kind}-${g.name}`}>
                  <TableCell>
                    <span className="t-mono">{g.name}</span>
                    <span className="block text-muted-foreground">{KINDS[g.kind]}</span>
                  </TableCell>
                  <TableCell className="whitespace-normal">{g.tools.length ? g.tools.join(", ") : "Every tool"}</TableCell>
                  <TableCell>
                    <Confirm
                      label="Revoke"
                      title={`Revoke ${server.name} from ${g.name}?`}
                      detail={`${g.name}'s calls to ${server.name} are refused once the policy is in force.`}
                      onConfirm={() => change(() => api.del(`mcp/${part(server.name)}/access/${g.kind}/${part(g.name)}`))}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : grants ? (
          <Empty title="No one may use it" body="Grant it to a team, a person or an app." />
        ) : null}
        <Form className="grid gap-6" onSubmit={grant}>
          <div className="grid gap-4 md:grid-cols-[1fr_2fr] md:items-end">
            <Field id="grant-kind" label="Grant to">
              <Select
                value={kind}
                onValueChange={(v) => {
                  setKind(v as Grant["kind"]);
                  setWho("");
                }}
              >
                <SelectTrigger id="grant-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(KINDS).map(([k, v]) => (
                    <SelectItem key={k} value={k}>
                      {v}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field id="grant-who" label={KINDS[kind]}>
              <EntityPicker key={kind} id="grant-who" kind={kind as Kind} value={who} onChange={(name) => setWho(name)} />
            </Field>
          </div>
          {known.length ? (
            <fieldset className="grid gap-2">
              <legend className="t-sm mb-2">Tools, none ticked for every tool</legend>
              {known.map((t) => (
                <label key={t} className="flex items-center gap-2">
                  <Checkbox checked={picked.has(t)} onCheckedChange={(on) => tick(t, on === true)} />
                  <span className="t-mono">{t}</span>
                </label>
              ))}
            </fieldset>
          ) : null}
          <Refusal text={refused} />
          <DialogFooter>
            {grants !== null ? (
              <Confirm
                label="Let rules decide"
                title={`Let each rule's tools decide who may use ${server.name}?`}
                detail="The grants above are removed. Whoever a rule's tools allow may use the server again."
                onConfirm={() => change(() => api.del(`mcp/${part(server.name)}/access`))}
              />
            ) : null}
            <Button type="button" variant="outline" onClick={onClose}>
              Close
            </Button>
            <Button type="submit" disabled={!who}>
              Grant
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
