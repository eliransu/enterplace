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
import { Remove } from "@/components/confirm";
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
};
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
    if (added) setTools({ name: added, transport: "", url: null, command: null, args: [], auth: "", auth_header: "", auth_env: "", access: [], disabled_tools: [] });
  };
  const [tools, setTools] = useState<Server | null>(null);
  const may = !!me?.edit_policy;
  return (
    <>
      <Head
        title="MCP servers"
        lead="The MCP servers agents reach through Enterplace, and which tools each rule may call."
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
                <TableHead>Tools allowed</TableHead>
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
                    {s.access.map((a) => (
                      <span key={a.rule} className="block">
                        {a.rule}: {summary(a)}
                      </span>
                    ))}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" disabled={!may} onClick={() => setTools(s)}>
                        Tools
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
