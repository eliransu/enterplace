import { useState } from "react";
import { Copy } from "@/components/copy";
import { Setup } from "./Setup";
import { goTo } from "@/lib/use";
import type { PageProps } from "@/pages";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
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
};
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

const AUTH: Record<string, string> = {
  none: "None",
  header: "Shared token from an environment variable",
  oauth: "Each person signs in (OAuth)",
};

export function McpServers({ me, query }: PageProps) {
  const { data, error, change, reload } = useData<{ servers: Server[]; gateway: string }>("mcp");
  const [picked, setForm] = useState<Server | "new" | null>(null);
  // `?add=1` opens Add a server, so Overview's next step is a link.
  const form = picked ?? (query.get("add") === "1" && me?.edit_policy ? "new" : null);
  const close = () => {
    setForm(null);
    if (query.get("add")) goTo("/mcp");
  };
  const [tools, setTools] = useState<Server | null>(null);
  const may = !!me?.edit_policy;
  return (
    <>
      <Head
        title="MCP servers"
        lead="The MCP servers agents reach through Enterplace, and which tools each rule may call."
        actions={
          data?.servers.length ? (
            <Button disabled={!may} onClick={() => setForm("new")}>
              Add a server
            </Button>
          ) : null
        }
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={3} /> : null}
      {data ? (
      <Panel title={data.servers.length ? `${data.servers.length} ${data.servers.length === 1 ? "server" : "servers"}` : undefined} note="The tools each server lists, their changes and their stop switches are under Tools.">
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
      {tools ? <ToolAccess server={tools} onClose={() => setTools(null)} change={change} /> : null}
    </>
  );
}

function summary(a: Access) {
  const allow = a.allow.includes("*") ? "every tool" : a.allow.length ? a.allow.join(", ") : a.everything ? "every tool (rule allows *)" : "none";
  return a.deny.length ? `${allow}, except ${a.deny.join(", ")}` : allow;
}

function ServerForm({ server, onClose, change }: { server: Server | null; onClose: () => void; change: Change }) {
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
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{server ? `Edit ${server.name}` : "Add an MCP server"}</DialogTitle>
        <DialogDescription>Agents see its tools as server.tool. No rule allows them until you say so under Tools.</DialogDescription>
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
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">{server ? "Save" : "Add server"}</Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function ToolAccess({ server, onClose, change }: { server: Server; onClose: () => void; change: Change }) {
  const [rows, setRows] = useState(server.access.map((a) => ({ rule: a.rule, allow: a.allow.join(", "), deny: a.deny.join(", ") })));
  const set = (i: number, key: "allow" | "deny", value: string) => setRows(rows.map((r, j) => (j === i ? { ...r, [key]: value } : r)));
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = { rules: rows.map((r) => ({ rule: r.rule, allow: words(r.allow), deny: words(r.deny) })) };
    const answer = await change(() => api.put(`mcp/${part(server.name)}/tools`, body));
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-wide">
        <DialogTitle>Tools of {server.name}</DialogTitle>
        <DialogDescription>For each rule: the tools it may call (* for all) and the ones it may never call, by the server's own tool names.</DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          {rows.map((r, i) => (
            <div key={r.rule} className="grid gap-4 md:grid-cols-[1fr_2fr_2fr] md:items-end">
              <span className="t-mono min-h-11 content-center">{r.rule}</span>
              <Field id={`allow-${i}`} label="Allow" hint="* for every tool.">
                <Input id={`allow-${i}`} className="t-mono" value={r.allow} onChange={(e) => set(i, "allow", e.target.value)} />
              </Field>
              <Field id={`deny-${i}`} label="Deny" hint="For example delete_repo.">
                <Input id={`deny-${i}`} className="t-mono" value={r.deny} onChange={(e) => set(i, "deny", e.target.value)} />
              </Field>
            </div>
          ))}
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
