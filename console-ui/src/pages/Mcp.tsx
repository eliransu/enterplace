import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Panel, Problem } from "@/components/page";
import { api } from "@/lib/api";
import { useData } from "@/lib/use";

// The MCP gateway's three pages: tools (pins, held changes, kill switches), calls waiting for approval, and open
// sessions. Each reloads every 5 seconds, so a call that starts waiting shows without a reload.

type Start = { title: string; body: string; action: { label: string; href: string }; docs: string };
type Base = { error?: string; lead: string; editable: boolean; empty: Start | null; none: { title: string; body: string } };
type Tool = { id: string; name: string; description: string; first_seen: string; used_by: string; held: boolean; changed: string | null; stopped: boolean };
type Call = { id: string; tool: string; person: string; team: string; rule: string; asked_at: string; arguments: string };
type Session = { id: string; client: string; who: string; user_agent: string; started: string; last_used: string };
type Connection = { id: string; server: string; person: string; detail: string };

const EVERY = 5000;

// With no MCP server in the policy, what fills the page and the Start here step for it.
function NoServers({ empty }: { empty: Start }) {
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

function Frame<T extends Base>({ title, fallback, data, error, rows, children }: { title: string; fallback: string; data: T | null; error: string; rows: number; children: React.ReactNode }) {
  return (
    <>
      <Head title={title} lead={data?.lead ?? fallback} />
      {error ? <Problem text={error} /> : null}
      {data?.error ? <Problem text={data.error} /> : null}
      {data?.empty ? <NoServers empty={data.empty} /> : null}
      {data && !data.empty && !data.error ? (
        rows === 0 ? (
          <Panel title={data.none.title}>
            <p className="t-body m-0 text-muted-foreground">{data.none.body}</p>
          </Panel>
        ) : (
          children
        )
      ) : null}
    </>
  );
}

export function McpTools() {
  const { data, error, change } = useData<Base & { tools: Tool[] }>("mcp-tools", EVERY);
  const act = (action: string, tool: string) => change(() => api.post("mcp-tools", { action, tool }));
  return (
    <Frame title="MCP tools" fallback="Each tool your MCP servers offer, and who may use it." data={data} error={error} rows={data?.tools?.length ?? 0}>
      <Panel title="Tools" note="A tool is pinned to the description and schema it was first seen with. A change is recorded, and held for approval on a server with tool_changes: block.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Tool</TableHead>
              <TableHead>Used by</TableHead>
              <TableHead>State</TableHead>
              {data?.editable ? <TableHead>Change</TableHead> : null}
            </TableRow>
          </TableHeader>
          <TableBody>
            {data?.tools.map((t) => (
              <TableRow key={t.id}>
                <TableCell className="whitespace-normal">
                  <span className="t-mono">{t.name}</span>
                  <span className="block text-muted-foreground">{t.description}</span>
                  <span className="block text-muted-foreground">First seen {t.first_seen}</span>
                  {t.changed ? <span className="block">{t.changed}</span> : null}
                </TableCell>
                <TableCell className="whitespace-normal">{t.used_by}</TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-2">
                    {t.held ? <Badge>held</Badge> : null}
                    {t.stopped ? <Badge className="border-destructive bg-destructive text-destructive-foreground">stopped</Badge> : null}
                    {!t.held && !t.stopped ? <span className="text-muted-foreground">runs</span> : null}
                  </div>
                </TableCell>
                {data.editable ? (
                  <TableCell>
                    <div className="flex flex-wrap gap-2">
                      {t.held ? (
                        <Button size="sm" onClick={() => act("approve", t.id)}>
                          Approve change
                        </Button>
                      ) : null}
                      <Button variant="outline" size="sm" onClick={() => act(t.stopped ? "start" : "stop", t.id)}>
                        {t.stopped ? "Start tool" : "Stop tool"}
                      </Button>
                    </div>
                  </TableCell>
                ) : null}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </Frame>
  );
}

export function McpApprovals() {
  const { data, error, change } = useData<Base & { calls: Call[] }>("mcp-approvals", EVERY);
  const decide = (action: string, id: string) => change(() => api.post("mcp-approvals", { action, id }));
  return (
    <Frame title="MCP approvals" fallback="Tool calls waiting for an admin." data={data} error={error} rows={data?.calls?.length ?? 0}>
      <Panel title="Waiting" note="A call waits until it is approved or denied here, or its time runs out.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Tool</TableHead>
              <TableHead>Who and why</TableHead>
              <TableHead>Arguments</TableHead>
              {data?.editable ? <TableHead>Decide</TableHead> : null}
            </TableRow>
          </TableHeader>
          <TableBody>
            {data?.calls.map((c) => (
              <TableRow key={c.id}>
                <TableCell className="t-mono">{c.tool}</TableCell>
                <TableCell className="whitespace-normal">
                  {c.person} of team {c.team}
                  <span className="block text-muted-foreground">
                    Rule {c.rule}, asked {c.asked_at}
                  </span>
                </TableCell>
                <TableCell className="t-mono-sm max-w-measure whitespace-normal break-all">{c.arguments}</TableCell>
                {data.editable ? (
                  <TableCell>
                    <div className="flex flex-wrap gap-2">
                      <Button size="sm" onClick={() => decide("approve", c.id)}>
                        Approve
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => decide("deny", c.id)}>
                        Deny
                      </Button>
                    </div>
                  </TableCell>
                ) : null}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </Frame>
  );
}

export function McpSessions() {
  const { data, error, change } = useData<Base & { sessions: Session[]; connections: Connection[] }>("mcp-sessions", EVERY);
  const end = (id: string) => change(() => api.post("mcp-sessions", { id }));
  const rows = (data?.sessions?.length ?? 0) + (data?.connections?.length ?? 0);
  return (
    <Frame title="MCP sessions" fallback="Connected MCP clients and accounts." data={data} error={error} rows={rows}>
      {data?.sessions.length ? (
        <Panel title="Clients" note="An ended session's client connects again to go on.">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Client</TableHead>
                <TableHead>Who</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Last used</TableHead>
                {data.editable ? <TableHead>End</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.sessions.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="whitespace-normal">
                    {s.client}
                    <span className="t-mono-sm block text-muted-foreground">{s.user_agent}</span>
                  </TableCell>
                  <TableCell>{s.who}</TableCell>
                  <TableCell className="tabular-nums">{s.started}</TableCell>
                  <TableCell className="tabular-nums">{s.last_used}</TableCell>
                  {data.editable ? (
                    <TableCell>
                      <Button variant="outline" size="sm" onClick={() => end(s.id)}>
                        End session
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      ) : null}
      {data?.connections.length ? (
        <Panel title="Accounts" note="A disconnected person signs in to the server again to go on.">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Server and person</TableHead>
                {data.editable ? <TableHead>End</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.connections.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="whitespace-normal">
                    {c.server}, {c.person}
                    <span className="block text-muted-foreground">{c.detail}</span>
                  </TableCell>
                  {data.editable ? (
                    <TableCell>
                      <Button variant="outline" size="sm" onClick={() => end(c.id)}>
                        Disconnect
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      ) : null}
    </Frame>
  );
}
