import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Loading, Panel, Problem } from "@/components/page";
import { api } from "@/lib/api";
import { useData } from "@/lib/use";
import { useProviderStatus } from "@/lib/status";
import { cn } from "@/lib/utils";

// Health: each gateway, each alias target's state as every gateway sees it, and each provider with its key pool and
// its status from the last connection test, the same one Providers shows.
// Reloads every 5 seconds, so a deployment that starts cooling shows without a reload.

type Deployment = { deployment: string; state: "up" | "cooling" | "down"; note: string; aliases: string; probe: string; limits: string; load: string; latency: string; errors: string };
type Provider = { name: string; kind: string; keys: string };
type Gateway = { host: string; version: string; healthy: boolean; stopped?: boolean; meta: string };
type View = { lead: string; gateways: Gateway[]; gateways_note: string; may_test: boolean; deployments: Deployment[]; providers: Provider[]; none: { title: string; body: string } };

function State({ state, note }: { state: string; note: string }) {
  return (
    <Badge className={cn(state === "down" && "border-destructive text-destructive-text", state === "up" && "border-transparent pl-0 text-muted-foreground")}>
      {note ? `${state}, ${note}` : state}
    </Badge>
  );
}

export function Deployments() {
  const { data, error, change, reload } = useData<View>("deployments", 5000);
  const [testing, setTesting] = useState("");
  const { status, reload: retest } = useProviderStatus();
  const [showStopped, setShowStopped] = useState(false);
  // A gateway silent for over an hour has stopped: folded away so the running ones read at a glance.
  const stopped = data?.gateways.filter((g) => g.stopped).length ?? 0;
  const gateways = (data?.gateways ?? []).filter((g) => showStopped || !g.stopped);
  const test = (provider: string) => {
    setTesting(provider);
    return change(() => api.post("deployments", { provider })).finally(() => {
      setTesting("");
      retest();
    });
  };
  return (
    <>
      <Head title="Health" lead={data?.lead ?? "Whether each gateway and provider is up."} />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={4} /> : null}
      {data ? (
        <>
          <Panel title="Gateways" note={data.gateways_note}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Gateway</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Health</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gateways.map((g, i) => (
                  <TableRow key={`${g.host} ${i}`}>
                    <TableCell className="whitespace-normal">
                      <span className="t-mono block">{g.host}</span>
                      <span className="block text-muted-foreground">{g.meta}</span>
                    </TableCell>
                    <TableCell className="t-mono">{g.version}</TableCell>
                    <TableCell>
                      <Badge className={cn(g.healthy && "border-transparent pl-0 text-muted-foreground")}>{g.healthy ? "healthy" : g.stopped ? "stopped" : "silent"}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {stopped ? (
              <div>
                <Button variant="outline" size="sm" aria-expanded={showStopped} onClick={() => setShowStopped((v) => !v)}>
                  {showStopped ? `Hide stopped gateways (${stopped})` : `Show stopped gateways (${stopped})`}
                </Button>
              </div>
            ) : null}
          </Panel>
          <Panel title={data.deployments.length ? "Alias targets" : undefined}>
            {data.deployments.length === 0 ? (
              <Empty title={data.none.title} body={data.none.body}>
                <Button variant="outline" asChild>
                  <a href="#/providers">Open providers</a>
                </Button>
              </Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Target</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Routing</TableHead>
                    <TableHead>Now</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.deployments.map((d) => (
                    <TableRow key={d.deployment}>
                      <TableCell className="t-mono">{d.deployment}</TableCell>
                      <TableCell>
                        <State state={d.state} note={d.note} />
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <span className="block">alias {d.aliases}</span>
                        <span className="block text-muted-foreground">limits {d.limits}</span>
                        <span className="block text-muted-foreground">{d.probe}</span>
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <span className="block">{d.load}</span>
                        <span className="block text-muted-foreground">{d.latency}</span>
                        <span className="block text-muted-foreground">{d.errors}</span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>
          <Panel title="Providers" note="Each provider of the policy, the keys of its pool, and its last connection test, which lists the provider's models and bills nothing.">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Keys</TableHead>
                  {data.may_test ? <TableHead>Connection</TableHead> : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.providers.map((p) => {
                  const result = status?.[p.name];
                  return (
                    <TableRow key={p.name}>
                      <TableCell>
                        <span className="t-mono block">{p.name}</span>
                        <span className="block text-muted-foreground">{p.kind}</span>
                      </TableCell>
                      <TableCell className="whitespace-normal">{p.keys}</TableCell>
                      {data.may_test ? (
                        <TableCell className="whitespace-normal">
                          <div className="flex flex-wrap items-center gap-2">
                            <Button variant="outline" size="sm" disabled={!!testing} onClick={() => test(p.name)}>
                              {testing === p.name ? "Testing" : "Test connection"}
                            </Button>
                            {result ? <Badge className={cn(!result.ok && "border-destructive text-destructive-text")}>{result.ok ? "connected" : "failed"}</Badge> : null}
                          </div>
                          {result ? <span className="block">{result.text.replace(/^Failed: /, "")}</span> : null}
                        </TableCell>
                      ) : null}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Panel>
        </>
      ) : null}
    </>
  );
}
