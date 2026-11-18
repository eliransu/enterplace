import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Head, Panel, Problem } from "@/components/page";
import { api } from "@/lib/api";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";

// Each deployment's health as every gateway sees it, and each provider with its key pool and a connection test.
// Reloads every 5 seconds, so a deployment that starts cooling shows without a reload.

type Deployment = { deployment: string; state: "up" | "cooling" | "down"; note: string; aliases: string; probe: string; limits: string; load: string; latency: string; errors: string };
type Provider = { name: string; kind: string; keys: string };
type Tested = { provider: string; ok: boolean; tag: string; note: string; detail: string };
type View = { lead: string; may_test: boolean; deployments: Deployment[]; providers: Provider[]; none: { title: string; body: string } };

function State({ state, note }: { state: string; note: string }) {
  return (
    <Badge className={cn(state === "down" && "border-destructive text-destructive-text", state === "up" && "border-transparent pl-0 text-muted-foreground")}>
      {note ? `${state}, ${note}` : state}
    </Badge>
  );
}

export function Deployments() {
  const { data, error, change } = useData<View>("deployments", 5000);
  const [tested, setTested] = useState<Tested | null>(null);
  const test = (provider: string) =>
    change(async () => {
      const done = (await api.post("deployments", { provider })) as { message: string; tested: Tested };
      setTested(done.tested);
      return done;
    });
  return (
    <>
      <Head title="Deployments" lead={data?.lead ?? "Providers and their health."} />
      {error ? <Problem text={error} /> : null}
      {data ? (
        <>
          <Panel title={data.deployments.length ? "Deployments" : data.none.title}>
            {data.deployments.length === 0 ? (
              <p className="t-body m-0 text-muted-foreground">{data.none.body}</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Deployment</TableHead>
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
          <Panel title="Providers" note="Each provider of the policy and the keys of its pool. Test connection lists the provider's models, which bills nothing.">
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
                  const result = tested?.provider === p.name ? tested : null;
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
                            <Button variant="outline" size="sm" onClick={() => test(p.name)}>
                              Test connection
                            </Button>
                            {result ? <Badge className={cn(!result.ok && "border-destructive text-destructive-text")}>{result.note ? `${result.tag}, ${result.note}` : result.tag}</Badge> : null}
                          </div>
                          {result ? <span className="block">{result.detail}</span> : null}
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
