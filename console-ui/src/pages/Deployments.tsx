import { useEffect, useState } from "react";
import { Confirm } from "@/components/confirm";
import { Copy } from "@/components/copy";
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

type Steps = {
  label: string;
  why: string;
  downtime: string;
  command: string;
  agent: string;
};
type Release = {
  version: string;
  url: string;
  summary: string[];
  more: number;
  image: string;
};
type Rollout = {
  from: string;
  to: string;
  by: string;
  at: string;
  back: boolean;
  state: "rolling" | "done" | "failed" | "stalled";
  gateways: {
    host: string;
    version: string;
    state: "updated" | "waiting" | "failed";
  }[];
  steps: Steps;
  rollback: { refused: string | null; steps: Steps };
};
type Updates = {
  running: string;
  check: string;
  skipped: string[];
  newest: Release | null;
  held: string | null;
  offer: (Release & { steps: Steps; gateways: number }) | null;
  rollout: Rollout | null;
  may_update: boolean;
};

// The steps this deployment takes a version with: what it costs in downtime, the exact command to copy or hand to an
// agent, and why the gateway does not run it itself.
function StepsBlock({ steps }: { steps: Steps }) {
  return (
    <div className="grid gap-2">
      <p className="t-body m-0 max-w-measure">{steps.downtime}</p>
      <pre className="t-mono-sm m-0 overflow-x-auto rounded-box bg-well px-6 py-3">
        {steps.command}
      </pre>
      <div className="flex flex-wrap gap-2">
        <Copy text={steps.command} />
        <Copy text={steps.agent} label="Copy for your agent" />
      </div>
      <p className="t-small m-0 max-w-measure text-muted-foreground">
        {steps.why}
      </p>
    </div>
  );
}

const ROLLOUT_STATE: Record<Rollout["state"], string> = {
  rolling: "rolling",
  done: "done",
  failed: "a gateway failed its health check",
  stalled: "not done after 15 minutes",
};

// The running version, the newest verified release and Update, then each gateway's progress while a version rolls,
// with the way back. Reloads every 5 seconds while a rollout runs.
function Version() {
  const { data, error, change, reload } = useData<Updates>("updates");
  const rolling = !!data?.rollout && data.rollout.state !== "done";
  useEffect(() => {
    if (!rolling) return;
    const timer = window.setInterval(reload, 5000);
    return () => window.clearInterval(timer);
  }, [rolling, reload]);
  if (error) return <Problem text={error} retry={reload} />;
  if (!data) return <Loading rows={2} />;
  const { offer, rollout } = data;
  const post = (body: object) => change(() => api.post("updates", body));
  return (
    <Panel title="Version" note={data.check}>
      <p className="t-body m-0">
        This gateway runs <span className="t-mono">{data.running}</span>.
        {offer || data.newest ? null : " No newer verified release."}
      </p>
      {offer && !rolling ? (
        <div className="grid gap-2">
          <p className="t-body-strong m-0">
            Enterplace <span className="t-mono">{offer.version}</span> is
            available. <a href={offer.url}>Release notes</a>
          </p>
          <ul className="t-small m-0 grid list-disc gap-1 pl-6">
            {offer.summary.map((line) => (
              <li key={line}>{line}</li>
            ))}
            {offer.more ? (
              <li className="text-muted-foreground">and {offer.more} more</li>
            ) : null}
          </ul>
          <div>
            <Confirm
              label={`Update to ${offer.version}`}
              variant="default"
              title={`Update to ${offer.version}?`}
              detail={`${offer.gateways === 1 ? "The gateway" : `All ${offer.gateways} gateways`} on ${offer.steps.label} ${offer.gateways === 1 ? "moves" : "move"} from ${data.running} to ${offer.version}, one at a time, each ready before the next. ${offer.steps.downtime} The update is recorded in the audit log, and the steps to run show here with each gateway's progress.`}
              action="Update"
              disabled={!data.may_update}
              onConfirm={() =>
                post({ action: "update", version: offer.version })
              }
            />
          </div>
          {data.may_update ? null : (
            <p className="t-small m-0 text-muted-foreground">
              Your role may not update Enterplace: it needs edit_policy and the
              whole install.
            </p>
          )}
        </div>
      ) : null}
      {data.held ? (
        <p className="t-small m-0 max-w-measure text-muted-foreground">
          {data.newest ? (
            <>
              Newest release:{" "}
              <span className="t-mono">{data.newest.version}</span>.{" "}
            </>
          ) : null}
          {data.held}
        </p>
      ) : null}
      {data.skipped.length ? (
        <p className="t-small m-0 text-muted-foreground">
          Not offered: {data.skipped.join("; ")}.
        </p>
      ) : null}
      {rollout ? (
        <div className="grid gap-4 border-t border-border pt-4">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="t-sm m-0">
              {rollout.back ? "Rolling back" : "Updating"} from{" "}
              <span className="t-mono">{rollout.from}</span> to{" "}
              <span className="t-mono">{rollout.to}</span>
            </h3>
            <Badge
              className={cn(
                (rollout.state === "failed" || rollout.state === "stalled") &&
                  "border-destructive text-destructive-text",
              )}
            >
              {ROLLOUT_STATE[rollout.state]}
            </Badge>
          </div>
          <p className="t-small m-0 text-muted-foreground">
            Started by {rollout.by} at{" "}
            {rollout.at.slice(0, 16).replace("T", " ")} UTC.
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Gateway</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Progress</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rollout.gateways.map((g, i) => (
                <TableRow key={`${g.host} ${i}`}>
                  <TableCell className="t-mono">{g.host}</TableCell>
                  <TableCell className="t-mono">{g.version}</TableCell>
                  <TableCell>
                    <Badge
                      className={cn(
                        g.state === "failed" &&
                          "border-destructive text-destructive-text",
                        g.state === "updated" &&
                          "border-transparent pl-0 text-muted-foreground",
                      )}
                    >
                      {g.state === "failed"
                        ? "failed its health check"
                        : g.state}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {rollout.state === "done" ? null : (
            <StepsBlock steps={rollout.steps} />
          )}
          {rollout.back ? null : (
            <div className="grid gap-2">
              <div>
                <Confirm
                  label={`Roll back to ${rollout.from}`}
                  title={`Roll back to ${rollout.from}?`}
                  detail={`Every gateway goes back from ${rollout.to} to ${rollout.from}, one at a time, each ready before the next. The rollback is recorded in the audit log, and its steps show here.`}
                  action="Roll back"
                  disabled={!data.may_update || !!rollout.rollback.refused}
                  onConfirm={() => post({ action: "rollback" })}
                />
              </div>
              {rollout.rollback.refused ? (
                <p className="t-small m-0 max-w-measure text-destructive-text">
                  {rollout.rollback.refused}
                </p>
              ) : null}
            </div>
          )}
        </div>
      ) : null}
    </Panel>
  );
}

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
      <Version />
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
