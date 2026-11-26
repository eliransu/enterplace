import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
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
import { Empty, Head, Loading, Panel, Problem } from "@/components/page";
import { Busy, useCheckedChange } from "@/components/policy-change";
import { api, part } from "@/lib/api";
import { count, num, useData } from "@/lib/use";
import type { PageProps } from "@/pages";

export type Refusal = {
  code: string;
  words: string;
  fix: "allow" | "provider" | "requests";
  model: string;
} | null;

export type Caller = {
  name: string;
  team: string;
  kind: string;
  state: "new" | "pending" | "blocked" | "blocked by default";
  first_seen: string;
  last_seen: string;
  requests: number;
  refused: number;
  refusal: Refusal;
};

type ModelRow = {
  model: string;
  first_seen: string;
  last_seen: string;
  requests: number;
  callers: string[];
  refusal: Refusal;
};

export type Callers = {
  set: boolean;
  mode: Mode | null;
  may: boolean;
  days: number;
  waiting: number;
  callers: Caller[];
  models: ModelRow[];
};

type Mode = "allow" | "hold" | "block";

const MODES: Record<Mode, { label: string; body: string }> = {
  allow: {
    label: "Allow and log",
    body: "A new caller is let through, as far as a provider serves it, and listed here until you allow or block it.",
  },
  hold: {
    label: "Hold for approval",
    body: "A new caller's requests are refused as awaiting_approval until you allow it here. The refusal tells the caller where.",
  },
  block: {
    label: "Block",
    body: "A new caller is refused as caller_blocked and listed here. You can still allow it.",
  },
};

/// The people a coding agent sends for, apart from the keys of apps.
export const isPerson = (c: Caller) =>
  c.kind === "person key" || c.kind === "person token";

/// What waits for an admin on one use case's page: new or pending callers, and on Apps and agents the models.
export function waitingFor(data: Callers | null, people: boolean): number {
  if (!data) return 0;
  const callers = data.callers.filter(
    (c) =>
      (c.state === "new" || c.state === "pending") && (!people || isPerson(c)),
  ).length;
  return people ? callers : callers + data.models.length;
}

// New and pending: what reached the gateway that no admin has reviewed, with Allow and Block, and the models no
// provider serves with the step that fixes each. `people`: the Coding agents view, people only.
export function NewCallers({ me, people }: PageProps & { people?: boolean }) {
  const { data, error, change: apply, reload } = useData<Callers>("callers");
  // A mode change shows its diff and a dry run of the last 24 hours first; Allow and Block apply at once.
  const [change, checking] = useCheckedChange(apply);
  const [asked, setAsked] = useState<Mode | null>(null);
  const [keep, setKeep] = useState(true);
  const may = !!data?.may && !!me?.edit_policy;
  const callers = (data?.callers ?? []).filter((c) => !people || isPerson(c));
  const seen = callers.filter((c) => c.state === "new").map((c) => c.name);
  const decide = (name: string, decision: "allow" | "block") =>
    apply(() => api.post("callers", { name, decision }));
  const setMode = (mode: Mode) =>
    change(() =>
      api.put("callers/mode", {
        mode,
        allow: mode !== "allow" && keep ? seen : [],
      }),
    );
  return (
    <>
      <Head
        title="New and pending"
        lead={`Callers no admin has reviewed and models no provider serves, from the last ${data?.days ?? 30} days of requests. Allow or block each one: every gateway follows within 2 seconds.`}
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={4} /> : null}
      {data ? (
        <>
          <Panel
            title="What happens to a new caller"
            note="A caller is new until an admin allows or blocks it, by the name its key, person token or sign-in gives it. Admins are never held."
          >
            <div className="flex flex-wrap items-center gap-4">
              <Select
                value={data.mode ?? ""}
                disabled={!may}
                onValueChange={(m) => {
                  setKeep(true);
                  setAsked(m as Mode);
                }}
              >
                <SelectTrigger
                  aria-label="What happens to a new caller"
                  className="w-auto"
                >
                  <SelectValue placeholder="Not set" />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(MODES) as Mode[]).map((m) => (
                    <SelectItem key={m} value={m}>
                      {MODES[m].label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="t-body m-0 max-w-measure text-muted-foreground">
                {data.mode
                  ? MODES[data.mode].body
                  : "Not set: every caller is let through as before and nothing is listed. Pick one to hear of new callers."}
              </p>
            </div>
          </Panel>
          <AlertDialog
            open={!!asked}
            onOpenChange={(open) => !open && setAsked(null)}
          >
            <AlertDialogContent>
              <AlertDialogTitle>
                {asked ? MODES[asked].label : ""}?
              </AlertDialogTitle>
              <AlertDialogDescription>
                {asked ? MODES[asked].body : ""} Every gateway follows within 2
                seconds. The next step shows the change and a dry run of the
                last 24 hours before anything is saved.
              </AlertDialogDescription>
              {asked && asked !== "allow" && seen.length ? (
                <label className="t-body flex min-h-11 items-center gap-3">
                  <Checkbox
                    checked={keep}
                    onCheckedChange={(c) => setKeep(c === true)}
                  />
                  Allow the {count(seen.length, "caller")} already working (
                  {seen.join(", ")}), so they are not refused.
                </label>
              ) : null}
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={() => {
                    if (asked) setMode(asked);
                    setAsked(null);
                  }}
                >
                  Continue
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
          <Panel
            title={people ? "People" : "Callers"}
            note="Allow puts the name on the policy's allowed list, Block on its blocked list. Both are recorded with your name."
          >
            {callers.length === 0 ? (
              <Empty
                title={
                  data.set ? "Nothing new" : "Not watching for new callers"
                }
                body={
                  data.set
                    ? "Every caller that sent a request is reviewed. A new key, person token or sign-in shows here with its first request."
                    : "Pick what happens to a new caller above, and each new key, person token or sign-in shows here with its first request."
                }
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Caller</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>First seen, UTC</TableHead>
                    <TableHead className="text-right">Requests</TableHead>
                    <TableHead>Last refusal</TableHead>
                    <TableHead>Decide</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {callers.map((c) => (
                    <TableRow key={c.name}>
                      <TableCell>
                        <a href={`#/requests?person=${part(c.name)}`}>
                          {c.name}
                        </a>
                        <span className="block text-muted-foreground">
                          {c.kind}
                          {c.team ? `, ${c.team}` : ""}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge>{c.state}</Badge>
                      </TableCell>
                      <TableCell>{c.first_seen || "-"}</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {num(c.requests)}
                        {c.refused ? (
                          <span className="block text-muted-foreground">
                            {num(c.refused)} refused
                          </span>
                        ) : null}
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <Fix refusal={c.refusal} may={may} />
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Busy
                            size="sm"
                            disabled={!may}
                            run={() => decide(c.name, "allow")}
                          >
                            Allow
                          </Busy>
                          {c.state === "blocked" ? null : (
                            <Busy
                              size="sm"
                              variant="outline"
                              disabled={!may}
                              run={() => decide(c.name, "block")}
                            >
                              Block
                            </Busy>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>
          {people ? null : (
            <Panel
              title="Models no provider serves"
              note="Each was asked for and refused. Add a provider that serves it: callers get it within 2 seconds."
            >
              {data.models.length === 0 ? (
                <Empty
                  title="None"
                  body="Every model asked for is served, or was refused for another reason: Requests lists those."
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Model</TableHead>
                      <TableHead>Why</TableHead>
                      <TableHead>First seen, UTC</TableHead>
                      <TableHead className="text-right">Requests</TableHead>
                      <TableHead>Asked for by</TableHead>
                      <TableHead>Fix</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.models.map((m) => (
                      <TableRow key={m.model}>
                        <TableCell className="t-mono-sm">{m.model}</TableCell>
                        <TableCell className="whitespace-normal">
                          {m.refusal?.words}
                        </TableCell>
                        <TableCell>{m.first_seen}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {num(m.requests)}
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          {m.callers.join(", ")}
                        </TableCell>
                        <TableCell>
                          <Button size="sm" disabled={!may} asChild={may}>
                            {may ? (
                              <a href={`#/providers?model=${part(m.model)}`}>
                                Add a provider
                              </a>
                            ) : (
                              "Add a provider"
                            )}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Panel>
          )}
          {checking}
        </>
      ) : null}
    </>
  );
}

/// The newest refusal of a caller in words, and the step that fixes it when it is not Allow beside it.
function Fix({ refusal, may }: { refusal: Refusal; may: boolean }) {
  if (!refusal) return <span className="text-muted-foreground">None</span>;
  return (
    <span className="grid justify-items-start gap-1">
      <span>
        {refusal.words}
        {refusal.model ? (
          <span className="t-mono-sm block text-muted-foreground">
            {refusal.model}
          </span>
        ) : null}
      </span>
      {refusal.fix === "provider" && may ? (
        <a href={`#/providers?model=${part(refusal.model)}`}>
          Add a provider for it
        </a>
      ) : refusal.fix === "requests" ? (
        <a href={`#/requests?outcome=refused&code=${part(refusal.code)}`}>
          See the refusals
        </a>
      ) : null}
    </span>
  );
}
