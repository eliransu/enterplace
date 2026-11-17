import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Panel, Problem, Refusal } from "@/components/page";
import { Remove } from "@/components/confirm";
import { api, part, type Me } from "@/lib/api";
import { useData, words } from "@/lib/use";

type Rule = { name: string; who: { kind: string; value: string }; models: string[]; guardrails: string[] };
type Budget = { scope: string; name: string; usd: number; per: string };
type Guardrail = { name: string; type: string; action: string | null; on: boolean };
type Alias = { name: string; deployments: { provider: string; model: string }[]; fallbacks: string[] };
type Data = { mode: string; rules: Rule[]; budgets: Budget[]; other_limits: number; guardrails: Guardrail[]; aliases: Alias[] };
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

const WHO: Record<string, string> = { any: "Everyone", team: "A team", name: "A person", tag: "A tag" };
const who = (r: Rule) => (r.who.kind === "any" ? "everyone" : r.who.kind === "other" ? "see the raw policy" : `${r.who.kind === "name" ? "person" : r.who.kind} ${r.who.value}`);

export function PolicyBasics({ me }: { me: Me | null }) {
  const { data, error, change } = useData<Data>("policy");
  const [rule, setRule] = useState<Rule | "new" | null>(null);
  const [budget, setBudget] = useState<Budget | "new" | null>(null);
  const [alias, setAlias] = useState<Alias | "new" | null>(null);
  const may = !!me?.edit_policy;
  return (
    <>
      <Head
        title="Policy basics"
        lead="Who may use which models, what they may spend, which guardrails run, and where requests go."
        actions={
          <Button variant="outline" asChild>
            <a href="/console/policy">Raw policy (advanced)</a>
          </Button>
        }
      />
      {error ? <Problem text={error} /> : null}
      {data ? (
        <>
          <Panel title="Mode">
            <label className="t-body flex items-center gap-3">
              <Switch
                checked={data.mode === "enforce"}
                disabled={!may}
                onCheckedChange={(on) => change(() => api.put("policy/mode", { mode: on ? "enforce" : "observe" }))}
              />
              {data.mode === "enforce" ? "Enforce: what the policy does not allow is refused." : "Observe: everything goes through, and what the policy would refuse is recorded."}
            </label>
          </Panel>

          <Panel
            title="Rules"
            note="The first rule that matches a caller decides. A new rule for a team or a person goes before the rule for everyone."
            actions={
              <Button size="sm" disabled={!may} onClick={() => setRule("new")}>
                Add a rule
              </Button>
            }
          >
            {data.rules.length === 0 ? (
              <Empty title="No rules" body="With no rule, every request is refused. Add one for everyone." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule</TableHead>
                    <TableHead>For</TableHead>
                    <TableHead>Models</TableHead>
                    <TableHead>Guardrails</TableHead>
                    <TableHead>Change</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.rules.map((r) => (
                    <TableRow key={r.name}>
                      <TableCell>{r.name}</TableCell>
                      <TableCell>{who(r)}</TableCell>
                      <TableCell className="whitespace-normal">{r.models.join(", ") || "from profiles"}</TableCell>
                      <TableCell>{r.guardrails.join(", ") || "none"}</TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" disabled={!may || r.who.kind === "other"} onClick={() => setRule(r)}>
                            Edit
                          </Button>
                          <Remove what={`rule ${r.name}`} disabled={!may} detail="Callers it let in fall to the next rule that matches them, or are refused." onConfirm={() => change(() => api.del(`policy/rules/${part(r.name)}`))} />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>

          <Panel
            title="Budgets"
            note={data.other_limits ? `${data.other_limits} other limits (rates, per model, per key) are kept in the raw policy.` : "A request that would pass a budget is refused until it resets."}
            actions={
              <Button size="sm" disabled={!may} onClick={() => setBudget("new")}>
                Set a budget
              </Button>
            }
          >
            {data.budgets.length === 0 ? (
              <Empty title="No budgets" body="Spend is counted but nothing stops it. Set a budget for everyone, a team or a person." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>For</TableHead>
                    <TableHead className="text-right">USD</TableHead>
                    <TableHead>Resets every</TableHead>
                    <TableHead>Change</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.budgets.map((b) => (
                    <TableRow key={`${b.scope}/${b.name}`}>
                      <TableCell>{b.scope === "global" ? "everyone together" : `${b.scope} ${b.name}`}</TableCell>
                      <TableCell className="text-right tabular-nums">{b.usd}</TableCell>
                      <TableCell>{b.per}</TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" disabled={!may} onClick={() => setBudget(b)}>
                            Edit
                          </Button>
                          <Remove what="this budget" disabled={!may} detail="Spend keeps being counted, and nothing stops it." onConfirm={() => change(() => api.del(`policy/budgets/${part(b.scope)}/${part(b.name)}`))} />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>

          <Panel title="Guardrails" note="On: runs on every request, before the rule's own guardrails. Adding a guardrail is done in the raw policy.">
            {data.guardrails.length === 0 ? (
              <Empty title="No guardrails defined" body="Define one in the raw policy, for example type: secrets, then turn it on here." />
            ) : (
              <div className="grid gap-2">
                {data.guardrails.map((g) => (
                  <label key={g.name} className="t-body flex min-h-11 items-center gap-3">
                    <Switch checked={g.on} disabled={!may} onCheckedChange={(on) => change(() => api.put(`policy/guardrails/${part(g.name)}`, { on }))} />
                    <span className="t-mono">{g.name}</span>
                    <span className="text-muted-foreground">
                      {g.type}
                      {g.action ? `, ${g.action}` : ""}
                    </span>
                  </label>
                ))}
              </div>
            )}
          </Panel>

          <Panel
            title="Aliases and fallbacks"
            note="An alias is a model name callers send that Enterplace spreads over providers, trying the fallbacks in turn when they fail."
            actions={
              <Button size="sm" disabled={!may} onClick={() => setAlias("new")}>
                Add an alias
              </Button>
            }
          >
            {data.aliases.length === 0 ? (
              <Empty title="No aliases" body="Callers name a provider's model directly. Add an alias to route one name to several." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Alias</TableHead>
                    <TableHead>Sends to</TableHead>
                    <TableHead>Fallbacks</TableHead>
                    <TableHead>Change</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.aliases.map((a) => (
                    <TableRow key={a.name}>
                      <TableCell>{a.name}</TableCell>
                      <TableCell className="whitespace-normal">{a.deployments.map((d) => `${d.provider}/${d.model}`).join(", ")}</TableCell>
                      <TableCell>{a.fallbacks.join(", ") || "none"}</TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" disabled={!may} onClick={() => setAlias(a)}>
                            Edit
                          </Button>
                          <Remove what={`alias ${a.name}`} disabled={!may} detail="Callers sending this name are refused once it goes, unless a rule's model list names it otherwise." onConfirm={() => change(() => api.del(`policy/aliases/${part(a.name)}`))} />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>
        </>
      ) : null}
      {data && rule ? <RuleForm rule={rule === "new" ? null : rule} guardrails={data.guardrails} onClose={() => setRule(null)} change={change} /> : null}
      {budget ? <BudgetForm budget={budget === "new" ? null : budget} onClose={() => setBudget(null)} change={change} /> : null}
      {alias ? <AliasForm alias={alias === "new" ? null : alias} onClose={() => setAlias(null)} change={change} /> : null}
    </>
  );
}

function Actions({ onClose, label }: { onClose: () => void; label: string }) {
  return (
    <DialogFooter>
      <Button type="button" variant="outline" onClick={onClose}>
        Cancel
      </Button>
      <Button type="submit">{label}</Button>
    </DialogFooter>
  );
}

function RuleForm({ rule, guardrails, onClose, change }: { rule: Rule | null; guardrails: Guardrail[]; onClose: () => void; change: Change }) {
  const [name, setName] = useState(rule?.name ?? "");
  const [kind, setKind] = useState(rule?.who.kind ?? "team");
  const [value, setValue] = useState(rule?.who.value ?? "");
  const [models, setModels] = useState(rule?.models.join(", ") ?? "");
  const [guards, setGuards] = useState<string[]>(rule?.guardrails ?? []);
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = { name, who: { kind, value }, models: words(models), guardrails: guards };
    const answer = await change(() => (rule ? api.put(`policy/rules/${part(rule.name)}`, body) : api.post("policy/rules", body)));
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{rule ? `Edit rule ${rule.name}` : "Add a rule"}</DialogTitle>
        <DialogDescription>Who it is for, the models they may use, and the guardrails their requests pass.</DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          {rule ? null : (
            <Field id="rule-name" label="Name">
              <Input id="rule-name" className="t-mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="payments-team" required />
            </Field>
          )}
          <Field id="who" label="For">
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger id="who">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(WHO).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {kind === "any" ? null : (
            <Field id="who-value" label={kind === "name" ? "Person" : kind === "tag" ? "Tag" : "Team"}>
              <Input id="who-value" className="t-mono" value={value} onChange={(e) => setValue(e.target.value)} required />
            </Field>
          )}
          <Field id="rule-models" label="Models" hint="Separated by commas. * allows every model.">
            <Input id="rule-models" className="t-mono" value={models} onChange={(e) => setModels(e.target.value)} required />
          </Field>
          {guardrails.length ? (
            <fieldset className="grid gap-2 border-0 p-0">
              <legend className="t-tag mb-2 uppercase">Guardrails</legend>
              {guardrails.map((g) => (
                <label key={g.name} className="t-body flex min-h-11 items-center gap-3">
                  <Checkbox
                    checked={guards.includes(g.name)}
                    onCheckedChange={(on) => setGuards(on ? [...guards, g.name] : guards.filter((x) => x !== g.name))}
                  />
                  <span className="t-mono">{g.name}</span>
                </label>
              ))}
            </fieldset>
          ) : null}
          <Refusal text={refused} />
          <Actions onClose={onClose} label={rule ? "Save" : "Add rule"} />
        </form>
      </DialogContent>
    </Dialog>
  );
}

function BudgetForm({ budget, onClose, change }: { budget: Budget | null; onClose: () => void; change: Change }) {
  const [scope, setScope] = useState(budget?.scope ?? "team");
  const [name, setName] = useState(budget?.name ?? "");
  const [usd, setUsd] = useState(budget?.usd.toString() ?? "");
  const [per, setPer] = useState(budget?.per ?? "month");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const answer = await change(() => api.put("policy/budgets", { scope, name, usd, per }));
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{budget ? "Edit the budget" : "Set a budget"}</DialogTitle>
        <DialogDescription>What may be spent, in US dollars, before requests are refused until it resets.</DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          {budget ? null : (
            <>
              <Field id="scope" label="For">
                <Select value={scope} onValueChange={setScope}>
                  <SelectTrigger id="scope">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="global">Everyone together</SelectItem>
                    <SelectItem value="team">A team</SelectItem>
                    <SelectItem value="person">A person</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              {scope === "global" ? null : (
                <Field id="budget-name" label={scope === "team" ? "Team" : "Person"}>
                  <Input id="budget-name" className="t-mono" value={name} onChange={(e) => setName(e.target.value)} required />
                </Field>
              )}
            </>
          )}
          <Field id="usd" label="USD">
            <Input id="usd" type="number" min={0} step="any" className="t-mono" value={usd} onChange={(e) => setUsd(e.target.value)} required />
          </Field>
          <Field id="per" label="Resets every">
            <Select value={per} onValueChange={setPer}>
              <SelectTrigger id="per">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["hour", "day", "week", "month"].map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Refusal text={refused} />
          <Actions onClose={onClose} label="Save" />
        </form>
      </DialogContent>
    </Dialog>
  );
}

function AliasForm({ alias, onClose, change }: { alias: Alias | null; onClose: () => void; change: Change }) {
  const [name, setName] = useState(alias?.name ?? "");
  const [deployments, setDeployments] = useState(alias?.deployments.map((d) => `${d.provider}/${d.model}`).join(", ") ?? "");
  const [fallbacks, setFallbacks] = useState(alias?.fallbacks.join(", ") ?? "");
  const [refused, setRefused] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = { name, deployments: words(deployments), fallbacks: words(fallbacks) };
    const answer = await change(() => (alias ? api.put(`policy/aliases/${part(alias.name)}`, body) : api.post("policy/aliases", body)));
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{alias ? `Edit alias ${alias.name}` : "Add an alias"}</DialogTitle>
        <DialogDescription>Callers send the alias as the model. A rule's models must name it for them to use it.</DialogDescription>
        <form className="grid gap-6" onSubmit={submit}>
          {alias ? null : (
            <Field id="alias-name" label="Name">
              <Input id="alias-name" className="t-mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="smart" required />
            </Field>
          )}
          <Field id="deployments" label="Sends to" hint="provider/model, separated by commas. Requests are spread over them.">
            <Input id="deployments" className="t-mono" value={deployments} onChange={(e) => setDeployments(e.target.value)} placeholder="openai/gpt-4o" required />
          </Field>
          <Field id="fallbacks" label="Fallbacks, optional" hint="Models or aliases tried in turn when all of the above fail.">
            <Input id="fallbacks" className="t-mono" value={fallbacks} onChange={(e) => setFallbacks(e.target.value)} />
          </Field>
          <Refusal text={refused} />
          <Actions onClose={onClose} label={alias ? "Save" : "Add alias"} />
        </form>
      </DialogContent>
    </Dialog>
  );
}
