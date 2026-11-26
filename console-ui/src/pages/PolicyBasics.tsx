import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Empty, Head, Panel, Problem, Refusal, Form, Loading } from "@/components/page";
import { Remove } from "@/components/confirm";
import { Copy } from "@/components/copy";
import { TeamPicker } from "@/components/team-picker";
import { api, part } from "@/lib/api";
import { useData, words } from "@/lib/use";
import type { PageProps } from "@/pages";

type Rule = { name: string; who: { kind: string; value: string }; models: string[]; guardrails: string[] };
type Entry = Record<string, unknown>;
type Limit = { index: number; entry: Entry };
type Guardrail = { name: string; type: string; action: string | null; on: boolean; entry: Entry };
type Alias = { name: string; deployments: { provider: string; model: string }[]; fallbacks: string[] };
type Data = { mode: string; rules: Rule[]; limits: Limit[]; guardrails: Guardrail[]; aliases: Alias[]; guard_agent: string; limit_agent: string };
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

const WHO: Record<string, string> = { any: "Everyone", team: "A team", name: "A person", tag: "A tag" };
const who = (r: Rule) => (r.who.kind === "any" ? "everyone" : r.who.kind === "other" ? "see the raw policy" : `${r.who.kind === "name" ? "person" : r.who.kind} ${r.who.value}`);

/// The confirmation before enforcing: the switch on Rules and limits and the observe-mode banner on every page open
/// this same dialog.
export function EnforceDialog({ open, onOpenChange, onConfirm }: { open: boolean; onOpenChange: (open: boolean) => void; onConfirm: () => void }) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogTitle>Turn on enforcement?</AlertDialogTitle>
        <AlertDialogDescription>
          Rules, limits and guardrails then refuse what the policy does not allow, instead of only recording it. Every gateway follows within 2 seconds. What observe mode only recorded is refused from now on: the Audit log shows those requests.
        </AlertDialogDescription>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>Turn on enforcement</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function PolicyBasics({ me, query }: PageProps) {
  const { data, error, change, reload } = useData<Data>("policy");
  const [observing, setObserving] = useState(false);
  const [enforcing, setEnforcing] = useState(false);
  const [rule, setRule] = useState<Rule | "new" | null>(null);
  const [limit, setLimit] = useState<Limit | "new" | null>(null);
  const [guard, setGuard] = useState<Guardrail | "new" | null>(null);
  const [alias, setAlias] = useState<Alias | "new" | null>(null);
  const [testing, setTesting] = useState<Guardrail | null>(null);
  const may = !!me?.edit_policy;
  // `?add=limit&team=payments` (from Overview, Spend and Teams) opens that team's limit, or Add a limit filled in
  // for it; `?at=limits` scrolls to Limits. Once per visit, so a reload of the data does not reopen it.
  const [prefill, setPrefill] = useState("");
  const opened = useRef(false);
  useEffect(() => {
    if (!data || opened.current) return;
    opened.current = true;
    const add = query.get("add") === "limit";
    if (add && may) {
      const team = query.get("team") ?? "";
      const own = team ? data.limits.find((l) => l.entry.team === team && l.entry.org === undefined) : undefined;
      setPrefill(team);
      setLimit(own ?? "new");
    }
    if (add || query.get("at") === "limits") document.getElementById("limits")?.scrollIntoView();
  }, [data, query, may]);
  const closeLimit = () => {
    setLimit(null);
    setPrefill("");
    if (query.get("add")) window.history.replaceState(null, "", "#/policy");
  };
  return (
    <>
      <Head
        title="Rules and limits"
        lead="Who may use which models, what they may spend, which guardrails run, and where requests go."
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={6} /> : null}
      {data ? (
        <>
          <Panel title="Mode">
            <label className="t-body flex items-center gap-3">
              <Switch
                checked={data.mode === "enforce"}
                disabled={!may}
                onCheckedChange={(on) => (on ? setEnforcing(true) : setObserving(true))}
              />
              {data.mode === "enforce" ? "Enforce: what the policy does not allow is refused." : "Observe: rules, limits and guardrails only record what they would refuse. A request without a valid key or person token, an unknown model and a kill switch are still refused."}
            </label>
            <EnforceDialog open={enforcing} onOpenChange={setEnforcing} onConfirm={() => change(() => api.put("policy/mode", { mode: "enforce" }))} />
            <AlertDialog open={observing} onOpenChange={setObserving}>
              <AlertDialogContent>
                <AlertDialogTitle>Stop enforcing the policy?</AlertDialogTitle>
                <AlertDialogDescription>
                  In observe mode rules, limits and guardrails only record what they would refuse. A request without a valid key or person token, an unknown model and a kill switch are still refused. Every gateway follows within 2 seconds.
                </AlertDialogDescription>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={() => change(() => api.put("policy/mode", { mode: "observe" }))}>Switch to observe</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
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

          <div id="limits" className="grid">
          <Panel
            title="Limits"
            note="Budgets in US dollars, request and token rates, and requests in flight, for everyone or one scope. A request counts against every limit that applies to it."
            actions={
              <>
                <Copy text={data.limit_agent} label="Copy for your agent" />
                <Button size="sm" disabled={!may} onClick={() => setLimit("new")}>
                  Add a limit
                </Button>
              </>
            }
          >
            {data.limits.length === 0 ? (
              <Empty title="No limits" body="Spend is counted but nothing stops it. Add a budget for everyone, a team or a person, or a rate for a key." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>For</TableHead>
                    <TableHead>Budget</TableHead>
                    <TableHead>Rate</TableHead>
                    <TableHead className="text-right">Parallel</TableHead>
                    <TableHead>Change</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.limits.map((l) => (
                    <TableRow key={l.index}>
                      <TableCell>{limitScope(l.entry)}</TableCell>
                      <TableCell>{limitBudget(l.entry)}</TableCell>
                      <TableCell>{limitRate(l.entry)}</TableCell>
                      <TableCell className="text-right tabular-nums">{String(l.entry.parallel ?? "none")}</TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" disabled={!may} onClick={() => setLimit(l)}>
                            Edit
                          </Button>
                          <Remove
                            what="this limit"
                            disabled={!may}
                            detail="What it capped is no longer capped by it. Spend keeps being counted."
                            onConfirm={() => change(() => api.del(`policy/limits/${l.index}`, { was: l.entry }))}
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>
          </div>

          <Panel
            title="Guardrails"
            note="On: runs on every request, before the rule's own guardrails. Off: runs only for rules that name it. To try one before it refuses anything, set Try first until on it: until that day what it would block shows as Would block in the Audit log."
            actions={
              <>
                <Copy text={data.guard_agent} label="Copy for your agent" />
                <Button size="sm" disabled={!may} onClick={() => setGuard("new")}>
                  Add a guardrail
                </Button>
              </>
            }
          >
            {data.guardrails.length === 0 ? (
              <Empty title="No guardrails" body="Add one, for example type secrets to block API keys and passwords in prompts." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>On</TableHead>
                    <TableHead>Guardrail</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Change</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.guardrails.map((g) => (
                    <TableRow key={g.name}>
                      <TableCell>
                        <Switch
                          aria-label={`Run ${g.name} on every request`}
                          checked={g.on}
                          disabled={!may}
                          onCheckedChange={(on) => change(() => api.put(`policy/guardrails/${part(g.name)}/on`, { on }))}
                        />
                      </TableCell>
                      <TableCell>{g.name}</TableCell>
                      <TableCell>{g.type}</TableCell>
                      <TableCell>
                        {g.action ?? "block"}
                        {trying(g) ? <span className="text-muted-foreground">, trying until {trying(g)}</span> : null}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" onClick={() => setTesting(g)}>
                            Test
                          </Button>
                          <Button variant="outline" size="sm" disabled={!may} onClick={() => setGuard(g)}>
                            Edit
                          </Button>
                          <Remove
                            what={`guardrail ${g.name}`}
                            disabled={!may}
                            detail="It stops running, and the rules that named it no longer do."
                            onConfirm={() => change(() => api.del(`policy/guardrails/${part(g.name)}`))}
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
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
      {limit ? <LimitForm limit={limit === "new" ? null : limit} team={prefill} onClose={closeLimit} change={change} /> : null}
      {guard ? <GuardForm guard={guard === "new" ? null : guard} onClose={() => setGuard(null)} change={change} /> : null}
      {testing ? <GuardTest guard={testing} onClose={() => setTesting(null)} /> : null}
      {alias ? <AliasForm alias={alias === "new" ? null : alias} onClose={() => setAlias(null)} change={change} /> : null}
    </>
  );
}

/// The day a guardrail on trial starts to act, while that day is still ahead.
const trying = (g: Guardrail) => {
  const until = typeof g.entry.shadow_until === "string" ? g.entry.shadow_until.slice(0, 10) : "";
  return until && until > new Date().toISOString().slice(0, 10) ? until : "";
};

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
        <Form className="grid gap-6" onSubmit={submit}>
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
        </Form>
      </DialogContent>
    </Dialog>
  );
}

const SCOPES: Record<string, string> = {
  global: "Everyone together",
  org: "An organization",
  team: "A team",
  person: "A person",
  key: "A key (first 8 hex of its hash)",
  customer: "An end customer",
  tag: "A tag",
  model: "A model",
  model_group: "A model group",
};
const RATES = [
  ["rpm", "Requests per minute"],
  ["rph", "Requests per hour"],
  ["rpd", "Requests per day"],
  ["tpm", "Tokens per minute"],
  ["tpd", "Tokens per day"],
] as const;

function scopeOf(e: Entry): [string, string] {
  if (e.global === true) return ["global", ""];
  for (const k of Object.keys(SCOPES)) if (k !== "global" && k !== "org" && e[k] !== undefined) return [k, String(e[k])];
  return e.org !== undefined ? ["org", String(e.org)] : ["global", ""];
}
function limitScope(e: Entry) {
  const [k, v] = scopeOf(e);
  const base = k === "global" ? "everyone together" : `${k.replace("_", " ")} ${v}`;
  return k !== "org" && e.org !== undefined ? `${base} in ${String(e.org)}` : base;
}
function budgetOf(e: Entry): { usd: unknown; per: unknown } | null {
  const b = e.budget;
  if (b && typeof b === "object" && !Array.isArray(b)) return b as { usd: unknown; per: unknown };
  return null;
}
function limitBudget(e: Entry) {
  if (Array.isArray(e.budget)) return `${e.budget.length} budgets, see the raw policy`;
  const b = budgetOf(e);
  return b ? `$${String(b.usd)} a ${typeof b.per === "string" ? b.per : "window"}` : "none";
}
function limitRate(e: Entry) {
  const r = (e.rate ?? {}) as Record<string, unknown>;
  const parts = RATES.filter(([k]) => r[k] !== undefined).map(([k]) => `${String(r[k])} ${k}`);
  return parts.join(", ") || "none";
}

function LimitForm({ limit, team, onClose, change }: { limit: Limit | null; team: string; onClose: () => void; change: Change }) {
  const e = limit?.entry ?? {};
  const [scope0, value0] = scopeOf(e);
  const b = budgetOf(e);
  const r = (e.rate ?? {}) as Record<string, unknown>;
  const [scope, setScope] = useState(limit ? scope0 : "team");
  const [value, setValue] = useState(limit ? value0 : team);
  // A team no key names yet is only taken when picked as Create team: the server refuses it otherwise.
  const [create, setCreate] = useState(false);
  const [org, setOrg] = useState(scope0 !== "org" && e.org !== undefined ? String(e.org) : "");
  const [usd, setUsd] = useState(b ? String(b.usd) : "");
  const [per, setPer] = useState(b && typeof b.per === "string" ? b.per : "month");
  const [rates, setRates] = useState<Record<string, string>>(Object.fromEntries(RATES.map(([k]) => [k, r[k] === undefined ? "" : String(r[k])])));
  const [parallel, setParallel] = useState(e.parallel === undefined ? "" : String(e.parallel));
  const [refused, setRefused] = useState("");
  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    const body = { scope, value, org, usd, per, parallel, create, ...rates, ...(limit ? { was: limit.entry } : {}) };
    const answer = await change(() => (limit ? api.put(`policy/limits/${limit.index}`, body) : api.post("policy/limits", body)));
    if (answer) setRefused(answer);
    else onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{limit ? "Edit the limit" : "Add a limit"}</DialogTitle>
        <DialogDescription>Fill in what to cap. Leave a field empty for no cap on it.</DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field id="scope" label="For">
            <Select value={scope} onValueChange={setScope}>
              <SelectTrigger id="scope">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(SCOPES).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {scope === "global" ? null : (
            <Field id="scope-value" label="Name" hint={'"*" sets the same limit for each one.'}>
              {scope === "team" ? (
                <TeamPicker
                  id="scope-value"
                  value={value}
                  onChange={(v, made) => {
                    setValue(v);
                    setCreate(made);
                  }}
                />
              ) : (
                <Input id="scope-value" className="t-mono" value={value} onChange={(ev) => setValue(ev.target.value)} required />
              )}
            </Field>
          )}
          {scope === "global" || scope === "org" ? null : (
            <Field id="org" label="Only in organization, optional">
              <Input id="org" className="t-mono" value={org} onChange={(ev) => setOrg(ev.target.value)} />
            </Field>
          )}
          <div className="grid gap-4 md:grid-cols-2">
            <Field id="usd" label="Budget, USD">
              <Input id="usd" type="number" min={0} step="any" className="t-mono" value={usd} onChange={(ev) => setUsd(ev.target.value)} />
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
            {RATES.map(([k, label]) => (
              <Field key={k} id={k} label={label}>
                <Input id={k} type="number" min={1} step={1} className="t-mono" value={rates[k]} onChange={(ev) => setRates({ ...rates, [k]: ev.target.value })} />
              </Field>
            ))}
            <Field id="parallel" label="Requests in flight">
              <Input id="parallel" type="number" min={1} step={1} className="t-mono" value={parallel} onChange={(ev) => setParallel(ev.target.value)} />
            </Field>
          </div>
          <Refusal text={refused} />
          <Actions onClose={onClose} label="Save" />
        </Form>
      </DialogContent>
    </Dialog>
  );
}

const GUARD_TYPES = [
  "secrets", "pii", "regex", "keywords", "webhook", "openai_moderation", "presidio", "lakera", "bedrock_guardrail",
  "azure_content_safety", "azure_prompt_shield", "llama_guard", "model_armor", "pangea", "nemo_guardrails", "hiddenlayer",
  "lasso", "guardrails_ai", "aporia", "prisma_airs", "enkrypt", "grayswan", "cisco_ai_defense", "mistral_moderation",
  "judge", "transform", "events",
];
const FORM_KEYS = ["name", "type", "action", "shadow_until", "on", "url", "key_env", "model", "timeout_ms", "on_failure", "patterns", "keywords", "region"];

function GuardForm({ guard, onClose, change }: { guard: Guardrail | null; onClose: () => void; change: Change }) {
  const e = guard?.entry ?? {};
  const str = (k: string) => (e[k] === undefined ? "" : String(e[k]));
  const map = (k: string, join: (v: unknown) => string) =>
    Object.entries((e[k] ?? {}) as Record<string, unknown>)
      .map(([n, v]) => `${n}: ${join(v)}`)
      .join("\n");
  const other = Object.entries(e)
    .filter(([k, v]) => !FORM_KEYS.includes(k) && typeof v !== "object")
    .map(([k, v]) => `${k}: ${String(v)}`)
    .join("\n");
  const sides = Array.isArray(e.on) ? (e.on as string[]) : ["request"];
  const [name, setName] = useState(guard?.name ?? "");
  const [type, setType] = useState(str("type") || "secrets");
  const [action, setAction] = useState(str("action") || "block");
  const [on, setOn] = useState<string[]>(sides);
  const [every, setEvery] = useState(true);
  const [fields, setFields] = useState<Record<string, string>>({
    url: str("url"),
    key_env: str("key_env"),
    model: str("model"),
    region: str("region"),
    shadow_until: str("shadow_until").slice(0, 10),
    timeout_ms: str("timeout_ms"),
    on_failure: str("on_failure"),
    patterns: map("patterns", String),
    keywords: map("keywords", (v) => (Array.isArray(v) ? v.join(", ") : String(v))),
    settings: other,
  });
  const [refused, setRefused] = useState("");
  const set = (k: string) => (ev: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setFields({ ...fields, [k]: ev.target.value });
  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    const body = { name, type, action, on, ...fields, ...(guard ? {} : { every }) };
    const answer = await change(() => (guard ? api.put(`policy/guardrails/${part(guard.name)}`, body) : api.post("policy/guardrails", body)));
    if (answer) setRefused(answer);
    else onClose();
  };
  const area = "t-mono min-h-24 w-full rounded-box border border-input bg-background px-6 py-3 text-foreground hover:border-foreground";
  const service = !["secrets", "pii", "regex", "keywords"].includes(type);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{guard ? `Edit guardrail ${guard.name}` : "Add a guardrail"}</DialogTitle>
        <DialogDescription>A detector requests or answers pass through. The check names any setting its type still needs.</DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          {guard ? null : (
            <Field id="guard-name" label="Name">
              <Input id="guard-name" className="t-mono" value={name} onChange={(ev) => setName(ev.target.value)} placeholder="no-secrets" required />
            </Field>
          )}
          <Field id="guard-type" label="Type">
            <Select value={type} onValueChange={setType}>
              <SelectTrigger id="guard-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {GUARD_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field id="guard-action" label="Action" hint="Block refuses, mask replaces each finding and forwards, warn forwards and records.">
            <Select value={action} onValueChange={setAction}>
              <SelectTrigger id="guard-action">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["block", "mask", "warn"].map((a) => (
                  <SelectItem key={a} value={a}>
                    {a}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field
            id="guard-shadow"
            label="Try first until, optional"
            hint="Until this day (UTC) it records what it would do, shown as Would block in the Audit log, and blocks or masks nothing. Empty: it acts now."
          >
            <Input id="guard-shadow" type="date" className="t-mono" value={fields.shadow_until} onChange={set("shadow_until")} />
          </Field>
          <fieldset className="grid gap-2 border-0 p-0">
            <legend className="t-tag mb-2 uppercase">Checks</legend>
            {["request", "answer"].map((side) => (
              <label key={side} className="t-body flex min-h-11 items-center gap-3">
                <Checkbox checked={on.includes(side)} onCheckedChange={(c) => setOn(c ? [...on, side] : on.filter((x) => x !== side))} />
                The {side}
              </label>
            ))}
          </fieldset>
          {guard ? null : (
            <label className="t-body flex min-h-11 items-center gap-3">
              <Checkbox checked={every} onCheckedChange={(c) => setEvery(c === true)} />
              Run it on every request. Off: it runs only for the rules that name it.
            </label>
          )}
          {type === "regex" ? (
            <Field id="patterns" label="Patterns" hint="One per line: name: regular expression. The name is the finding's kind.">
              <textarea id="patterns" className={area} value={fields.patterns} onChange={set("patterns")} placeholder="card: \b\d{16}\b" />
            </Field>
          ) : null}
          {type === "keywords" ? (
            <Field id="keywords" label="Word lists" hint="One per line: name: word, phrase, word.">
              <textarea id="keywords" className={area} value={fields.keywords} onChange={set("keywords")} placeholder="projects: atlas, blue harbor" />
            </Field>
          ) : null}
          {service ? (
            <>
              <Field id="guard-url" label="URL, if the service needs one">
                <Input id="guard-url" className="t-mono" value={fields.url} onChange={set("url")} />
              </Field>
              <Field id="guard-key" label="Environment variable with its key" hint="The value never goes in the policy.">
                <Input id="guard-key" className="t-mono" value={fields.key_env} onChange={set("key_env")} />
              </Field>
              <Field id="guard-model" label="Model, for a model that checks">
                <Input id="guard-model" className="t-mono" value={fields.model} onChange={set("model")} />
              </Field>
              <div className="grid gap-4 md:grid-cols-2">
                <Field id="guard-timeout" label="Timeout, ms">
                  <Input id="guard-timeout" type="number" min={1} className="t-mono" value={fields.timeout_ms} onChange={set("timeout_ms")} />
                </Field>
                <Field id="guard-failure" label="When it cannot be reached">
                  <Select value={fields.on_failure || "fail_closed"} onValueChange={(v) => setFields({ ...fields, on_failure: v })}>
                    <SelectTrigger id="guard-failure">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="fail_closed">Refuse the request</SelectItem>
                      <SelectItem value="fail_open">Let it through, recorded</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
              </div>
              <Field id="guard-region" label="Region, for a cloud service">
                <Input id="guard-region" className="t-mono" value={fields.region} onChange={set("region")} />
              </Field>
            </>
          ) : null}
          <Field id="guard-settings" label="Other settings, optional" hint="One per line: setting: value, for the type's own settings such as guardrail_id or threshold.">
            <textarea id="guard-settings" className={area} value={fields.settings} onChange={set("settings")} />
          </Field>
          <Refusal text={refused} />
          <Actions onClose={onClose} label={guard ? "Save" : "Add guardrail"} />
        </Form>
      </DialogContent>
    </Dialog>
  );
}

/// Runs the guardrail over a sample typed here. Nothing is sent to a model or kept; the answer names what it found.
function GuardTest({ guard, onClose }: { guard: Guardrail; onClose: () => void }) {
  const [sample, setSample] = useState("");
  const [said, setSaid] = useState<{ message: string; masked: { kind: string; masked: string }[] } | null>(null);
  const [refused, setRefused] = useState("");
  const submit = async () => {
    setRefused("");
    try {
      setSaid((await api.post(`policy/guardrails/${part(guard.name)}/test`, { text: sample })) as unknown as NonNullable<typeof said>);
    } catch (e) {
      setSaid(null);
      setRefused(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>Test guardrail {guard.name}</DialogTitle>
        <DialogDescription>Paste a prompt it should catch, or one it should let through. Nothing is sent to a model or kept.</DialogDescription>
        <Form className="grid gap-6" onSubmit={submit}>
          <Field id="guard-sample" label="Sample prompt">
            <textarea
              id="guard-sample"
              className="t-mono min-h-24 w-full rounded-box border border-input bg-background px-6 py-3 text-foreground hover:border-foreground"
              value={sample}
              onChange={(e) => setSample(e.target.value)}
              placeholder="Deploy with AKIAIOSFODNN7EXAMPLE"
              required
            />
          </Field>
          {said ? (
            <div role="status" className="grid gap-2 rounded-box bg-well px-6 py-3">
              <span className="t-body">{said.message}</span>
              {said.masked.map((m, i) => (
                <span key={i} className="t-mono-sm">
                  {m.kind}: {m.masked}
                </span>
              ))}
            </div>
          ) : null}
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Close
            </Button>
            <Button type="submit">Test</Button>
          </DialogFooter>
        </Form>
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
        <Form className="grid gap-6" onSubmit={submit}>
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
        </Form>
      </DialogContent>
    </Dialog>
  );
}
