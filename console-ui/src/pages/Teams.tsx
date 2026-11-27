import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Empty,
  Form,
  Head,
  Loading,
  Panel,
  Problem,
  Refusal,
} from "@/components/page";
import { Confirm } from "@/components/confirm";
import { EntityPicker } from "@/components/team-picker";
import { api } from "@/lib/api";
import { count, goTo, useData } from "@/lib/use";
import type { Keys } from "@/pages/People";
import type { PageProps } from "@/pages";

type Member = {
  name: string;
  sha256: string;
  hash: string;
  kind: string;
  admin: boolean;
};
type Team = {
  name: string;
  keys: string;
  owner: string | null;
  members: Member[];
  rule: string;
  budget: string;
};
type Data = {
  error?: string;
  issue: boolean;
  manage: boolean;
  teams?: Team[];
  empty: {
    title: string;
    body: string;
    action?: { label: string; href: string };
    docs: string;
  } | null;
};
type Change = (run: () => Promise<{ message: string }>) => Promise<string>;

/// People, not keys: an admin key and a person token under one name are one person.
const people = (t: Team) =>
  count(new Set(t.members.map((m) => m.name)).size, "person", "people");

/// The dialog open on the page: create a group, rename the open one, or move a person out of it.
type Open =
  | { kind: "create" }
  | { kind: "rename"; team: string }
  | { kind: "remove"; team: string; member: Member }
  | null;

export function Teams({ query }: PageProps) {
  const [open, setOpen] = useState<Open>(null);
  // Live: a key issued or a policy saved shows within the next 5 seconds. Paused while a dialog is open.
  const { data, error, reload, change } = useData<Data>("teams", 5000, !!open);
  const name = query.get("group") ?? "";
  const group = data?.teams?.find((t) => t.name === name);
  const close = () => setOpen(null);

  return (
    <>
      <Head
        title={group ? `Group ${group.name}` : "Groups"}
        lead={
          group
            ? `${people(group)}. ${group.rule === "none: refused" ? "No rule lets them in." : `Rule ${group.rule}.`} Budget and limits: ${group.budget}.`
            : "The people in each group, the rule it falls under, and its budget."
        }
        actions={
          group ? (
            <Button variant="outline" onClick={() => goTo("/teams")}>
              All groups
            </Button>
          ) : data?.manage ? (
            <Button onClick={() => setOpen({ kind: "create" })}>
              Create a group
            </Button>
          ) : null
        }
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {data?.error ? <Problem text={data.error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={4} /> : null}
      {data && name && !group && !data.error ? (
        <Panel>
          <Empty
            title={`There is no group ${name}`}
            body="Someone renamed or deleted it."
          >
            <Button variant="outline" onClick={() => goTo("/teams")}>
              All groups
            </Button>
          </Empty>
        </Panel>
      ) : null}
      {group ? (
        <GroupView
          group={group}
          manage={data?.manage ?? false}
          change={change}
          open={setOpen}
        />
      ) : null}
      {!name && data?.empty ? (
        <Panel title={data.empty.title}>
          <p className="t-body m-0 text-muted-foreground">{data.empty.body}</p>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" asChild>
              <a href={data.empty.docs}>Read the docs page</a>
            </Button>
          </div>
        </Panel>
      ) : null}
      {!name && data?.teams?.length ? (
        <Panel title={count(data.teams.length, "group")}>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-1/3">Group</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>Budget and limits</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.teams.map((t) => (
                <TableRow key={t.name}>
                  <TableCell>
                    <span
                      className="block max-w-col-md truncate"
                      title={t.name}
                    >
                      {t.name}
                    </span>
                    <span className="block text-muted-foreground">
                      {people(t)}
                      {t.owner ? `, owner ${t.owner}` : ""}
                    </span>
                  </TableCell>
                  <TableCell>{t.rule}</TableCell>
                  <TableCell className="whitespace-normal">
                    {t.budget}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => goTo("/teams", { group: t.name })}
                      >
                        Open
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      ) : null}
      {open?.kind === "create" ? (
        <NameDialog
          title="Create a group"
          detail="A group holds people. Add them once it is made; rules and limits can name it in the policy."
          action="Create group"
          initial=""
          close={close}
          send={(to) => change(() => api.post("teams", { name: to }))}
          done={(to) => goTo("/teams", { group: to })}
        />
      ) : null}
      {open?.kind === "rename" ? (
        <NameDialog
          title={`Rename group ${open.team}`}
          detail="Its people move to the new name, and so does every rule, limit and role in the policy that names the group."
          action="Rename group"
          initial={open.team}
          close={close}
          send={(to) =>
            change(() => api.post("teams/rename", { name: open.team, to }))
          }
          done={(to) => goTo("/teams", { group: to })}
        />
      ) : null}
      {open?.kind === "remove" ? (
        <RemoveDialog
          team={open.team}
          member={open.member}
          change={change}
          close={close}
        />
      ) : null}
    </>
  );
}

function GroupView({
  group,
  manage,
  change,
  open,
}: {
  group: Team;
  manage: boolean;
  change: Change;
  open: (o: Open) => void;
}) {
  return (
    <Panel
      title={people(group)}
      note="A person is always in one group: removing them from this one moves them to the group you pick. Service keys belong to apps and are not listed here."
      actions={
        manage ? (
          <>
            <Button variant="outline" size="sm" asChild>
              <a
                href={`#/policy?add=limit&team=${encodeURIComponent(group.name)}`}
              >
                {group.budget === "none" ? "Set budget" : "Change budget"}
              </a>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => open({ kind: "rename", team: group.name })}
            >
              Rename
            </Button>
            <Confirm
              label="Delete"
              title={`Delete group ${group.name}?`}
              detail="Only an empty group can be deleted, and only once no rule, limit or role in the policy names it."
              action="Delete group"
              onConfirm={async () => {
                const refused = await change(() =>
                  api.post("teams/remove", { name: group.name }),
                );
                if (!refused) goTo("/teams");
              }}
            />
          </>
        ) : null
      }
    >
      <AddPeople group={group} change={change} />
      {group.members.length === 0 ? (
        <Empty
          title="No one in this group yet"
          body="Pick people above to add them. Their key moves here from the group it was in."
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-1/3">Name</TableHead>
              <TableHead>Key hash</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {group.members.map((m) => (
              <TableRow key={m.sha256}>
                <TableCell>
                  <span className="block max-w-col-md truncate" title={m.name}>
                    {m.name}
                  </span>
                  <span className="block text-muted-foreground">{m.kind}</span>
                </TableCell>
                <TableCell>{m.hash}</TableCell>
                <TableCell>
                  <div className="flex justify-end">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        open({ kind: "remove", team: group.name, member: m })
                      }
                    >
                      Remove
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}

/// Picks a person who has a key and moves their keys (an admin key and a person token may share a name) here.
function AddPeople({ group, change }: { group: Team; change: Change }) {
  const people = useData<Keys>("people");
  const [person, setPerson] = useState("");
  const [refused, setRefused] = useState("");
  if (!people.data?.may.issue || people.data.read_only) return null;
  const keys = (people.data.entries ?? []).filter(
    (e) =>
      e.name === person && e.kind !== "workload key" && e.team !== group.name,
  );
  return (
    <Form
      className="grid gap-2"
      onSubmit={async () => {
        setRefused("");
        for (const k of keys) {
          const answer = await change(() =>
            api.post("teams/members", { name: group.name, sha256: k.sha256 }),
          );
          if (answer) {
            setRefused(answer);
            return;
          }
        }
        setPerson("");
        people.reload();
      }}
    >
      <Field id="add-person" label="Add a person">
        <div className="flex flex-wrap items-start gap-2">
          <div className="min-w-0 flex-1 sm:max-w-col-md">
            <EntityPicker
              id="add-person"
              kind="person"
              value={person}
              onChange={(n) => setPerson(n)}
              creatable={false}
            />
          </div>
          <Button type="submit" disabled={!person || keys.length === 0}>
            Add
          </Button>
        </div>
      </Field>
      {person && keys.length === 0 ? (
        <p className="t-small m-0 pl-6 text-muted-foreground">
          {person} is in this group already.
        </p>
      ) : null}
      <Refusal text={refused} />
    </Form>
  );
}

function NameDialog({
  title,
  detail,
  action,
  initial,
  close,
  send,
  done,
}: {
  title: string;
  detail: string;
  action: string;
  initial: string;
  close: () => void;
  send: (name: string) => Promise<string>;
  done: (name: string) => void;
}) {
  const [name, setName] = useState(initial);
  const [refused, setRefused] = useState("");
  return (
    <Dialog open onOpenChange={(o) => !o && close()}>
      <DialogContent>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{detail}</DialogDescription>
        <Form
          className="grid gap-6"
          onSubmit={async () => {
            const answer = await send(name.trim());
            if (answer) setRefused(answer);
            else {
              close();
              done(name.trim());
            }
          }}
        >
          <Field
            id="group-name"
            label="Group name"
            hint="Letters, digits, dots, dashes, underscores and @, for example design."
          >
            <Input
              id="group-name"
              className="t-mono"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              autoFocus
              autoComplete="off"
              aria-invalid={!!refused}
            />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!name.trim() || name.trim() === initial}
            >
              {action}
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function RemoveDialog({
  team,
  member,
  change,
  close,
}: {
  team: string;
  member: Member;
  change: Change;
  close: () => void;
}) {
  const [to, setTo] = useState("");
  const [refused, setRefused] = useState("");
  return (
    <Dialog open onOpenChange={(o) => !o && close()}>
      <DialogContent>
        <DialogTitle>
          Remove {member.name} from {team}?
        </DialogTitle>
        <DialogDescription>
          A person is always in one group. Pick the group {member.name} moves
          to: the rule and budget of that group apply to them within 2 seconds.
        </DialogDescription>
        <Form
          className="grid gap-6"
          onSubmit={async () => {
            const answer = await change(() =>
              api.post("teams/members", { name: to, sha256: member.sha256 }),
            );
            if (answer) setRefused(answer);
            else close();
          }}
        >
          <Field id="move-to" label="Move to group">
            <EntityPicker
              id="move-to"
              kind="team"
              value={to}
              onChange={(n) => setTo(n)}
              creatable={false}
            />
          </Field>
          <Refusal text={refused} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" disabled={!to || to === team}>
              Remove from {team}
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
