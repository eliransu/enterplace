import { useEffect, useId, useRef, useState } from "react";
import { Input } from "./ui/input";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";
import {
  isService,
  IssueDialog,
  MadeDialog,
  type Keys,
  type Made,
} from "@/pages/People";

const NAME = /^[A-Za-z0-9._@-]+$/;

/// What a picker picks. Teams and tags exist once something names them, so "Create" only takes the new name. A
/// person or an app exists once it has a key, so "Create" opens Issue a key in place and comes back with the name
/// picked.
export type Kind = "team" | "person" | "app" | "tag" | "customer";

const NOUN: Record<Kind, string> = {
  team: "team",
  person: "person",
  app: "app",
  tag: "tag",
  customer: "customer",
};

/// An entity, picked from the ones there are with search, or made new only with an explicit "Create <kind> <name>"
/// row, so a typo never splits a team's spend or names a person no key has. `onChange` gets a name only once it is
/// picked; typed text that is neither picked nor created keeps the form from submitting. `options` adds names the
/// caller knows (a policy's tags, say) to the ones read here. `creatable={false}` offers only what exists, for
/// forms such as a kill switch that may name nothing new.
export function EntityPicker({
  kind,
  value,
  onChange,
  options: extra,
  id,
  creatable = true,
}: {
  kind: Kind;
  value: string;
  onChange: (name: string, create: boolean) => void;
  options?: string[];
  id?: string;
  creatable?: boolean;
}) {
  const fallback = useId();
  const inputId = id ?? fallback;
  const listId = `${inputId}-list`;
  const noun = NOUN[kind];
  const keyed = kind === "person" || kind === "app";
  const teams = useData<{ teams?: { name: string }[] }>(
    "teams",
    0,
    kind !== "team",
  );
  const people = useData<Keys>("people", 0, !keyed);
  const entries = people.data?.entries ?? [];
  const read =
    kind === "team"
      ? (teams.data?.teams ?? []).map((t) => t.name)
      : kind === "person"
        ? entries.filter((e) => !isService(e)).map((e) => e.name)
        : kind === "app"
          ? entries.filter(isService).map((e) => e.name)
          : [];
  const known = [...new Set([...(extra ?? []), ...read])]
    .filter(Boolean)
    .sort();
  const [text, setText] = useState(value);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  // Issue a key for a new person or app, opened from the Create row; then the key shown once.
  const [issuing, setIssuing] = useState<string | null>(null);
  const [made, setMade] = useState<Made | null>(null);
  const input = useRef<HTMLInputElement>(null);
  // What this picker last sent: only a value set from outside replaces the typed text.
  const sent = useRef(value);
  useEffect(() => {
    if (value !== sent.current) setText(value);
    sent.current = value;
  }, [value]);
  const send = (name: string, create = false) => {
    sent.current = name;
    onChange(name, create);
  };

  const typed = text.trim();
  const needle = typed.toLowerCase();
  const matches = known.filter((t) => t.toLowerCase().includes(needle));
  // "*" means each one, for a limit.
  const exact = known.includes(typed) || typed === "*";
  const mayIssue = !keyed || !!people.data?.may.issue;
  const canCreate =
    creatable && mayIssue && !exact && (!typed || NAME.test(typed));
  const options = [
    ...matches.map((t) => ({ name: t, label: t, create: false })),
    ...(canCreate
      ? [
          {
            name: typed,
            label: typed ? `Create ${noun} ${typed}` : `Create a ${noun}`,
            create: true,
          },
        ]
      : []),
  ];
  const picked = !!typed && typed === value;

  // The browser's own check keeps the form from submitting until a name is picked or created.
  useEffect(() => {
    input.current?.setCustomValidity(
      !typed || picked || exact
        ? ""
        : !NAME.test(typed)
          ? `A ${noun} is named with letters, digits, dots, dashes, underscores and @ only.`
          : creatable
            ? `Pick a ${noun} from the list, or press Create ${noun} ${typed}.`
            : `Pick a ${noun} from the list.`,
    );
  }, [typed, picked, exact, noun, creatable]);

  const pick = (name: string, create = false) => {
    setOpen(false);
    if (create && keyed) {
      setIssuing(name);
      return;
    }
    if (create && !name) {
      // "Create a team" with nothing typed: ask for the name in the field itself.
      input.current?.focus();
      return;
    }
    setText(name);
    send(name, create);
  };

  return (
    <div className="relative">
      <Input
        ref={input}
        id={inputId}
        role="combobox"
        aria-expanded={open && options.length > 0}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={
          open && options[active] ? `${listId}-${active}` : undefined
        }
        className="t-mono"
        value={text}
        placeholder={
          known.length ? `Search ${noun}s` : `No ${noun}s yet: type a name`
        }
        required
        autoComplete="off"
        onChange={(e) => {
          const next = e.target.value;
          setText(next);
          setActive(0);
          setOpen(true);
          // An existing name typed in full counts as picked; anything else waits for a pick.
          send(
            known.includes(next.trim()) || next.trim() === "*"
              ? next.trim()
              : "",
          );
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setOpen(true);
            setActive((a) => Math.min(a + 1, options.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(a - 1, 0));
          } else if (e.key === "Enter" && open && options[active]) {
            e.preventDefault();
            pick(options[active].name, options[active].create);
          } else if (e.key === "Escape" && open) {
            e.preventDefault();
            e.stopPropagation();
            setOpen(false);
          }
        }}
      />
      {open && (options.length > 0 || !creatable) ? (
        <ul
          id={listId}
          role="listbox"
          aria-label={`${noun}s`}
          className="absolute inset-x-0 top-full z-50 m-0 mt-1 grid max-h-60 list-none overflow-auto rounded-box border border-input bg-background p-1"
        >
          {options.length === 0 ? (
            <li
              role="presentation"
              className="t-body px-6 py-2 text-muted-foreground"
            >
              No {noun} matches {typed ? typed : "yet"}.
            </li>
          ) : null}
          {options.map((o, i) => (
            <li
              key={o.label}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              // mousedown, not click: the input's blur would close the list first.
              onMouseDown={(e) => {
                e.preventDefault();
                pick(o.name, o.create);
              }}
              onMouseEnter={() => setActive(i)}
              className={cn(
                "t-body cursor-pointer rounded-pill px-6 py-2",
                i === active && "bg-well",
                o.create && "t-body-strong border-t border-border",
              )}
            >
              {o.create ? `+ ${o.label}` : o.label}
            </li>
          ))}
        </ul>
      ) : null}
      {issuing !== null && people.data ? (
        <IssueDialog
          name={issuing}
          team=""
          token={false}
          service={kind === "app"}
          fullAdmin={people.data.may.full_admin}
          entries={entries}
          route="/people"
          onMade={(m) => {
            setMade(m);
            people.reload();
          }}
          close={() => setIssuing(null)}
        />
      ) : null}
      {made ? (
        <MadeDialog
          made={made}
          service={kind === "app"}
          onClose={() => {
            // Back to the form, with what was just made picked.
            setText(made.name);
            send(made.name, false);
            setMade(null);
          }}
        />
      ) : null}
    </div>
  );
}

/// The team picker of the forms that name a team.
export function TeamPicker({
  teams,
  ...props
}: {
  value: string;
  onChange: (team: string, create: boolean) => void;
  teams?: string[];
  id?: string;
}) {
  return <EntityPicker kind="team" options={teams} {...props} />;
}
