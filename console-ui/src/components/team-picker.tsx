import { useEffect, useId, useRef, useState } from "react";
import { Input } from "./ui/input";
import { useData } from "@/lib/use";
import { cn } from "@/lib/utils";

const NAME = /^[A-Za-z0-9._@-]+$/;

/// A team, picked from the teams there are, or made new only with an explicit "Create team <name>" row, so a typo
/// never splits a team's spend. `onChange` gets a team only once it is picked; typed text that is neither picked nor
/// created keeps the form from submitting. The teams are the Teams page's, plus any in `teams`.
export function TeamPicker({
  value,
  onChange,
  teams,
  id,
}: {
  value: string;
  onChange: (team: string) => void;
  teams?: string[];
  id?: string;
}) {
  const fallback = useId();
  const inputId = id ?? fallback;
  const listId = `${inputId}-list`;
  const { data } = useData<{ teams?: { name: string }[] }>("teams");
  const known = [
    ...new Set([...(teams ?? []), ...(data?.teams ?? []).map((t) => t.name)]),
  ].sort();
  const [text, setText] = useState(value);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  // What this picker last sent: only a value set from outside replaces the typed text.
  const sent = useRef(value);
  useEffect(() => {
    if (value !== sent.current) setText(value);
    sent.current = value;
  }, [value]);
  const send = (team: string) => {
    sent.current = team;
    onChange(team);
  };

  const typed = text.trim();
  const needle = typed.toLowerCase();
  const matches = known.filter((t) => t.toLowerCase().includes(needle));
  const exact = known.includes(typed);
  const canCreate = !!typed && !exact && NAME.test(typed);
  const options = [
    ...matches.map((t) => ({ team: t, label: t })),
    ...(canCreate ? [{ team: typed, label: `Create team ${typed}` }] : []),
  ];
  const picked = !!typed && typed === value;

  // The browser's own check keeps the form from submitting until the team is picked or created.
  useEffect(() => {
    input.current?.setCustomValidity(
      !typed || picked || exact
        ? ""
        : NAME.test(typed)
          ? `Pick a team from the list, or press Create team ${typed}.`
          : "A team is named with letters, digits, dots, dashes, underscores and @ only.",
    );
  }, [typed, picked, exact]);

  const pick = (team: string) => {
    setText(team);
    send(team);
    setOpen(false);
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
        required
        autoComplete="off"
        onChange={(e) => {
          const next = e.target.value;
          setText(next);
          setActive(0);
          setOpen(true);
          // An existing team typed in full counts as picked; anything else waits for a pick.
          send(known.includes(next.trim()) ? next.trim() : "");
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
            pick(options[active].team);
          } else if (e.key === "Escape" && open) {
            e.preventDefault();
            e.stopPropagation();
            setOpen(false);
          }
        }}
      />
      {open && options.length > 0 ? (
        <ul
          id={listId}
          role="listbox"
          className="absolute inset-x-0 top-full z-50 m-0 mt-1 grid max-h-60 list-none overflow-auto rounded-box border border-input bg-background p-1"
        >
          {options.map((o, i) => (
            <li
              key={o.label}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              // mousedown, not click: the input's blur would close the list first.
              onMouseDown={(e) => {
                e.preventDefault();
                pick(o.team);
              }}
              onMouseEnter={() => setActive(i)}
              className={cn(
                "t-body cursor-pointer rounded-pill px-6 py-2",
                i === active && "bg-well",
                o.label !== o.team && "t-body-strong",
              )}
            >
              {o.label}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
