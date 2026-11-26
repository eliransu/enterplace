import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useData } from "@/lib/use";

/// A team: one of the teams that exist, or a new one only through an explicit "Create team <name>" row, so a typo
/// never makes a team. `onChange` gets the name and whether it is a team to create. `teams` defaults to the Teams list.
export function TeamPicker({
  id,
  value,
  onChange,
  teams,
}: {
  id?: string;
  value: string;
  onChange: (team: string, create: boolean) => void;
  teams?: string[];
}) {
  const listed = useData<{ teams?: { name: string }[] }>("teams");
  const known = teams ?? (listed.data?.teams ?? []).map((t) => t.name);
  const [create, setCreate] = useState(false);
  const typed = value.trim();
  const isNew = typed !== "" && typed !== "*" && !known.includes(typed);
  const list = `${id ?? "team"}-teams`;
  return (
    <div className="grid gap-2">
      <Input
        id={id}
        className="t-mono"
        list={list}
        value={value}
        onChange={(e) => {
          setCreate(false);
          onChange(e.target.value, false);
        }}
        autoComplete="off"
        required
      />
      <datalist id={list}>
        {known.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      {isNew ? (
        create ? (
          <span className="t-small pl-6 text-muted-foreground">
            New team {typed}: made when you save.
          </span>
        ) : (
          <div className="flex flex-wrap items-center gap-2 pl-6">
            <span className="t-small text-muted-foreground">
              No team {typed} yet.
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                setCreate(true);
                onChange(typed, true);
              }}
            >
              Create team {typed}
            </Button>
          </div>
        )
      ) : null}
    </div>
  );
}
