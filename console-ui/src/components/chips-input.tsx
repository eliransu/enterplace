import { useId, useState } from "react";
import { X } from "lucide-react";
import { Input } from "./ui/input";

/// A list of names, one chip each: Enter, a comma or a paste adds, the chip's button removes. `suggestions` are
/// offered as the name is typed. Replaces a comma-separated text field, where one long line hid typos.
export function ChipsInput({
  id,
  values,
  onChange,
  suggestions = [],
  placeholder,
}: {
  id: string;
  values: string[];
  onChange: (values: string[]) => void;
  suggestions?: string[];
  placeholder?: string;
}) {
  const [text, setText] = useState("");
  const listId = `${useId()}-suggestions`;
  const add = (raw: string) => {
    const names = raw
      .split(/[\s,]+/)
      .map((n) => n.trim())
      .filter((n) => n && !values.includes(n));
    if (names.length) onChange([...values, ...new Set(names)]);
    setText("");
  };
  return (
    <div className="grid gap-2">
      {values.length ? (
        <ul
          className="m-0 flex list-none flex-wrap gap-2 p-0"
          aria-label="Added"
        >
          {values.map((v) => (
            <li
              key={v}
              className="t-mono-sm inline-flex items-center gap-1 rounded-pill border border-input py-1 pr-1 pl-4"
            >
              {v}
              <button
                type="button"
                aria-label={`Remove ${v}`}
                className="inline-flex size-6 cursor-pointer items-center justify-center rounded-pill hover:bg-accent"
                onClick={() => onChange(values.filter((x) => x !== v))}
              >
                <X className="size-3" aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      <Input
        id={id}
        className="t-mono"
        value={text}
        list={listId}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        // The browser's own check: at least one name before the form submits.
        required={values.length === 0}
        onChange={(e) => {
          const next = e.target.value;
          // A pick from the suggestions arrives whole: add it at once.
          if (suggestions.includes(next)) add(next);
          else if (/[,\s]/.test(next)) add(next);
          else setText(next);
        }}
        onPaste={(e) => {
          e.preventDefault();
          add(e.clipboardData.getData("text"));
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter" && text.trim()) {
            e.preventDefault();
            add(text);
          } else if (e.key === "Backspace" && !text && values.length) {
            onChange(values.slice(0, -1));
          }
        }}
        onBlur={() => text.trim() && add(text)}
      />
      <datalist id={listId}>
        {suggestions
          .filter((s) => !values.includes(s))
          .map((s) => (
            <option key={s} value={s} />
          ))}
      </datalist>
    </div>
  );
}
