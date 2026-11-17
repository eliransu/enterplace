import { useState } from "react";
import { Button } from "./ui/button";

// Copies a value shown once (a new key, the lines for a tool). Without the Clipboard API (plain http from another
// machine) a selected textarea and execCommand copy instead, as the server-rendered pages do.
export function Copy({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    setDone(true);
    window.setTimeout(() => setDone(false), 1500);
  };
  return (
    <Button type="button" variant="outline" size="sm" onClick={copy} data-copy>
      {done ? "Copied" : label}
    </Button>
  );
}
