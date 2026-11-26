import * as React from "react";
import { Label } from "./label";

// A labelled control with its hint under it, as the console's Field component lays it out.
function Field({ id, label, hint, children }: { id: string; label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div data-field className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint ? <span className="t-small pl-6 text-muted-foreground">{hint}</span> : null}
    </div>
  );
}

export { Field };
