import * as React from "react";
import { cn } from "@/lib/utils";

// Ant Design's field states on the tokens: the border darkens on hover, focus adds a soft ring around it, an error
// turns both flame, disabled fades on the surface fill. Shared with Select's trigger.
const fieldStates =
  "border border-input bg-background text-foreground transition-[border-color,box-shadow] hover:border-foreground focus-visible:border-foreground focus-visible:shadow-[var(--ring-soft)] focus-visible:outline-none aria-invalid:border-destructive aria-invalid:focus-visible:shadow-[var(--ring-danger)] disabled:cursor-not-allowed disabled:bg-secondary disabled:opacity-40 disabled:hover:border-input";

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "t-body min-h-11 w-full rounded-pill px-6 placeholder:text-muted-foreground",
        fieldStates,
        className,
      )}
      {...props}
    />
  );
}

export { Input, fieldStates };
