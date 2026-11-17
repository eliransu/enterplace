import * as React from "react";
import { cn } from "@/lib/utils";

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "t-body min-h-11 w-full rounded-pill border border-input bg-background px-6 text-foreground transition-colors placeholder:text-muted-foreground hover:border-foreground focus-visible:border-foreground disabled:opacity-40 aria-invalid:border-destructive",
        className,
      )}
      {...props}
    />
  );
}

export { Input };
