import * as React from "react";
import { cn } from "@/lib/utils";

// The console's Tag: quiet by default, uppercase.
function Badge({ className, ...props }: React.ComponentProps<"span">) {
  return (
    <span
      className={cn("t-tag inline-flex min-h-7 items-center gap-2 rounded-pill border border-input px-3 whitespace-nowrap uppercase", className)}
      {...props}
    />
  );
}

export { Badge };
