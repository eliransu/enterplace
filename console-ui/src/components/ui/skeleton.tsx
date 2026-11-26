import * as React from "react";
import { cn } from "@/lib/utils";

// shadcn's Skeleton on the tokens: a hairline-grey block with a light sweeping across it (index.css) while its
// content loads.
function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      aria-hidden="true"
      className={cn("rounded-small", className)}
      {...props}
    />
  );
}

export { Skeleton };
