import * as React from "react";
import { cn } from "@/lib/utils";

// shadcn's Skeleton on the tokens: a hairline-grey block that pulses while its content loads.
function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      aria-hidden="true"
      className={cn(
        "animate-pulse rounded-small bg-border motion-reduce:animate-none",
        className,
      )}
      {...props}
    />
  );
}

export { Skeleton };
