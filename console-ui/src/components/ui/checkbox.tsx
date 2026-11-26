import * as React from "react";
import { Checkbox as CheckboxPrimitive } from "radix-ui";
import { cn } from "@/lib/utils";

// A checked choice holds a disc, as the console's Choice does.
function Checkbox({
  className,
  ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      className={cn(
        "grid size-6 shrink-0 place-content-center rounded-small border border-input bg-background transition-colors hover:border-foreground data-[state=checked]:border-primary data-[state=checked]:bg-primary disabled:cursor-not-allowed disabled:opacity-40",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator className="block size-2 rounded-pill bg-primary-foreground" />
    </CheckboxPrimitive.Root>
  );
}

export { Checkbox };
