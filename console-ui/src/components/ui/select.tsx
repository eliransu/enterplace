import * as React from "react";
import { Select as SelectPrimitive } from "radix-ui";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { fieldStates } from "./input";

const Select = SelectPrimitive.Root;
const SelectValue = SelectPrimitive.Value;

// The trigger has the Input's states; while open it holds the focus look and its chevron turns over.
function SelectTrigger({
  className,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Trigger>) {
  return (
    <SelectPrimitive.Trigger
      className={cn(
        "t-body group/select flex min-h-11 w-full items-center justify-between gap-2 rounded-pill px-6 text-left data-[placeholder]:text-muted-foreground data-[state=open]:border-foreground data-[state=open]:shadow-[var(--ring-soft)]",
        fieldStates,
        className,
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon asChild>
        <ChevronDown className="size-4 flex-none transition-transform group-data-[state=open]/select:rotate-180" />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  );
}
function SelectContent({
  className,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        data-slot="select-content"
        position="popper"
        sideOffset={4}
        className={cn(
          "z-50 max-h-80 min-w-[var(--radix-select-trigger-width)] origin-[var(--radix-select-content-transform-origin)] overflow-y-auto rounded-box border border-input bg-popover p-2 text-popover-foreground",
          className,
        )}
        {...props}
      >
        <SelectPrimitive.Viewport>{children}</SelectPrimitive.Viewport>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}
// Highlighted: the hover fill. Chosen: bold with a check, as Ant's selected option reads.
function SelectItem({
  className,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      className={cn(
        "t-body relative flex min-h-11 cursor-pointer items-center justify-between gap-6 rounded-small px-4 outline-none transition-colors select-none data-[highlighted]:bg-[var(--fill-hover)] data-[state=checked]:bg-[var(--fill-selected)] data-[state=checked]:font-semibold data-[disabled]:cursor-not-allowed data-[disabled]:opacity-40",
        className,
      )}
      {...props}
    >
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
      <SelectPrimitive.ItemIndicator>
        <Check className="size-4" />
      </SelectPrimitive.ItemIndicator>
    </SelectPrimitive.Item>
  );
}

export { Select, SelectValue, SelectTrigger, SelectContent, SelectItem };
