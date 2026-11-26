import * as React from "react";
import { Dialog as DialogPrimitive } from "radix-ui";
import { cn } from "@/lib/utils";

// shadcn's Sheet, right side only: a dialog that slides in beside the list, so the row stays in view.
const Sheet = DialogPrimitive.Root;

function SheetContent({
  className,
  children,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Content>) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-overlay" />
      <DialogPrimitive.Content
        className={cn(
          "fixed inset-y-0 right-0 z-50 grid w-full max-w-wide content-start grid-cols-[minmax(0,1fr)] gap-6 overflow-y-auto border-l border-input bg-background p-10 text-foreground",
          className,
        )}
        {...props}
      >
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}
function SheetTitle({
  className,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Title>) {
  return (
    <DialogPrimitive.Title className={cn("t-md m-0", className)} {...props} />
  );
}
function SheetDescription({
  className,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      className={cn("t-body m-0 text-muted-foreground", className)}
      {...props}
    />
  );
}

export { Sheet, SheetContent, SheetTitle, SheetDescription };
