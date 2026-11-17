import * as React from "react";
import { Dialog as DialogPrimitive } from "radix-ui";
import { cn } from "@/lib/utils";

// Flat: the scrim separates the dialog, not a shadow.
const Dialog = DialogPrimitive.Root;
const DialogClose = DialogPrimitive.Close;

function DialogContent({ className, children, ...props }: React.ComponentProps<typeof DialogPrimitive.Content>) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 bg-overlay" />
      <DialogPrimitive.Content
        className={cn(
          "fixed top-1/2 left-1/2 grid max-h-[90vh] w-[calc(100%-var(--space-8))] max-w-dialog -translate-x-1/2 -translate-y-1/2 grid-cols-[minmax(0,1fr)] gap-6 overflow-y-auto rounded-dialog border border-input bg-background p-10 text-foreground",
          className,
        )}
        {...props}
      >
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}
function DialogTitle({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Title>) {
  return <DialogPrimitive.Title className={cn("t-md m-0", className)} {...props} />;
}
function DialogDescription({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Description>) {
  return <DialogPrimitive.Description className={cn("t-body m-0 text-muted-foreground", className)} {...props} />;
}
function DialogFooter({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("flex flex-wrap justify-end gap-2", className)} {...props} />;
}

export { Dialog, DialogClose, DialogContent, DialogTitle, DialogDescription, DialogFooter };
