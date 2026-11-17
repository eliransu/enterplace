import * as React from "react";
import { AlertDialog as AlertDialogPrimitive } from "radix-ui";
import { cn } from "@/lib/utils";
import { buttonVariants } from "./button";

const AlertDialog = AlertDialogPrimitive.Root;

function AlertDialogContent({ className, ...props }: React.ComponentProps<typeof AlertDialogPrimitive.Content>) {
  return (
    <AlertDialogPrimitive.Portal>
      <AlertDialogPrimitive.Overlay className="fixed inset-0 bg-overlay" />
      <AlertDialogPrimitive.Content
        className={cn(
          "fixed top-1/2 left-1/2 grid w-[calc(100%-var(--space-8))] max-w-dialog -translate-x-1/2 -translate-y-1/2 gap-6 rounded-dialog border border-input bg-background p-10 text-foreground",
          className,
        )}
        {...props}
      />
    </AlertDialogPrimitive.Portal>
  );
}
function AlertDialogTitle(props: React.ComponentProps<typeof AlertDialogPrimitive.Title>) {
  return <AlertDialogPrimitive.Title className="t-md m-0" {...props} />;
}
function AlertDialogDescription(props: React.ComponentProps<typeof AlertDialogPrimitive.Description>) {
  return <AlertDialogPrimitive.Description className="t-body m-0 text-muted-foreground" {...props} />;
}
function AlertDialogFooter(props: React.ComponentProps<"div">) {
  return <div className="flex flex-wrap justify-end gap-2" {...props} />;
}
function AlertDialogCancel({ className, ...props }: React.ComponentProps<typeof AlertDialogPrimitive.Cancel>) {
  return <AlertDialogPrimitive.Cancel className={cn(buttonVariants({ variant: "outline" }), className)} {...props} />;
}
function AlertDialogAction({ className, ...props }: React.ComponentProps<typeof AlertDialogPrimitive.Action>) {
  return <AlertDialogPrimitive.Action className={cn(buttonVariants({ variant: "destructive" }), className)} {...props} />;
}

export { AlertDialog, AlertDialogContent, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogCancel, AlertDialogAction };
