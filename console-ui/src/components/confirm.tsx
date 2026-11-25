import * as React from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogTitle,
} from "./ui/alert-dialog";
import { Button } from "./ui/button";

// A change that ends or stops something asks first, naming the thing. The flame button lives only here.
export function Confirm({
  label,
  title,
  detail,
  action = label,
  onConfirm,
  disabled,
  variant = "outline",
}: {
  label: string;
  title: string;
  detail: React.ReactNode;
  action?: string;
  onConfirm: () => void;
  disabled?: boolean;
  variant?: "outline" | "default";
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <Button
        variant={variant}
        size="sm"
        disabled={disabled}
        onClick={() => setOpen(true)}
      >
        {label}
      </Button>
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{detail}</AlertDialogDescription>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={onConfirm}>{action}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

export function Remove({
  what,
  detail,
  onConfirm,
  disabled,
}: {
  what: string;
  detail: string;
  onConfirm: () => void;
  disabled?: boolean;
}) {
  return (
    <Confirm
      label="Remove"
      title={`Remove ${what}?`}
      detail={detail}
      onConfirm={onConfirm}
      disabled={disabled}
    />
  );
}
