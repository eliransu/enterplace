import * as React from "react";
import { Slot } from "radix-ui";
import { LoaderCircle } from "lucide-react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

// Every button is a pill, as in the design system. One primary per view; destructive only inside a confirmation.
// The states follow Ant Design's: hover lightens or fills, a press settles back and sinks a little, focus from the
// keyboard rings it (index.css), disabled fades, and loading keeps the label's width under a spinner.
const buttonVariants = cva(
  "t-body relative inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-pill border border-transparent transition-[color,background-color,border-color,opacity,scale] active:scale-[0.98] active:duration-100 disabled:pointer-events-none [&:disabled:not([data-loading])]:opacity-40 data-loading:opacity-70 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        // Primary.
        default:
          "bg-primary text-primary-foreground hover:bg-primary-hover active:bg-primary",
        // Danger.
        destructive:
          "bg-destructive text-destructive-foreground hover:bg-destructive-hover active:bg-destructive",
        // Secondary.
        outline:
          "bg-transparent text-foreground border-input hover:border-foreground hover:bg-[var(--fill-hover)] active:bg-[var(--fill-active)]",
        // Text.
        ghost:
          "bg-transparent text-foreground hover:bg-[var(--fill-hover)] active:bg-[var(--fill-active)]",
        link: "bg-transparent text-foreground underline underline-offset-4 hover:decoration-2 active:scale-100",
      },
      size: {
        sm: "min-h-8 px-4 t-small",
        default: "min-h-11 px-6",
        lg: "min-h-12 px-8",
        icon: "size-11 p-0",
        "icon-sm": "size-8 p-0",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

// Set by the console's Form while it waits on the gateway: its submit button shows the spinner.
const FormBusy = React.createContext(false);

function Button({
  className,
  variant,
  size,
  asChild = false,
  loading = false,
  disabled,
  children,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
    loading?: boolean;
  }) {
  const formBusy = React.useContext(FormBusy);
  // A button in a form with no type is its submit button.
  const busy =
    !asChild &&
    (loading || (formBusy && (props.type ?? "submit") === "submit"));
  if (asChild)
    return (
      <Slot.Root
        data-slot="button"
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      >
        {children}
      </Slot.Root>
    );
  return (
    <button
      data-slot="button"
      data-loading={busy || undefined}
      aria-busy={busy || undefined}
      disabled={disabled || busy}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    >
      {busy ? (
        <>
          <span className="invisible inline-flex items-center gap-2">
            {children}
          </span>
          <LoaderCircle aria-hidden="true" className="absolute animate-spin" />
        </>
      ) : (
        children
      )}
    </button>
  );
}

export { Button, buttonVariants, FormBusy };
