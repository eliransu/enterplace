import * as React from "react";
import { Slot } from "radix-ui";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

// Every button is a pill, as in the design system. One primary per view; destructive only inside a confirmation.
const buttonVariants = cva(
  "t-body inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-pill border border-transparent transition-colors disabled:pointer-events-none disabled:opacity-40 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary-hover",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive-hover",
        outline: "bg-transparent text-foreground border-input hover:border-foreground",
        ghost: "bg-transparent text-foreground hover:bg-accent",
        link: "bg-transparent text-foreground underline underline-offset-4",
      },
      size: {
        default: "min-h-11 px-6",
        sm: "min-h-8 px-4 t-small",
        icon: "size-11 p-0",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: React.ComponentProps<"button"> & VariantProps<typeof buttonVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot.Root : "button";
  return <Comp data-slot="button" className={cn(buttonVariants({ variant, size, className }))} {...props} />;
}

export { Button, buttonVariants };
