import { Toaster as Sonner } from "sonner";

// The console's Toast: an inverse pill at the bottom right; a failure is flame.
function Toaster() {
  return (
    <Sonner
      position="bottom-right"
      toastOptions={{
        unstyled: true,
        classNames: {
          toast: "t-body flex min-h-11 max-w-dialog items-center gap-3 rounded-pill bg-primary px-6 py-2 text-primary-foreground",
          // Sonner puts both class lists on a failed toast: the failure's colors win.
          error: "rounded-box! bg-destructive! text-destructive-foreground!",
        },
      }}
    />
  );
}

export { Toaster };
