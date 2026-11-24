import * as React from "react";
import { Dialog as DialogPrimitive, Slot } from "radix-ui";
import { PanelLeft } from "lucide-react";
import { cn } from "@/lib/utils";

// shadcn/ui's Sidebar, same parts and data-slot names, themed with the Enterplace tokens and cut to what the console
// uses: one left sidebar that collapses to icons on desktop (Ctrl or Cmd+B, kept in localStorage) and slides in as a
// sheet below md. ponytail: no right side, no floating or inset variants; add them when a page needs one.

type Ctx = { collapsed: boolean; toggle: () => void; mobileOpen: boolean; setMobileOpen: (open: boolean) => void };
const SidebarContext = React.createContext<Ctx | null>(null);
const KEY = "enterplace.sidebar.collapsed";

function useSidebar() {
  const ctx = React.useContext(SidebarContext);
  if (!ctx) throw new Error("useSidebar must be used inside SidebarProvider.");
  return ctx;
}

function SidebarProvider({ className, children, ...props }: React.ComponentProps<"div">) {
  const [collapsed, setCollapsed] = React.useState(() => {
    try {
      return localStorage.getItem(KEY) === "1";
    } catch {
      return false;
    }
  });
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const toggle = React.useCallback(() => {
    if (window.matchMedia("(max-width: 767px)").matches) return setMobileOpen((o) => !o);
    setCollapsed((c) => {
      try {
        localStorage.setItem(KEY, c ? "0" : "1");
      } catch {
        // Private windows refuse storage: the sidebar still toggles, it just is not remembered.
      }
      return !c;
    });
  }, []);
  React.useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.key === "b" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        toggle();
      }
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, [toggle]);
  return (
    <SidebarContext.Provider value={{ collapsed, toggle, mobileOpen, setMobileOpen }}>
      <div data-slot="sidebar-wrapper" data-collapsed={collapsed || undefined} className={cn("group/sidebar flex min-h-screen w-full", className)} {...props}>
        {children}
      </div>
    </SidebarContext.Provider>
  );
}

const panel = "flex h-full flex-col bg-card text-foreground";

function Sidebar({ className, children, label = "Console" }: { className?: string; children: React.ReactNode; label?: string }) {
  const { mobileOpen, setMobileOpen } = useSidebar();
  return (
    <>
      <nav
        aria-label={label}
        data-slot="sidebar"
        className={cn(
          panel,
          "sticky top-0 hidden h-screen flex-none border-r border-border transition-[width] md:flex",
          "w-nav group-data-collapsed/sidebar:w-16",
          className,
        )}
      >
        {children}
      </nav>
      <DialogPrimitive.Root open={mobileOpen} onOpenChange={setMobileOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 bg-overlay md:hidden" />
          <DialogPrimitive.Content aria-describedby={undefined} className={cn(panel, "fixed inset-y-0 left-0 w-nav border-r border-border md:hidden")}>
            <DialogPrimitive.Title className="sr-only">{label}</DialogPrimitive.Title>
            {/* The sheet never collapses to icons, whatever the desktop state. */}
            <div data-mobile className="contents">{children}</div>
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
    </>
  );
}

function SidebarTrigger({ className, ...props }: React.ComponentProps<"button">) {
  const { toggle } = useSidebar();
  return (
    <button
      type="button"
      data-slot="sidebar-trigger"
      onClick={toggle}
      aria-label="Toggle the sidebar (Ctrl or Cmd+B)"
      title="Toggle the sidebar (Ctrl or Cmd+B)"
      className={cn("inline-flex size-8 flex-none items-center justify-center rounded-box bg-transparent text-muted-foreground hover:bg-accent hover:text-foreground [&_svg]:size-4", className)}
      {...props}
    >
      <PanelLeft aria-hidden="true" />
    </button>
  );
}

function SidebarInset({ className, ...props }: React.ComponentProps<"main">) {
  return <main data-slot="sidebar-inset" className={cn("min-w-0 flex-1", className)} {...props} />;
}

function SidebarHeader({ className, ...props }: React.ComponentProps<"div">) {
  return <div data-slot="sidebar-header" className={cn("flex flex-col gap-2 p-3", className)} {...props} />;
}

function SidebarFooter({ className, ...props }: React.ComponentProps<"div">) {
  return <div data-slot="sidebar-footer" className={cn("flex flex-col gap-2 border-t border-border p-3", className)} {...props} />;
}

function SidebarContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="sidebar-content"
      className={cn("flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto overflow-x-hidden px-3 [scrollbar-color:var(--line)_transparent] [scrollbar-width:thin]", className)}
      {...props}
    />
  );
}

function SidebarGroup({ className, ...props }: React.ComponentProps<"div">) {
  return <div data-slot="sidebar-group" role="group" className={cn("flex flex-col py-2", className)} {...props} />;
}

// Hidden when collapsed: the icons alone carry the list, and a hairline keeps the groups apart.
function SidebarGroupLabel({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="sidebar-group-label"
      className={cn(
        "t-tag flex h-8 items-center px-2 uppercase text-muted-foreground",
        "md:group-data-collapsed/sidebar:[&:not([data-mobile]_*)]:hidden",
        className,
      )}
      {...props}
    />
  );
}

function SidebarMenu({ className, ...props }: React.ComponentProps<"ul">) {
  return <ul data-slot="sidebar-menu" className={cn("m-0 flex list-none flex-col gap-0.5 p-0", className)} {...props} />;
}

function SidebarMenuItem({ className, ...props }: React.ComponentProps<"li">) {
  return <li data-slot="sidebar-menu-item" className={cn("relative", className)} {...props} />;
}

function SidebarMenuButton({
  asChild = false,
  isActive = false,
  tooltip,
  className,
  ...props
}: React.ComponentProps<"button"> & { asChild?: boolean; isActive?: boolean; tooltip?: string }) {
  const Comp = asChild ? Slot.Root : "button";
  return (
    <Comp
      data-slot="sidebar-menu-button"
      data-active={isActive || undefined}
      title={tooltip}
      className={cn(
        "t-small flex h-8 w-full items-center gap-3 overflow-hidden rounded-box bg-transparent px-2 text-left whitespace-nowrap no-underline text-muted-foreground",
        "hover:bg-accent hover:text-foreground data-active:bg-accent data-active:text-foreground data-active:font-semibold",
        "[&_svg]:size-4 [&_svg]:flex-none [&>span]:truncate",
        "md:group-data-collapsed/sidebar:[&:not([data-mobile]_*)]:w-8 md:group-data-collapsed/sidebar:[&:not([data-mobile]_*)]:justify-center md:group-data-collapsed/sidebar:[&:not([data-mobile]_*)]:[&>span]:hidden",
        className,
      )}
      {...props}
    />
  );
}

function SidebarSeparator({ className, ...props }: React.ComponentProps<"hr">) {
  return <hr data-slot="sidebar-separator" className={cn("m-0 border-0 border-t border-border", className)} {...props} />;
}

export {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarSeparator,
  SidebarTrigger,
  useSidebar,
};
