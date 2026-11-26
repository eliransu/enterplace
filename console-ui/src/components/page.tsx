import * as React from "react";
import { createPortal } from "react-dom";
import { CircleAlert } from "lucide-react";
import { Button } from "./ui/button";
import { Skeleton } from "./ui/skeleton";
import { cn } from "@/lib/utils";
import { inline } from "@/lib/use";

// The console's page head: title, one line that says what the page is for, and the page's actions on the right.
export function Head({
  title,
  lead,
  actions,
}: {
  title: string;
  lead?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div className="grid min-w-0 gap-2">
        <h1 className="t-lg m-0">{title}</h1>
        {/* Held at one line's height while the lead loads, so the page does not move when it arrives. */}
        <p className="t-lead m-0 min-h-[1lh] max-w-measure text-muted-foreground">
          {lead}
        </p>
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </header>
  );
}

export function Panel({
  title,
  note,
  actions,
  children,
  className,
}: {
  title?: string;
  note?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cn(
        "grid min-w-0 content-start gap-4 rounded-panel bg-card p-6",
        className,
      )}
    >
      {title || actions ? (
        <div className="flex flex-wrap items-center justify-between gap-4">
          {title ? <h2 className="t-sm m-0">{title}</h2> : <span />}
          {actions ? (
            <div className="flex flex-wrap gap-2">{actions}</div>
          ) : null}
        </div>
      ) : null}
      {children}
      {note ? (
        <p className="t-small m-0 text-muted-foreground">{note}</p>
      ) : null}
    </section>
  );
}

// An empty list: what it will hold, and the one thing to do next.
export function Empty({
  title,
  body,
  children,
}: {
  title: string;
  body: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className="grid justify-items-start gap-2 py-6">
      <p className="t-body-strong m-0">{title}</p>
      <p className="t-body m-0 max-w-measure text-muted-foreground">{body}</p>
      {children ? (
        <div className="flex flex-wrap gap-2 pt-2">{children}</div>
      ) : null}
    </div>
  );
}

// What failed, in the gateway's words (they name the cause and the fix), and a way to try again.
export function Problem({ text, retry }: { text: string; retry?: () => void }) {
  return (
    <div
      role="alert"
      className="t-body flex flex-wrap items-center justify-between gap-4 rounded-panel border border-destructive p-6"
    >
      <span className="flex min-w-0 flex-1 items-start gap-3">
        <CircleAlert
          aria-hidden="true"
          className="mt-1 size-4 flex-none text-destructive-text"
        />
        <span className="min-w-0">{text}</span>
      </span>
      {retry ? (
        <Button variant="outline" size="sm" onClick={retry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

// A refused change, as a field error reads: under the field whose value the refusal names ("platfrom" is not a
// team), else at the end of the form. The anchor tells the form's submit that the refusal shows here, not as a toast.
export function Refusal({ text }: { text: string }) {
  const anchor = React.useRef<HTMLSpanElement>(null);
  const [field, setField] = React.useState<Element | null>(null);
  React.useLayoutEffect(() => {
    const form = anchor.current?.closest("form");
    const named = text
      ? [...(form?.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input:not([type=hidden]), textarea") ?? [])].filter((c) => {
          const v = c.value.trim();
          return v.length > 1 && text.includes(v);
        })
      : [];
    setField(named.length === 1 ? (named[0].closest("[data-field]") ?? null) : null);
  }, [text]);
  const error = text ? (
    <p role="alert" className="t-small m-0 pl-6 text-destructive-text">
      {text}
    </p>
  ) : null;
  return (
    <>
      <span ref={anchor} data-refusal hidden />
      {field && error ? createPortal(error, field) : error}
    </>
  );
}

// A page that is still loading: the panel and rows it will fill, so nothing jumps when the data arrives.
export function Loading({ rows = 4 }: { rows?: number }) {
  return (
    <section
      aria-busy="true"
      aria-label="Loading"
      className="grid gap-4 rounded-panel bg-card p-6"
    >
      <Skeleton className="h-6 w-1/4" />
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-10" />
      ))}
    </section>
  );
}

// A form that cannot be sent twice: its controls are disabled from the click until the gateway answers.
export function Form({
  onSubmit,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"form">, "onSubmit"> & {
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => Promise<unknown> | void;
}) {
  const [busy, setBusy] = React.useState(false);
  const ref = React.useRef<HTMLFormElement>(null);
  return (
    <form
      ref={ref}
      {...props}
      aria-busy={busy || undefined}
      className={className}
      onSubmit={async (e) => {
        e.preventDefault();
        if (busy) return;
        setBusy(true);
        // A form that shows its own refusal does not also toast it.
        const shown = !!ref.current?.querySelector("[data-refusal]");
        if (shown) inline.forms++;
        try {
          await onSubmit(e);
        } finally {
          if (shown) inline.forms--;
          setBusy(false);
        }
      }}
    >
      <fieldset disabled={busy} className="contents">
        {children}
      </fieldset>
    </form>
  );
}

// A figure and what it counts.
export function Stat({
  figure,
  label,
}: {
  figure: React.ReactNode;
  label: string;
}) {
  return (
    <div className="grid min-w-0 gap-1">
      <p className="t-lg m-0 truncate tabular-nums">{figure}</p>
      <p className="t-small m-0 text-muted-foreground">{label}</p>
    </div>
  );
}

// A value that may be long (a URL, a model list): cut to its column, whole on hover.
export function Cut({ text, className }: { text: string; className?: string }) {
  return (
    <span title={text} className={cn("block max-w-col-sm truncate", className)}>
      {text}
    </span>
  );
}

// A section's own pages, as tabs. Each tab is a # route, so a tab is a link that can be shared.
export function RouteTabs({
  label,
  tabs,
  current,
}: {
  label: string;
  tabs: { route: string; label: string }[];
  current: string;
}) {
  return (
    <nav
      aria-label={label}
      className="-mb-2 flex gap-1 overflow-x-auto border-b border-border"
    >
      {tabs.map((t) => (
        <a
          key={t.route}
          href={`#${t.route}`}
          aria-current={t.route === current ? "page" : undefined}
          className={cn(
            "t-small -mb-px inline-flex min-h-10 flex-none items-center border-b-2 border-transparent px-3 whitespace-nowrap no-underline text-muted-foreground hover:text-foreground",
            t.route === current &&
              "border-foreground font-semibold text-foreground",
          )}
        >
          {t.label}
        </a>
      ))}
    </nav>
  );
}
