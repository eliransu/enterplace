import * as React from "react";

// The console's page head and panel.
export function Head({ title, lead, actions }: { title: string; lead: string; actions?: React.ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div className="grid gap-2">
        <h1 className="t-lg m-0">{title}</h1>
        <p className="t-lead m-0 max-w-measure text-muted-foreground">{lead}</p>
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </header>
  );
}

export function Panel({ title, note, actions, children }: { title: string; note?: string; actions?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="grid gap-4 rounded-panel bg-card p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h2 className="t-sm m-0">{title}</h2>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </div>
      {children}
      {note ? <p className="t-small m-0 text-muted-foreground">{note}</p> : null}
    </section>
  );
}

export function Empty({ title, body }: { title: string; body: string }) {
  return (
    <div className="grid justify-items-start gap-2 py-6">
      <p className="t-body-strong m-0">{title}</p>
      <p className="t-body m-0 text-muted-foreground">{body}</p>
    </div>
  );
}

export function Problem({ text }: { text: string }) {
  return (
    <div role="alert" className="t-body rounded-panel border border-destructive p-6">
      {text}
    </div>
  );
}

// A refused change, under the form that sent it, as a field error reads.
export function Refusal({ text }: { text: string }) {
  return text ? (
    <p role="alert" className="t-small m-0 pl-6 text-destructive-text">
      {text}
    </p>
  ) : null;
}
