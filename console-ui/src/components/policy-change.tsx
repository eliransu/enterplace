import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Panel, Refusal } from "@/components/page";
import { api, preview, Refused } from "@/lib/api";
import { cn } from "@/lib/utils";
import { VerdictTag } from "@/pages/Audit";

export type Tag = { kind: string; word: string; detail: string };
export type Line = { n: number; text: string; kind: string };
export type Run = {
  tag: Tag;
  summary: string;
  note: string;
  tables: { title: string; count: number; rows: Record<string, string>[] }[];
};
type Preview = { diff: Line[]; text: string; removes: string[] };
export type Change = (
  run: () => Promise<{ message: string }>,
) => Promise<string>;

// The policy's lines, numbered: + added, - removed, the asked-for line marked, and each problem under its line.
export function Code({ lines, hit }: { lines: Line[]; hit?: number }) {
  return (
    <div className="t-mono-sm grid overflow-x-auto rounded-box bg-well py-3">
      {lines.map((l, i) => (
        <div
          key={i}
          id={l.kind === "note" ? undefined : `line-${l.n}`}
          data-kind={l.kind || undefined}
          className={cn(
            "flex gap-4 px-6 whitespace-pre",
            (l.n === hit || l.kind === "add") &&
              l.kind !== "note" &&
              "bg-card font-semibold",
            l.kind === "del" && "text-muted-foreground line-through",
            l.kind === "error" && "text-destructive-text",
            l.kind === "note" && "whitespace-pre-wrap text-destructive-text",
          )}
        >
          <span
            aria-hidden="true"
            className="w-8 flex-none text-right text-muted-foreground"
          >
            {l.kind === "add"
              ? "+"
              : l.kind === "del"
                ? "-"
                : l.kind === "note"
                  ? ""
                  : l.n}
          </span>
          <span>{l.text}</span>
        </div>
      ))}
    </div>
  );
}

export function Report({ run }: { run: Run }) {
  return (
    <Panel
      title="Dry run"
      actions={<VerdictTag tag={run.tag} />}
      note={run.note}
    >
      <p className="t-body m-0">{run.summary}</p>
      {run.tables.map((t) =>
        t.count === 0 ? (
          <p key={t.title} className="t-small m-0 text-muted-foreground">
            {t.title}: none.
          </p>
        ) : (
          <div key={t.title} className="grid gap-2">
            <h3 className="t-tag m-0 uppercase">
              {t.title}: {t.count}
            </h3>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Who</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Decision</TableHead>
                  <TableHead>Rule</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {t.rows.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell>{r.time}</TableCell>
                    <TableCell>
                      {r.person}
                      <span className="block text-muted-foreground">
                        {r.team}
                      </span>
                    </TableCell>
                    <TableCell>{r.model}</TableCell>
                    <TableCell>{r.decision}</TableCell>
                    <TableCell className="whitespace-normal">
                      {r.rule}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ),
      )}
    </Panel>
  );
}

/// A button that waits for what it started: disabled until the gateway answers, so it is never sent twice.
export function Busy({
  run,
  children,
  ...props
}: Omit<React.ComponentProps<typeof Button>, "onClick"> & {
  run: () => Promise<unknown>;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <Button
      {...props}
      disabled={busy || props.disabled}
      aria-busy={busy || undefined}
      onClick={async () => {
        setBusy(true);
        try {
          await run();
        } finally {
          setBusy(false);
        }
      }}
    >
      {children}
    </Button>
  );
}

/// A dry run of `text` over the last `hours`: the report, or the refusal as a toast.
export async function dryRun(
  text: string,
  hours: number | string,
): Promise<Run | null> {
  try {
    const done = (await api.post("policy/dry-run", {
      text,
      hours,
    })) as unknown as { message: string; run: Run };
    toast(done.message);
    return done.run;
  } catch (e) {
    if (e instanceof Refused) {
      toast.error(e.message, { duration: 10000 });
      return null;
    }
    throw e;
  }
}

/// Every policy save from the console goes through this one step: the change is drafted and checked first, then
/// shown as its diff against the policy in force, with what it removes and a dry run over the last 24 hours, and
/// saved only on Apply. Wraps a page's `change` and returns the same kind of function, plus the dialog to render.
export function useCheckedChange(change: Change): [Change, React.ReactNode] {
  const [pending, setPending] = useState<{
    run: () => Promise<{ message: string }>;
    preview: Preview;
  } | null>(null);
  const checked = useCallback<Change>(async (run) => {
    try {
      const done = (await preview(run)) as {
        message: string;
        preview?: Preview;
      };
      if (done.preview) setPending({ run, preview: done.preview });
      else toast(done.message);
      return "";
    } catch (e) {
      if (e instanceof Refused) {
        toast.error(e.message, { duration: 10000 });
        return e.message;
      }
      throw e;
    }
  }, []);
  const dialog = pending ? (
    <ChangeCheck
      preview={pending.preview}
      onClose={() => setPending(null)}
      onApply={async () => {
        await change(pending.run);
        setPending(null);
      }}
    />
  ) : null;
  return [checked, dialog];
}

function ChangeCheck({
  preview,
  onClose,
  onApply,
}: {
  preview: Preview;
  onClose: () => void;
  onApply: () => Promise<void>;
}) {
  const [run, setRun] = useState<Run | null>(null);
  const [refused, setRefused] = useState("");
  useEffect(() => {
    api
      .post("policy/dry-run", { text: preview.text, hours: 24 })
      .then((done) => setRun((done as unknown as { run: Run }).run))
      .catch((e: Error) => setRefused(`The dry run did not run: ${e.message}`));
  }, [preview.text]);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-wide">
        <DialogTitle>Check this change before it applies</DialogTitle>
        <DialogDescription>
          Against the policy in force now: + lines are added, - lines removed.
          The dry run replays the last 24 hours of requests under the change.
          Nothing is saved until you apply it.
        </DialogDescription>
        {preview.removes.length ? (
          <p role="alert" className="t-body m-0 text-destructive-text">
            This removes: {preview.removes.join(", ")}.
          </p>
        ) : null}
        {preview.diff.length ? (
          <Code lines={preview.diff} />
        ) : (
          <p className="t-small m-0 text-muted-foreground">
            Only comments or spacing change.
          </p>
        )}
        {run ? (
          <Report run={run} />
        ) : refused ? null : (
          <p className="t-small m-0 text-muted-foreground">
            Replaying the last 24 hours...
          </p>
        )}
        <Refusal text={refused} />
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Busy run={onApply}>Apply</Busy>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
