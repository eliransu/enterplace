import * as React from "react";
import { cn } from "@/lib/utils";

// Dense rows separated by hairlines, inside a panel: the console's Table. `long`: a list of up to a page of rows
// scrolls inside its panel under a header that stays put. Relative, so a cell's absolutely placed screen reader label is
// clipped by the scroll box too, instead of widening the whole page on a phone.
// `dense`: tighter rows, for a table inside a dialog or a sheet. A row with aria-selected reads as chosen.
function Table({
  className,
  long,
  dense,
  ...props
}: React.ComponentProps<"table"> & { long?: boolean; dense?: boolean }) {
  return (
    <div className={cn("relative", long ? "max-h-[75vh] overflow-auto" : "overflow-x-auto")}>
      <table
        data-slot="table"
        className={cn(
          "w-full border-separate border-spacing-0 [&_tbody>tr:first-child>td]:border-t-0",
          long && "[&_th]:sticky [&_th]:top-0 [&_th]:z-[1] [&_th]:bg-card",
          dense && "[&_td]:py-2 [&_th]:pb-2",
          className,
        )}
        {...props}
      />
    </div>
  );
}
function TableHeader(props: React.ComponentProps<"thead">) {
  return <thead className="t-tag uppercase text-muted-foreground" {...props} />;
}
function TableBody(props: React.ComponentProps<"tbody">) {
  return <tbody {...props} />;
}
function TableRow({ className, ...props }: React.ComponentProps<"tr">) {
  return (
    <tr
      className={cn("[&>td]:transition-colors [&:hover>td]:bg-well", className)}
      {...props}
    />
  );
}
// The header's own hairline keeps it apart from the first row, sticky or not.
function TableHead({ className, ...props }: React.ComponentProps<"th">) {
  return (
    <th
      className={cn(
        "border-b border-border px-4 pt-2 pb-3 text-left font-semibold whitespace-nowrap",
        className,
      )}
      {...props}
    />
  );
}
function TableCell({ className, ...props }: React.ComponentProps<"td">) {
  return (
    <td
      className={cn(
        "t-mono-sm border-t border-border px-4 py-3 align-middle",
        className,
      )}
      {...props}
    />
  );
}

export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell };
