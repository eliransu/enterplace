import * as React from "react";
import { cn } from "@/lib/utils";

// Dense rows separated by hairlines, inside a panel: the console's Table. `long`: a list of up to a page of rows
// scrolls inside its panel under a header that stays put.
function Table({ className, long, ...props }: React.ComponentProps<"table"> & { long?: boolean }) {
  return (
    <div className={long ? "max-h-[75vh] overflow-auto" : "overflow-x-auto"}>
      <table
        data-slot="table"
        className={cn("w-full border-separate border-spacing-0", long && "[&_th]:sticky [&_th]:top-0 [&_th]:z-[1] [&_th]:bg-card", className)}
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
  return <tr className={cn("[&:hover>td]:bg-well", className)} {...props} />;
}
function TableHead({ className, ...props }: React.ComponentProps<"th">) {
  return <th className={cn("px-4 pt-2 pb-3 text-left font-normal whitespace-nowrap", className)} {...props} />;
}
function TableCell({ className, ...props }: React.ComponentProps<"td">) {
  return <td className={cn("t-mono-sm border-t border-border px-4 py-3 align-middle", className)} {...props} />;
}

export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell };
