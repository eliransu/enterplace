import * as React from "react";
import { cn } from "@/lib/utils";

// Dense rows separated by hairlines, inside a panel: the console's Table.
function Table({ className, ...props }: React.ComponentProps<"table">) {
  return (
    <div className="overflow-x-auto">
      <table data-slot="table" className={cn("w-full border-separate border-spacing-0", className)} {...props} />
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
