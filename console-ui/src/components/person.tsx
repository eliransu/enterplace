import { Badge } from "./ui/badge";
import { UNNAMED } from "@/lib/api";

export const unnamed = (name: string) => !name || name === UNNAMED;

const WHY =
  "Sent with no person token, so nobody is named. Hand out person tokens, then turn on Every request needs a name under Coding agents.";

// A person as a list shows them. A request that named nobody is never shown as a person called "unknown".
export function Person({ name, href }: { name: string; href?: string }) {
  if (unnamed(name)) {
    return (
      <Badge title={WHY} className="border-dashed text-muted-foreground">
        Unnamed
      </Badge>
    );
  }
  return href ? (
    <a href={href} className="text-foreground">
      {name}
    </a>
  ) : (
    <>{name}</>
  );
}
