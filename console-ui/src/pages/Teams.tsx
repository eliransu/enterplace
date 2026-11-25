import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Head, Loading, Panel, Problem } from "@/components/page";
import { useData } from "@/lib/use";

type Team = { name: string; keys: string; owner: string | null; people: { name: string; admin: boolean }[]; rule: string; budget: string };
type Data = {
  error?: string;
  issue: boolean;
  teams?: Team[];
  empty: { title: string; body: string; action?: { label: string; href: string }; docs: string } | null;
};

export function Teams() {
  // Live: a key issued or a policy saved shows within the next 5 seconds.
  const { data, error, reload } = useData<Data>("teams", 5000);
  return (
    <>
      <Head
        title="Teams"
        lead="Who is in each team, the rule it falls under, and its budget."
        actions={
          data?.issue ? (
            <Button asChild>
              <a href="#/people?issue=1">Issue a key</a>
            </Button>
          ) : null
        }
      />
      {error ? <Problem text={error} retry={reload} /> : null}
      {data?.error ? <Problem text={data.error} retry={reload} /> : null}
      {!data && !error ? <Loading rows={4} /> : null}
      {data?.empty ? (
        <Panel title={data.empty.title}>
          <p className="t-body m-0 text-muted-foreground">{data.empty.body}</p>
          <div className="flex flex-wrap gap-2">
            {data.empty.action ? (
              <Button asChild>
                <a href={data.empty.action.href}>{data.empty.action.label}</a>
              </Button>
            ) : null}
            <Button variant="outline" asChild>
              <a href={data.empty.docs}>Read the docs page</a>
            </Button>
          </div>
        </Panel>
      ) : data?.teams?.length ? (
        <Panel title={`${data.teams.length} ${data.teams.length === 1 ? "team" : "teams"}`}>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Team</TableHead>
                <TableHead>People and apps</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead className="text-right">Budget</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.teams.map((t) => (
                <TableRow key={t.name}>
                  <TableCell className="align-top">
                    {t.name}
                    <span className="block text-muted-foreground">
                      {t.keys}
                      {t.owner ? `, owner ${t.owner}` : ""}
                    </span>
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    <div className="grid gap-1">
                      {t.people.map((p) => (
                        <span key={`${p.name} ${p.admin}`} className="flex flex-wrap items-center gap-2">
                          {p.name}
                          <Badge className={p.admin ? undefined : "border-transparent pl-0 text-muted-foreground"}>{p.admin ? "Admin" : "Member"}</Badge>
                        </span>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="align-top">{t.rule}</TableCell>
                  <TableCell className="text-right align-top tabular-nums">{t.budget}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      ) : null}
    </>
  );
}
