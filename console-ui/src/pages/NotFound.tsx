import { Button } from "@/components/ui/button";
import { Empty, Head, Panel } from "@/components/page";

// A # route no page answers: said plainly, so a wrong link is not hidden behind the Overview.
export function NotFound() {
  const route = window.location.hash.slice(1).split("?")[0];
  return (
    <>
      <Head
        title="Page not found"
        lead={`No console page lives at ${route}.`}
      />
      <Panel>
        <Empty
          title="This link does not lead anywhere"
          body="It may have a typo, or the page moved. Pick where to go from the menu, or start from one of these."
        >
          <Button asChild>
            <a href="#/overview">Go to Overview</a>
          </Button>
          <Button variant="outline" asChild>
            <a href="#/usage">Usage</a>
          </Button>
          <Button variant="outline" asChild>
            <a href="#/requests">Requests</a>
          </Button>
        </Empty>
      </Panel>
    </>
  );
}
