// The EnterplaceStore Durable Object alone, answering every request, for a local check with `wrangler dev` and
// gateways run on this machine (ENTERPLACE_CLOUDFLARE_STORE_URL=http://127.0.0.1:8787). Never deploy this: in the
// template the object is reachable only from the gateway containers.
import { EnterplaceStore } from "../src/store-object";

export { EnterplaceStore };

export default {
  fetch(req: Request, env: { STORE: DurableObjectNamespace<EnterplaceStore> }): Promise<Response> {
    return env.STORE.get(env.STORE.idFromName("enterplace")).fetch(req);
  },
} satisfies ExportedHandler<{ STORE: DurableObjectNamespace<EnterplaceStore> }>;
