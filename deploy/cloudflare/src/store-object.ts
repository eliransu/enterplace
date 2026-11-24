// Every gateway's store, in one Durable Object: it runs one call at a time, which makes each call atomic. The calls
// themselves are in store.ts, which names no Workers API so tests run it on node:sqlite too.
import { DurableObject } from "cloudflare:workers";
import { StoreCore, serve } from "./store";

export class EnterplaceStore<Env = unknown> extends DurableObject<Env> {
  private core: StoreCore;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    this.core = new StoreCore({
      exec: (query, ...params) => sql.exec(query, ...params),
      rows: (query, ...params) => {
        const cursor = sql.exec(query, ...params);
        return { columns: cursor.columnNames, rows: [...cursor.raw()] };
      },
      script: (text) => {
        sql.exec(text);
      },
      tx: (work) => ctx.storage.transactionSync(work),
    });
  }
  fetch(req: Request): Promise<Response> {
    return serve(this.core, req);
  }
}
