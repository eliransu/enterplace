// The Cloudflare store's code (src/store.ts) on node:sqlite, behind a plain HTTP server, so the gateway's store tests
// run against it without Cloudflare: `node test/store-server.ts` prints the port it listens on, then serves until
// stdin closes. Each run starts with an empty database in memory.
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { StoreCore, serve } from "../src/store.ts";

const db = new DatabaseSync(":memory:");
const core = new StoreCore({
  exec: (query, ...params) => {
    const rows = db.prepare(query).all(...(params as never[]));
    return { toArray: () => rows as Record<string, any>[] };
  },
  rows: (query, ...params) => {
    const statement = db.prepare(query);
    statement.setReturnArrays(true);
    const columns = statement.columns().map((c) => c.name);
    return { columns, rows: statement.all(...(params as never[])) as unknown as unknown[][] };
  },
  script: (text) => db.exec(text),
  tx: (work) => {
    db.exec("BEGIN");
    try {
      const done = work();
      db.exec("COMMIT");
      return done;
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  },
});

const server = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const answer = await serve(
    core,
    new Request(`http://store${req.url}`, { method: req.method, body: req.method === "POST" ? Buffer.concat(chunks) : undefined }),
  );
  res.writeHead(answer.status, { "content-type": answer.headers.get("content-type") ?? "text/plain" });
  res.end(Buffer.from(await answer.arrayBuffer()));
});

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  console.log(typeof address === "object" && address ? address.port : 0);
});
// The test that started it holds stdin open; when the test ends, so does this.
process.stdin.resume();
process.stdin.on("end", () => process.exit(0));
