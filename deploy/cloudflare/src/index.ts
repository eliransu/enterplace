// Gantry on Cloudflare: this Worker routes every request to a gateway container (gantry-enterprise, one gateway per
// instance) and keeps each gateway's audit chain in R2, because a container's disk does not survive a restart.
//
// - Routing: each request goes to one of GATEWAYS instances, named gateway-0 to gateway-(N-1). They share the store
//   (Postgres at DATABASE_URL), so any of them can answer any request.
// - Audit: the gateway seals its log every GANTRY_AUDIT_SEAL_SECONDS and writes each sealed segment to R2 through the
//   handler below, which speaks the three S3 calls the gateway makes (PUT, GET, ListObjectsV2) against the AUDIT
//   bucket binding. No R2 access key exists: the handler is reachable only from this application's containers, and
//   it keeps each instance under audit/<its Durable Object id>/, so one gateway cannot write another's chain. It
//   never overwrites a segment with other bytes and has no delete.
// - Secrets: Workers secrets and vars named GANTRY_*, DATABASE_URL, AWS_* or *_PROVIDER_KEY are passed to the
//   container as environment variables when it starts.

import { Container, ContainerProxy, getContainer } from "@cloudflare/containers";

export { ContainerProxy };

export interface Env {
  GATEWAY: DurableObjectNamespace<GantryGateway>;
  AUDIT: R2Bucket;
  GATEWAYS?: string;
  GANTRY_AUDIT_READ_TOKEN?: string;
  [name: string]: unknown;
}

// Not a real host: the container's HTTP requests to it are answered by `segments` below.
const AUDIT_HOST = "audit.gantry.internal";

const root = (containerId: string) => `audit/${containerId}/`;

const xml = (text: string) =>
  text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

// The S3 subset the gateway uses, path style (/<bucket>/<key>). The bucket in the path is ignored: the binding decides.
async function segments(req: Request, env: Env, ctx: { containerId: string }): Promise<Response> {
  const url = new URL(req.url);
  const key = url.pathname.split("/").slice(2).join("/");
  if (key.includes("..") || key.startsWith("/")) return new Response("bad key\n", { status: 400 });
  const base = root(ctx.containerId);
  if (req.method === "GET" && key === "") {
    const prefix = url.searchParams.get("prefix") ?? "";
    const listed = await env.AUDIT.list({
      prefix: base + prefix,
      cursor: url.searchParams.get("continuation-token") ?? undefined,
      limit: 1000,
    });
    const keys = listed.objects.map((o) => `<Contents><Key>${xml(o.key.slice(base.length))}</Key></Contents>`).join("");
    const more = listed.truncated
      ? `<IsTruncated>true</IsTruncated><NextContinuationToken>${xml(listed.cursor)}</NextContinuationToken>`
      : "<IsTruncated>false</IsTruncated>";
    return new Response(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>${keys}${more}</ListBucketResult>`, {
      headers: { "content-type": "application/xml" },
    });
  }
  if (req.method === "GET") {
    const object = await env.AUDIT.get(base + key);
    return object ? new Response(object.body) : new Response("not found\n", { status: 404 });
  }
  if (req.method === "PUT") {
    const body = new Uint8Array(await req.arrayBuffer());
    const existing = await env.AUDIT.get(base + key);
    if (existing) {
      // A segment is written again after a restart fetched it back; the same bytes are fine, others are refused.
      return same(new Uint8Array(await existing.arrayBuffer()), body)
        ? new Response(null, { status: 200 })
        : new Response("a different object is already stored under this key\n", { status: 409 });
    }
    await env.AUDIT.put(base + key, body);
    return new Response(null, { status: 200 });
  }
  return new Response("not allowed\n", { status: 405 });
}

export class GantryGateway extends Container<Env> {
  defaultPort = 8080;
  // /healthz answers without an audit record, so probes do not fill the chain.
  pingEndpoint = "localhost/healthz";
  // An idle gateway stops (a graceful stop: it seals and writes its last records first) and starts on the next request.
  sleepAfter = "30m";
}
// Assigned, not declared as a static field: a class field would define its own property and skip the setter that
// registers the handler, and the container's requests to AUDIT_HOST would then be refused.
GantryGateway.outboundByHost = { [AUDIT_HOST]: segments };

const PASSED = /^(GANTRY_[A-Z0-9_]+|DATABASE_URL|AWS_[A-Z0-9_]+|[A-Z0-9_]+_PROVIDER_KEY)$/;

function startEnv(env: Env, instance: string): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (typeof value === "string" && PASSED.test(name)) vars[name] = value;
  }
  vars.HOSTNAME = instance;
  vars.GANTRY_AUDIT_SEGMENTS_URL = `http://${AUDIT_HOST}/segments`;
  return vars;
}

async function gateway(env: Env, instance: string) {
  const stub = getContainer(env.GATEWAY, instance);
  await stub.startAndWaitForPorts({ startOptions: { envVars: startEnv(env, instance) } });
  return stub;
}

// GET /_gantry/audit/<instance> with the read token: that gateway's whole chain, the R2 segments in order and then
// the records not yet sealed, as one file for `gantry audit verify`.
async function chain(env: Env, instance: string): Promise<Response> {
  const stub = await gateway(env, instance);
  // The tail first: a segment sealed after this read starts at or after its first record and is left out.
  const tail = await stub.fetch(
    new Request("http://gateway/audit/tail", { headers: { authorization: `Bearer ${env.GANTRY_AUDIT_READ_TOKEN}` } }),
  );
  if (!tail.ok) return new Response(`the gateway answered ${tail.status} for its tail: ${await tail.text()}`, { status: 502 });
  const tailText = await tail.text();
  const firstLine = tailText.split("\n", 1)[0];
  const tailFirst = firstLine ? Number(JSON.parse(firstLine).n) : Infinity;
  const base = root(env.GATEWAY.idFromName(instance).toString());
  const names: { first: number; key: string }[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.AUDIT.list({ prefix: base, cursor, limit: 1000 });
    for (const o of page.objects) {
      const m = /(\d{20})-(\d{20})\.jsonl$/.exec(o.key);
      if (m && Number(m[2]) < tailFirst) names.push({ first: Number(m[1]), key: o.key });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  names.sort((a, b) => a.first - b.first);
  const encoder = new TextEncoder();
  let i = 0;
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (i < names.length) {
        const object = await env.AUDIT.get(names[i++].key);
        if (object) controller.enqueue(new Uint8Array(await object.arrayBuffer()));
        return;
      }
      controller.enqueue(encoder.encode(tailText));
      controller.close();
    },
  });
  return new Response(body, { headers: { "content-type": "application/x-ndjson" } });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const audit = /^\/_gantry\/audit\/(gateway-\d+)$/.exec(url.pathname);
    if (audit) {
      const token = env.GANTRY_AUDIT_READ_TOKEN;
      if (!token || req.headers.get("authorization") !== `Bearer ${token}`) {
        return new Response("Send the GANTRY_AUDIT_READ_TOKEN secret as Authorization: Bearer <token>.\n", { status: 401 });
      }
      return chain(env, audit[1]);
    }
    const count = Math.max(1, Number(env.GATEWAYS ?? "1") || 1);
    const instance = `gateway-${Math.floor(Math.random() * count)}`;
    let stub;
    try {
      stub = await gateway(env, instance);
    } catch (err) {
      console.error("gateway start", instance, err);
      return new Response(
        JSON.stringify({
          error: {
            type: "gantry_refused",
            code: "gateway_not_ready",
            message: "The gateway container did not start. Run `npx wrangler tail` to see why (a policy it cannot use, or a missing secret), fix it and deploy again.",
          },
        }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    // Cloudflare's own request headers stop here: the gateway passes headers on to the provider, and a provider
    // behind Cloudflare refuses a request that carries them (error 1000).
    const headers = new Headers();
    for (const [name, value] of req.headers) {
      const n = name.toLowerCase();
      if (n.startsWith("cf-") || n.startsWith("x-forwarded-") || n === "cdn-loop" || n === "x-real-ip" || n === "true-client-ip") continue;
      headers.set(name, value);
    }
    return stub.fetch(new Request(req, { headers }));
  },
} satisfies ExportedHandler<Env>;
