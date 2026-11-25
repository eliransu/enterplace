// The Cloudflare store: what every gateway instance shares (keys, kill switches, spend, rate limits, cooldowns,
// console sessions, credentials, policy versions, routing and health), kept in the SQLite of one Durable Object.
//
// The gateway (`store: { cloudflare: true }`) sends each call as POST /v1/<call> with a JSON body to
// http://store.enterplace.internal, which the Worker forwards here. A Durable Object runs one request at a time and
// every call below is synchronous SQL, so each call is atomic: a reservation, a lease, a probe lease and a policy
// change cannot interleave with another gateway's. Changes that touch several rows run in one transaction, so an
// error leaves nothing half written.
//
// Kept free of Workers APIs, so tests run the same code on node:sqlite (test/store-server.ts).

/** The SQL a Durable Object's `ctx.storage` gives, or node:sqlite in tests. */
export interface Sql {
  exec(query: string, ...params: unknown[]): { toArray(): Record<string, any>[] };
  /** A statement's rows as arrays in column order, for the features' own SQL. */
  rows(query: string, ...params: unknown[]): { columns: string[]; rows: unknown[][] };
  /** Several statements separated by semicolons, without parameters. */
  script(text: string): void;
  tx<T>(work: () => T): T;
}

/** A parameter of the features' SQL as JSON: bytes come as {"$b64": ...}, a boolean as 1 or 0. */
function bind(value: unknown): unknown {
  if (value === true) return 1;
  if (value === false) return 0;
  if (value && typeof value === "object" && "$b64" in value) {
    return Uint8Array.from(atob(String((value as { $b64: string }).$b64)), (c) => c.charCodeAt(0));
  }
  return value ?? null;
}

/** A cell of the features' SQL as JSON: bytes as {"$b64": ...}. */
function cell(value: unknown): unknown {
  if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    let text = "";
    for (const b of bytes) text += String.fromCharCode(b);
    return { $b64: btoa(text) };
  }
  if (typeof value === "bigint") return Number(value);
  return value;
}

type Row = Record<string, any>;

// One migration per entry, applied in order on first use. Never edit an entry that has shipped: add one.
const MIGRATIONS: string[][] = [
  [
    "CREATE TABLE keys (id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE, name TEXT NOT NULL, body TEXT NOT NULL)",
    "CREATE TABLE kills (scope TEXT NOT NULL, value TEXT NOT NULL, reason TEXT NOT NULL, set_by TEXT NOT NULL, set_at TEXT NOT NULL, PRIMARY KEY (scope, value))",
    "CREATE TABLE spend (scope TEXT NOT NULL, per TEXT NOT NULL, period TEXT NOT NULL, spent REAL NOT NULL DEFAULT 0, reserved REAL NOT NULL DEFAULT 0, PRIMARY KEY (scope, per, period))",
    "CREATE TABLE versions (name TEXT PRIMARY KEY, version INTEGER NOT NULL)",
    "CREATE TABLE rate_grants (id INTEGER PRIMARY KEY, scope TEXT NOT NULL, until INTEGER NOT NULL, n INTEGER NOT NULL)",
    "CREATE INDEX rate_grants_scope ON rate_grants (scope, until)",
    "CREATE TABLE cooldowns (deployment TEXT PRIMARY KEY, until INTEGER NOT NULL)",
    "CREATE TABLE sessions (sha256 TEXT PRIMARY KEY, who TEXT NOT NULL, expires INTEGER NOT NULL)",
    "CREATE TABLE credentials (name TEXT PRIMARY KEY, provider TEXT NOT NULL, sealed TEXT NOT NULL, fingerprint TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, rotated_by TEXT, rotated_at TEXT, generation INTEGER NOT NULL DEFAULT 1)",
    "CREATE TABLE master (id INTEGER PRIMARY KEY CHECK (id = 1), sealed TEXT NOT NULL)",
    "CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT NOT NULL, updated INTEGER NOT NULL)",
    "CREATE TABLE policy_versions (id INTEGER PRIMARY KEY, text TEXT NOT NULL, sha256 TEXT NOT NULL, base INTEGER, note TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, state TEXT NOT NULL, decided_by TEXT, decided_at TEXT)",
    "CREATE TABLE affinity (session TEXT PRIMARY KEY, deployment TEXT NOT NULL, seen INTEGER NOT NULL)",
    "CREATE INDEX affinity_seen ON affinity (seen)",
    "CREATE TABLE latency (deployment TEXT NOT NULL, gateway TEXT NOT NULL, samples TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (deployment, gateway))",
    "CREATE TABLE probe_leases (deployment TEXT PRIMARY KEY, gateway TEXT NOT NULL, until INTEGER NOT NULL)",
    "CREATE TABLE deployment_load (deployment TEXT NOT NULL, gateway TEXT NOT NULL, in_flight INTEGER NOT NULL, minute INTEGER NOT NULL, requests INTEGER NOT NULL, tokens INTEGER NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (deployment, gateway))",
    "CREATE TABLE gateway_health (gateway TEXT PRIMARY KEY, report TEXT NOT NULL, updated INTEGER NOT NULL)",
    "CREATE TABLE replicas (gateway TEXT PRIMARY KEY, host TEXT NOT NULL, version TEXT NOT NULL, schema TEXT NOT NULL, started INTEGER NOT NULL, seen INTEGER NOT NULL)",
    "CREATE TABLE answer_cache (key TEXT PRIMARY KEY, scope TEXT NOT NULL, status INTEGER NOT NULL, content_type TEXT, body TEXT NOT NULL, origin TEXT NOT NULL, cost REAL NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL, size INTEGER NOT NULL)",
    "CREATE INDEX answer_cache_expires ON answer_cache (expires)",
    "CREATE TABLE answer_vectors (key TEXT PRIMARY KEY, partition TEXT NOT NULL, vector TEXT NOT NULL, created INTEGER NOT NULL)",
    "CREATE INDEX answer_vectors_partition ON answer_vectors (partition, created)",
    "CREATE TABLE raises (id TEXT PRIMARY KEY, body TEXT NOT NULL)",
    "INSERT INTO versions VALUES ('keys', 0), ('kills', 0), ('cooldowns', 0), ('credentials', 0), ('policy', 0), ('events', 0), ('raises', 0)",
  ],
  // Failed console sign-ins per source address and account, and until when each is locked out.
  ["CREATE TABLE sign_in_failures (scope TEXT PRIMARY KEY, failures INTEGER NOT NULL, since INTEGER NOT NULL, locked_until INTEGER)"],
  // The policy version each gateway runs, and a newer one it refused with why.
  [
    "ALTER TABLE replicas ADD COLUMN policy_version INTEGER",
    "ALTER TABLE replicas ADD COLUMN refused_version INTEGER",
    "ALTER TABLE replicas ADD COLUMN refused TEXT",
  ],
];

/** The versions the poll compares, each naming what is read again when it changes. */
const WATCHED = ["keys", "kills", "cooldowns", "credentials", "policy", "events", "raises"] as const;

/** Most bytes of answers kept. Past it the least recently used go first, at the next clean-up. */
// ponytail: one fixed size, as the Postgres store has. A setting when someone needs another.
const CACHE_BYTES = 1024 * 1024 * 1024;

/** What marks a session row as one an events plugin ended, before the guardrail's name. */
const ENDED = "events:";

const SHOWN = "name, provider, fingerprint, created_by, created_at, rotated_by, rotated_at, generation";
const VERSION = "id, text, sha256, base, note, created_by, created_at, state, decided_by, decided_at";

export class StoreCore {
  private sql: Sql;
  constructor(sql: Sql) {
    this.sql = sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS schema (version INTEGER NOT NULL)");
    const applied = Number(this.one("SELECT coalesce(max(version), 0) AS v FROM schema")?.v ?? 0);
    if (applied > MIGRATIONS.length) {
      throw new Error(
        `the store's tables were written by a newer Worker (schema ${applied}, this one knows ${MIGRATIONS.length}). Deploy the Worker of the newest Enterplace version.`,
      );
    }
    this.sql.tx(() => {
      MIGRATIONS.slice(applied).forEach((list, i) => {
        for (const statement of list) this.sql.exec(statement);
        this.sql.exec("INSERT INTO schema VALUES (?)", applied + i + 1);
      });
    });
  }

  private all(query: string, ...params: unknown[]): Row[] {
    return this.sql.exec(query, ...params).toArray();
  }

  private one(query: string, ...params: unknown[]): Row | undefined {
    return this.all(query, ...params)[0];
  }

  private run(query: string, ...params: unknown[]) {
    this.sql.exec(query, ...params);
  }

  private bump(name: string) {
    this.run("UPDATE versions SET version = version + 1 WHERE name = ?", name);
  }

  // The features with tables of their own (the request log, batches, MCP state, the enterprise features) send
  // their SQL here, already in SQLite. A transaction holds the object: until it ends (or 10 seconds pass with no
  // statement of it), another connection's statement waits.
  private holder: { id: string; until: number } | null = null;

  private held(session: string | null | undefined): boolean {
    if (this.holder && this.holder.until < Date.now()) this.holder = null;
    return !!this.holder && this.holder.id !== session;
  }

  async sqlCall(name: string, body: any): Promise<unknown> {
    const started = Date.now();
    while (this.held(body?.session)) {
      if (Date.now() - started > 10_000) throw new Error("another gateway's transaction held the store for 10 seconds");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    const now = Date.now();
    if (name === "sql_begin") {
      this.holder = { id: crypto.randomUUID(), until: now + 10_000 };
      return { session: this.holder.id };
    }
    if (name === "sql_end") {
      if (this.holder?.id === body.session) this.holder = null;
      return {};
    }
    if (name === "sql_migrate") return this.migrate(body.namespace, body.migrations);
    if (this.holder) this.holder.until = now + 10_000;
    const run = () =>
      (body.statements as { sql: string; params: unknown[]; expect: number | null }[]).map((st) => {
        const { columns, rows } = this.sql.rows(st.sql, ...(st.params ?? []).map(bind));
        const changed = /^\s*(select|with\s[^;]*\bselect\b(?![\s\S]*\b(insert|update|delete)\b))/i.test(st.sql)
          ? 0
          : Number(this.one("SELECT changes() AS n")?.n ?? 0);
        if (st.expect != null && changed !== st.expect) {
          throw new Error(`unexpected row count: ${changed}, not ${st.expect}, from ${st.sql.slice(0, 80)}`);
        }
        return { columns, rows: rows.map((row) => row.map(cell)), changed };
      });
    return { results: body.atomic ? this.sql.tx(run) : run() };
  }

  private migrate(namespace: string, migrations: string[]) {
    this.sql.exec("CREATE TABLE IF NOT EXISTS enterplace_migrations (namespace TEXT PRIMARY KEY, version INTEGER NOT NULL)");
    const applied = Number(this.one("SELECT version AS v FROM enterplace_migrations WHERE namespace = ?", namespace)?.v ?? 0);
    if (applied > migrations.length) {
      throw new Error(
        `the ${namespace} tables were written by a newer Enterplace (version ${applied}, this one knows ${migrations.length}). Run the same version on every gateway.`,
      );
    }
    this.sql.tx(() => {
      migrations.slice(applied).forEach((text, i) => {
        this.sql.script(text);
        this.sql.exec(
          "INSERT INTO enterplace_migrations VALUES (?, ?) ON CONFLICT (namespace) DO UPDATE SET version = excluded.version",
          namespace,
          applied + i + 1,
        );
      });
    });
    return {};
  }

  /** The answer to one call. Unknown calls are refused by the caller. */
  call(name: string, body: any): unknown {
    const fn = (this as any)[`on_${name}`];
    if (typeof fn !== "function") return undefined;
    return this.sql.tx(() => fn.call(this, body ?? {}, Date.now()));
  }

  // Reads what changed since `seen`, after writing what the gateway gathered since its last poll: given-back
  // grants, session pins, latency samples, its load on each deployment, its health report and its heartbeat.
  on_poll(b: any, now: number) {
    for (const [id, given] of b.returns ?? []) {
      this.run("UPDATE rate_grants SET n = max(n - ?, 0) WHERE id = ?", given, id);
    }
    for (const [session, deployment] of b.pins ?? []) {
      this.run(
        "INSERT INTO affinity VALUES (?, ?, ?) ON CONFLICT (session) DO UPDATE SET deployment = excluded.deployment, seen = excluded.seen",
        session,
        deployment,
        now,
      );
    }
    for (const [deployment, samples] of b.samples ?? []) {
      this.run(
        "INSERT INTO latency VALUES (?, ?, ?, ?) ON CONFLICT (deployment, gateway) DO UPDATE SET samples = excluded.samples, updated = excluded.updated",
        deployment,
        b.gateway,
        JSON.stringify(samples),
        now,
      );
    }
    for (const [deployment, inFlight, minute, requests, tokens] of b.load ?? []) {
      this.run(
        "INSERT INTO deployment_load VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (deployment, gateway) DO UPDATE SET in_flight = excluded.in_flight, minute = excluded.minute, requests = excluded.requests, tokens = excluded.tokens, updated = excluded.updated",
        deployment,
        b.gateway,
        inFlight,
        minute,
        requests,
        tokens,
        now,
      );
    }
    if (typeof b.health === "string") {
      this.run(
        "INSERT INTO gateway_health VALUES (?, ?, ?) ON CONFLICT (gateway) DO UPDATE SET report = excluded.report, updated = excluded.updated",
        b.gateway,
        b.health,
        now,
      );
    }
    if (b.heartbeat) {
      this.run(
        "INSERT INTO replicas (gateway, host, version, schema, started, seen, policy_version, refused_version, refused) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT (gateway) DO UPDATE SET seen = excluded.seen, policy_version = excluded.policy_version, refused_version = excluded.refused_version, refused = excluded.refused",
        b.gateway,
        b.heartbeat.host,
        b.heartbeat.version,
        b.heartbeat.schema,
        now,
        now,
        b.heartbeat.policy_version ?? null,
        b.heartbeat.refused_version ?? null,
        b.heartbeat.refused ?? null,
      );
    }
    const loadFor = b.load_for * 1000;
    if (b.clean) {
      this.run("DELETE FROM gateway_health WHERE updated < ?", now - loadFor);
      this.run("DELETE FROM deployment_load WHERE updated < ?", now - loadFor);
      this.run("DELETE FROM sessions WHERE expires < ?", now);
      // Failed sign-ins long past any window, whose lockout, if any, has ended.
      this.run("DELETE FROM sign_in_failures WHERE since < ? AND coalesce(locked_until, since) < ?", now - 86_400_000, now);
      this.run("DELETE FROM affinity WHERE seen < ?", now - b.idle * 1000);
      this.run("DELETE FROM latency WHERE updated < ?", now - b.latency_for * 1000);
      this.run("DELETE FROM replicas WHERE seen < ?", now - 86_400_000);
      this.run("DELETE FROM answer_cache WHERE expires < ?", now);
      this.run(
        "DELETE FROM answer_cache WHERE key IN (SELECT key FROM (SELECT key, sum(size) OVER (ORDER BY used DESC, key) AS total FROM answer_cache) WHERE total > ?)",
        CACHE_BYTES,
      );
      this.run("DELETE FROM answer_vectors WHERE key NOT IN (SELECT key FROM answer_cache)");
    }

    const versions: Record<string, number> = {};
    for (const row of this.all("SELECT name, version FROM versions")) versions[row.name] = Number(row.version);
    const seen = b.seen ?? {};
    const changed = (name: (typeof WATCHED)[number]) => seen[name] !== versions[name];
    const out: Record<string, unknown> = { now: now / 1000, versions };
    if (changed("keys")) out.keys = this.all("SELECT body FROM keys ORDER BY id").map((r) => JSON.parse(r.body));
    if (changed("kills")) {
      out.kills = this.all("SELECT scope, value, reason, set_by, set_at FROM kills ORDER BY set_at, scope, value");
    }
    if (changed("cooldowns")) {
      out.cooling = this.all("SELECT deployment, until FROM cooldowns WHERE until > ?", now).map((r) => [
        r.deployment,
        (r.until - now) / 1000,
      ]);
    }
    if (changed("credentials")) out.credentials = this.all(`SELECT ${SHOWN}, sealed FROM credentials ORDER BY name`);
    if (changed("policy")) out.policies = this.all(`SELECT ${VERSION} FROM policy_versions ORDER BY id DESC`);
    if (changed("events")) {
      out.ended = this.all("SELECT sha256, who, expires FROM sessions WHERE who LIKE 'events:%' AND expires > ?", now).map(
        (r) => [r.sha256, String(r.who).slice(ENDED.length), (r.expires - now) / 1000],
      );
    }
    if (changed("raises")) out.raises = this.all("SELECT body FROM raises ORDER BY id").map((r) => JSON.parse(r.body));
    // Pins written since the last read, and a few seconds before it, as the Postgres store reads them.
    const since = Math.max((b.pins_since - b.pin_overlap) * 1000, now - b.idle * 1000);
    out.pins = this.all("SELECT session, deployment, seen FROM affinity WHERE seen > ?", since).map((r) => [
      r.session,
      r.deployment,
      (now - r.seen) / 1000,
    ]);
    out.latency = this.all("SELECT deployment, samples FROM latency WHERE updated > ?", now - b.latency_for * 1000).map(
      (r) => [r.deployment, JSON.parse(r.samples)],
    );
    out.load = this.all(
      "SELECT deployment, sum(in_flight) AS f, sum(CASE WHEN minute = ? THEN requests ELSE 0 END) AS r, sum(CASE WHEN minute = ? THEN tokens ELSE 0 END) AS t FROM deployment_load WHERE gateway <> ? AND updated > ? GROUP BY deployment",
      b.minute,
      b.minute,
      b.gateway,
      now - loadFor,
    ).map((r) => [r.deployment, Number(r.f), Number(r.r), Number(r.t)]);
    out.health = this.all(
      "SELECT report FROM gateway_health WHERE gateway <> ? AND updated > ? ORDER BY gateway",
      b.gateway,
      now - loadFor,
    ).map((r) => r.report);
    return out;
  }

  // Adds a key, unless its hash is already there: whether it was added, and whether its name had a key before.
  on_add_key(b: any) {
    const nameHad = !!this.one("SELECT 1 AS x FROM keys WHERE name = ?", b.key.name);
    if (this.one("SELECT 1 AS x FROM keys WHERE sha256 = ?", b.key.sha256)) return { added: false, name_had: nameHad };
    this.run("INSERT INTO keys (sha256, name, body) VALUES (?, ?, ?)", b.key.sha256, b.key.name, JSON.stringify(b.key));
    this.bump("keys");
    return { added: true, name_had: nameHad };
  }

  // Replaces a key's settings. Its name, team, organization and hash stay.
  on_update_key(b: any) {
    const row = this.one("SELECT body FROM keys WHERE sha256 = ?", b.key.sha256);
    if (!row) return { changed: false };
    const old = JSON.parse(row.body);
    const body = { ...b.key, name: old.name, team: old.team, org: old.org };
    this.run("UPDATE keys SET body = ? WHERE sha256 = ?", JSON.stringify(body), b.key.sha256);
    this.bump("keys");
    return { changed: true };
  }

  // Removes the one key whose hash starts with `prefix`. Several matching remove none.
  on_revoke(b: any) {
    const prefix = String(b.prefix);
    const matching = this.all("SELECT sha256, body FROM keys WHERE substr(sha256, 1, ?) = ?", prefix.length, prefix);
    if (matching.length !== 1) return { matching: matching.length, gone: null };
    const key = JSON.parse(matching[0].body);
    this.run("DELETE FROM keys WHERE sha256 = ?", matching[0].sha256);
    this.bump("keys");
    return { matching: 1, gone: { name: key.name, team: key.team, sha256: matching[0].sha256 } };
  }

  on_set_kill(b: any) {
    const k = b.kill;
    const old = this.one("SELECT scope, value, reason, set_by, set_at FROM kills WHERE scope = ? AND value = ?", k.scope, k.value);
    this.run(
      "INSERT INTO kills VALUES (?, ?, ?, ?, ?) ON CONFLICT (scope, value) DO UPDATE SET reason = excluded.reason, set_by = excluded.set_by, set_at = excluded.set_at",
      k.scope,
      k.value,
      k.reason,
      k.set_by,
      k.set_at,
    );
    this.bump("kills");
    return { old: old ?? null };
  }

  on_clear_kill(b: any) {
    const gone = this.one("SELECT scope, value, reason, set_by, set_at FROM kills WHERE scope = ? AND value = ?", b.scope, b.value);
    if (gone) {
      this.run("DELETE FROM kills WHERE scope = ? AND value = ?", b.scope, b.value);
      this.bump("kills");
    }
    return { gone: gone ?? null };
  }

  // Holds `usd` unless spent plus held plus it would pass `limit`. A sliding window sums its slots from `from`.
  on_reserve(b: any) {
    let used: Row | undefined;
    if (b.sliding) {
      this.run("DELETE FROM spend WHERE scope = ? AND per = ? AND period < ? AND reserved <= 0", b.scope, b.per, b.from);
      used = this.one(
        "SELECT coalesce(sum(CASE WHEN period >= ? THEN spent ELSE 0 END), 0) AS spent, coalesce(sum(reserved), 0) AS reserved FROM spend WHERE scope = ? AND per = ?",
        b.from,
        b.scope,
        b.per,
      );
    } else {
      used = this.one("SELECT spent, reserved FROM spend WHERE scope = ? AND per = ? AND period = ?", b.scope, b.per, b.period);
    }
    const spent = Number(used?.spent ?? 0);
    const reserved = Number(used?.reserved ?? 0);
    if (b.usd > b.limit || spent + reserved + b.usd > b.limit) return { done: false, spent, reserved };
    this.run(
      "INSERT INTO spend (scope, per, period, reserved) VALUES (?, ?, ?, ?) ON CONFLICT (scope, per, period) DO UPDATE SET reserved = reserved + excluded.reserved",
      b.scope,
      b.per,
      b.period,
      b.usd,
    );
    return { done: true, spent, reserved };
  }

  // Applies what requests cost and gives back what they held.
  on_settle(b: any) {
    for (const [scope, per, period, spent, reserved] of b.changes) {
      this.run(
        "INSERT INTO spend VALUES (?, ?, ?, ?, max(?, 0)) ON CONFLICT (scope, per, period) DO UPDATE SET spent = spent + excluded.spent, reserved = max(reserved + ?, 0)",
        scope,
        per,
        period,
        spent,
        reserved,
        reserved,
      );
    }
    return {};
  }

  // Grants at least `need` and at most `want` of `limit` per minute, counting every grant made in the last minute.
  // A grant counts until `hold_ms` after now: its lease and a margin for the gateway's clock.
  on_lease(b: any, now: number) {
    this.run("DELETE FROM rate_grants WHERE scope = ? AND until < ?", b.scope, now - 61_000);
    const used = this.one(
      "SELECT coalesce(sum(n), 0) AS n, min(until) AS first FROM rate_grants WHERE scope = ? AND until >= ?",
      b.scope,
      now - 60_000,
    );
    const n = Number(used?.n ?? 0);
    if (n + b.need > b.limit) {
      const first = used?.first;
      return { wait: first == null ? 1 : Math.max(1, Math.ceil((Number(first) + 60_000 - now) / 1000)) };
    }
    const take = Math.min(b.want, b.limit - n);
    this.run("INSERT INTO rate_grants (scope, until, n) VALUES (?, ?, ?)", b.scope, now + b.hold_ms, take);
    const grant = this.one("SELECT last_insert_rowid() AS id")?.id;
    return { grant: Number(grant), n: take };
  }

  on_cooled(b: any, now: number) {
    this.run(
      "INSERT INTO cooldowns VALUES (?, ?) ON CONFLICT (deployment) DO UPDATE SET until = max(until, excluded.until)",
      b.deployment,
      now + b.ms,
    );
    this.bump("cooldowns");
    return {};
  }

  on_warmed(b: any) {
    if (this.one("SELECT 1 AS x FROM cooldowns WHERE deployment = ?", b.deployment)) {
      this.run("DELETE FROM cooldowns WHERE deployment = ?", b.deployment);
      this.bump("cooldowns");
    }
    return {};
  }

  // Takes or keeps a deployment's probe: free, expired, or already this gateway's.
  on_probe_lease(b: any, now: number) {
    const row = this.one("SELECT gateway, until FROM probe_leases WHERE deployment = ?", b.deployment);
    if (row && row.until >= now && row.gateway !== b.gateway) return { held: false };
    this.run(
      "INSERT INTO probe_leases VALUES (?, ?, ?) ON CONFLICT (deployment) DO UPDATE SET gateway = excluded.gateway, until = excluded.until",
      b.deployment,
      b.gateway,
      now + b.ttl * 1000,
    );
    return { held: true };
  }

  on_end_events_session(b: any, now: number) {
    this.run(
      "INSERT INTO sessions VALUES (?, ?, ?) ON CONFLICT (sha256) DO UPDATE SET expires = max(expires, excluded.expires)",
      b.key,
      ENDED + b.by,
      now + b.seconds * 1000,
    );
    this.bump("events");
    return {};
  }

  on_open_session(b: any, now: number) {
    this.run("DELETE FROM sessions WHERE expires < ?", now);
    this.run("INSERT INTO sessions VALUES (?, ?, ?)", b.sha256, b.who, now + b.seconds * 1000);
    return {};
  }

  on_session(b: any, now: number) {
    return { who: this.one("SELECT who FROM sessions WHERE sha256 = ? AND expires > ?", b.sha256, now)?.who ?? null };
  }

  on_end_session(b: any) {
    this.run("DELETE FROM sessions WHERE sha256 = ?", b.sha256);
    return {};
  }

  // Counts a failed console sign-in under its scope when `failed` is given ({ max, window, lock } in seconds), then
  // says how many seconds the scope is still locked out for. The object runs one call at a time, so two gateways
  // counting the same scope cannot both miss the limit.
  on_sign_in_lock(b: any, now: number) {
    const f = b.failed;
    if (f) {
      const row = this.one("SELECT failures, since, locked_until FROM sign_in_failures WHERE scope = ?", b.scope);
      const fresh = !row || Number(row.since) < now - f.window * 1000;
      const failures = fresh ? 1 : Number(row.failures) + 1;
      const locked = failures >= f.max ? now + f.lock * 1000 : (row?.locked_until ?? null);
      this.run(
        "INSERT INTO sign_in_failures VALUES (?, ?, ?, ?) ON CONFLICT (scope) DO UPDATE SET failures = excluded.failures, since = excluded.since, locked_until = excluded.locked_until",
        b.scope,
        failures,
        fresh ? now : Number(row.since),
        locked,
      );
    }
    const until = this.one("SELECT locked_until FROM sign_in_failures WHERE scope = ?", b.scope)?.locked_until;
    return { seconds: until != null && Number(until) > now ? Math.ceil((Number(until) - now) / 1000) : null };
  }

  on_sign_in_clear(b: any) {
    this.run("DELETE FROM sign_in_failures WHERE scope = ?", b.scope);
    return {};
  }

  // The master key's check value: the first gateway's is kept, and every later one must open it.
  on_master(b: any) {
    this.run("INSERT INTO master VALUES (1, ?) ON CONFLICT (id) DO NOTHING", b.sealed);
    return { sealed: this.one("SELECT sealed FROM master WHERE id = 1")?.sealed };
  }

  private shown(name: string) {
    return this.one(`SELECT ${SHOWN} FROM credentials WHERE name = ?`, name) ?? null;
  }

  on_add_credential(b: any) {
    if (this.shown(b.name)) return { credential: null };
    this.run(
      "INSERT INTO credentials (name, provider, sealed, fingerprint, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      b.name,
      b.provider,
      b.sealed,
      b.fingerprint,
      b.by,
      b.at,
    );
    this.bump("credentials");
    return { credential: this.shown(b.name) };
  }

  on_rotate_credential(b: any) {
    if (!this.shown(b.name)) return { credential: null };
    this.run(
      "UPDATE credentials SET sealed = ?, fingerprint = ?, rotated_by = ?, rotated_at = ?, generation = generation + 1 WHERE name = ?",
      b.sealed,
      b.fingerprint,
      b.by,
      b.at,
      b.name,
    );
    this.bump("credentials");
    return { credential: this.shown(b.name) };
  }

  on_remove_credential(b: any) {
    const gone = this.shown(b.name);
    if (gone) {
      this.run("DELETE FROM credentials WHERE name = ?", b.name);
      this.bump("credentials");
    }
    return { credential: gone };
  }

  private live(): number | null {
    const id = this.one("SELECT id FROM policy_versions WHERE state = 'live'")?.id;
    return id == null ? null : Number(id);
  }

  // Adds a policy version only while `base` is still the live one. A refusal says what is live now.
  on_add_policy_version(b: any) {
    const live = this.live();
    if (live !== (b.base ?? null)) return { conflict: "base", live };
    if (!b.pending) this.run("UPDATE policy_versions SET state = 'retired' WHERE state = 'live'");
    this.run(
      "INSERT INTO policy_versions (text, sha256, base, note, created_by, created_at, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
      b.text,
      b.sha256,
      b.base ?? null,
      b.note,
      b.by,
      b.at,
      b.pending ? "pending" : "live",
    );
    const id = this.one("SELECT last_insert_rowid() AS id")?.id;
    this.bump("policy");
    return { version: this.one(`SELECT ${VERSION} FROM policy_versions WHERE id = ?`, id) };
  }

  // Puts a pending version live, only while the version it was drafted on is still live, or rejects it.
  on_decide_policy_version(b: any) {
    const row = this.one("SELECT state, base FROM policy_versions WHERE id = ?", b.id);
    if (!row) return { conflict: "missing" };
    if (row.state !== "pending") return { conflict: "state", state: row.state };
    if (b.approve) {
      if (this.live() !== (row.base == null ? null : Number(row.base))) return { conflict: "stale" };
      this.run("UPDATE policy_versions SET state = 'retired' WHERE state = 'live'");
    }
    this.run(
      "UPDATE policy_versions SET state = ?, decided_by = ?, decided_at = ? WHERE id = ?",
      b.approve ? "live" : "rejected",
      b.by,
      b.at,
      b.id,
    );
    this.bump("policy");
    return { version: this.one(`SELECT ${VERSION} FROM policy_versions WHERE id = ?`, b.id) };
  }

  on_put_raise(b: any) {
    this.run("INSERT INTO raises VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET body = excluded.body", b.raise.id, JSON.stringify(b.raise));
    this.bump("raises");
    return {};
  }

  on_replicas(b: any, now: number) {
    const time = (ms: number) => new Date(Number(ms)).toISOString().slice(0, 19) + "Z";
    return {
      replicas: this.all("SELECT * FROM replicas ORDER BY started DESC, gateway").map((r) => ({
        gateway: r.gateway,
        host: r.host,
        version: r.version,
        schema: r.schema,
        started: time(r.started),
        seen: time(r.seen),
        healthy: r.seen > now - b.healthy_for * 1000,
        policy_version: r.policy_version ?? null,
        refused_version: r.refused_version ?? null,
        refused: r.refused ?? null,
      })),
    };
  }

  on_cache_get(b: any, now: number) {
    const row = this.one(
      "SELECT status, content_type, body, origin, cost, expires FROM answer_cache WHERE key = ? AND scope = ? AND expires > ?",
      b.key,
      b.scope,
      now,
    );
    if (!row) return { answer: null };
    this.run("UPDATE answer_cache SET used = ? WHERE key = ?", now, b.key);
    return { answer: { ...row, left: (row.expires - now) / 1000 } };
  }

  on_cache_put(b: any, now: number) {
    this.run(
      "INSERT INTO answer_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET scope = excluded.scope, status = excluded.status, content_type = excluded.content_type, body = excluded.body, origin = excluded.origin, cost = excluded.cost, expires = excluded.expires, used = excluded.used, size = excluded.size",
      b.key,
      b.scope,
      b.status,
      b.content_type ?? null,
      b.body,
      b.origin,
      b.cost,
      now + b.ttl * 1000,
      now,
      b.body.length,
    );
    if (b.vector) {
      this.run(
        "INSERT INTO answer_vectors VALUES (?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET partition = excluded.partition, vector = excluded.vector, created = excluded.created",
        b.key,
        b.vector.partition,
        JSON.stringify(b.vector.values),
        now,
      );
    }
    return {};
  }

  on_cache_vectors(b: any, now: number) {
    return {
      vectors: this.all(
        "SELECT v.key, v.vector FROM answer_vectors v JOIN answer_cache c ON c.key = v.key WHERE v.partition = ? AND c.expires > ? ORDER BY v.created DESC LIMIT ?",
        b.partition,
        now,
        b.limit,
      ).map((r) => [r.key, JSON.parse(r.vector)]),
    };
  }

  on_setting(b: any) {
    return { value: this.one("SELECT value FROM settings WHERE name = ?", b.name)?.value ?? null };
  }

  on_set_setting(b: any, now: number) {
    this.run(
      "INSERT INTO settings VALUES (?, ?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated = excluded.updated",
      b.name,
      b.value,
      now,
    );
    return {};
  }

  // What a scope has spent and holds for the current UTC day and month.
  on_spend(b: any, now: number) {
    const day = new Date(now).toISOString().slice(0, 10);
    return {
      rows: this.all(
        "SELECT per, period, spent, reserved FROM spend WHERE scope = ? AND period IN (?, ?)",
        b.scope,
        day,
        day.slice(0, 7),
      ),
    };
  }
}

/** Answers one store request: POST /v1/<call> with a JSON body. */
export async function serve(core: StoreCore, req: Request): Promise<Response> {
  const call = /^\/v1\/([a-z_]+)$/.exec(new URL(req.url).pathname)?.[1];
  if (req.method !== "POST" || !call) return new Response("POST /v1/<call>\n", { status: 404 });
  try {
    const body = await req.json();
    const answer = call.startsWith("sql") ? await core.sqlCall(call, body) : core.call(call, body);
    if (answer === undefined) {
      return new Response(
        `the store has no call "${call}": the gateway is newer than this Worker. Deploy the Worker of the same Enterplace version.\n`,
        { status: 404 },
      );
    }
    return Response.json(answer);
  } catch (err) {
    return new Response(`the store refused ${call}: ${err instanceof Error ? err.message : String(err)}\n`, { status: 500 });
  }
}
