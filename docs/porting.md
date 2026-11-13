# Porting a feature from the Cloudflare app

Step S.4 moves the enterprise features of the Cloudflare app (`cloud/control-plane`, TypeScript on D1) into this
binary, behind the license, on the store's Postgres. Members was the first; this is how it was done, for the next one.

## Where a feature plugs in

The open source crates expose these extension points. Nothing in them knows about licenses.

| What | Open source side | What a feature does with it |
|---|---|---|
| Startup | `gantry_server::serve_policy_with(.., extend)`, `governed_with` | `extend(Host)` runs once the files are checked and the store is open, and returns a `gantry_server::Extension`. `src/main.rs` passes `enterprise::extend`. |
| Console pages | `gantry_console::Extension { nav, routes, sign_in, accounts }` | Routes nested at `/console`, handlers take `State<Console>`. `Console::signed_in` gives who is signed in (`Admin`, with `via` and `role`), `Console::page` draws the shell with the nav, `Console::audit` writes an admin record, `Console::sign_in_account` opens a session the feature vouches for through `accounts`. Markup comes from `gantry_console::html`. |
| Gateway routes | `gantry_server::Extension::routes` | Routes outside the console (an API such as SCIM). Merged into the gateway's router. |
| Tables | `Host::postgres`: `PgStore::migrate(namespace, migrations)`, `PgStore::connect()` | Every enterprise table is created by `enterprise::MIGRATIONS`, applied under the namespace `enterprise`. `enterprise::Db` holds a connection of the features' own, so transactions are safe. |
| /healthz | `gantry_server::Extension::health` | Already used for the license; add fields only when an operator needs them to tell the feature is working. |

## The members port, as the example

- `src/enterprise/mod.rs`: `extend` adds the license to /healthz, then, only if `status.unlocked("members")`, runs
  the migrations and calls `members::register`. Without the feature it calls `members::locked`, which answers the
  feature's addresses with the `license_required` refusal and adds no nav entry and no sign-in link.
- `src/enterprise/members.rs`: `MIGRATION` (two tables), `register` (nav entry, routes, password sign-in link,
  `accounts`), the handlers, and the rules ported from `members.ts` and `account.ts`.
- `src/enterprise/members/tests.rs`: the Cloudflare tests' behaviour as Rust tests against Postgres.

Rules the port follows, which the next ones keep:

- One org per install: the Cloudflare app's `org` path segment and `memberships` table go away. A person's row
  holds their role.
- Same hashing, same limits, same messages where they still make sense, so accounts and habits carry over.
- Who is signed in maps to the feature's roles in one place (`Role::of`): an admin key acts as owner, single sign-on
  as admin or viewer.
- Every change is an admin record, written before the change is made (`Console::audit`); if it cannot be recorded,
  nothing is done.
- Keys are read and revoked through `gantry_core::config::read_keys` and `gantry_core::keyfile::revoke` on the keys
  path from `Host::keys`, so every gateway on the database sees the change.
- Checks that must hold across replicas (the last owner) run in one transaction with the rows locked.

## Adding the next feature

1. Read the feature in `cloud/control-plane/src/app/*.ts`, its tables in `migrations/*.sql`, and its tests in
   `cloud/tests/test_*.py`.
2. Write its tests first, in `src/enterprise/<feature>/tests.rs`, with `enterprise::testing` (a gateway on a fresh
   database, a browser that keeps the console cookie).
3. Append its tables to `enterprise::MIGRATIONS` as a new entry. Never edit one that has shipped.
4. Add `src/enterprise/<feature>.rs` with `FEATURE`, `register` and `locked`, and call them from `extend`.
5. Write its page in the open source docs site (`docs/src/content/docs/operations/`), as `members.mdx`.

## Checklist

- [ ] Behaviour parity: every check in the Cloudflare app's tests for the feature has a Rust test, or the report says
      why it does not apply to a self-hosted install (orgs, the admin API, staff).
- [ ] The tests run against Postgres (`GANTRY_TEST_DATABASE_URL`; CI runs a postgres:16 service).
- [ ] A license gate test: without the feature (no license, and a license without it) the pages answer
      `license_required`, the nav and sign-in page do not offer it, and no tables are made.
- [ ] Every change writes an admin record; a refused one is recorded with its code.
- [ ] A docs page.
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (and `--all-features`), `cargo test`.

## Running the tests

```sh
docker run -d --name gantry-pg -e POSTGRES_PASSWORD=test -p 55433:5432 postgres:16
GANTRY_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55433/postgres cargo test
```

The open source checkout must sit beside this one as `../gantry`, since the crates are path dependencies.

## Ported

- Members (`members.rs`).
- SIEM export and retention with legal hold (`siem.rs`, `siem/sinks.rs`, features `siem` and `retention`). One org
  per install and one replica per audit log: each replica reads its own chain into `enterprise_audit` and sends it
  on; retention seals and retires whole segments through `gantry_core::audit::{seal, retire}`.

## Still to port

SCIM (with its tokens and the one-time password links for people it makes), policy editing with dry run and approval, reports, workload identity, Claude Code watch mode, devices, TOTP. The
admin API's "add an existing user to an org" has no counterpart in a one-org install.
