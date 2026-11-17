# Porting a console page to the app

The console is moving page by page from server-rendered Rust HTML to this app (React, shadcn/ui on Tailwind, themed
only with the Enterplace tokens). People is the worked example: read
`crates/enterplace-console/src/people.rs` and `console-ui/src/pages/People.tsx` side by side before starting.

A port is one commit that leaves `main` green: the JSON API, the app page, the old route redirecting, the old Rust
page deleted, and every test of the old page moved to the API.

## The two files a port adds

1. **`crates/enterplace-console/src/<page>.rs`**: the page's JSON API and the redirect from its old address.
   - `pub(crate) fn routes() -> Router<Console>` holds everything of the page: the redirect of the old GET
     address(es) and `/api/<page>...` endpoints.
   - Use the shared helpers in `api.rs`: `signed_in` (session, and the same-origin check for a change),
     `body_of` (JSON, or a plain `name=value` form), `text`, `ok`, `bad`, `Fail`, `answer`, `sentence`.
   - Keep the existing write path. Move the old handler's logic into the endpoint and return JSON instead of HTML:
     the same permission check (call `read_only(...)` so the refusal is recorded), the same `record(...)` before
     the change, the same `keyfile`/`versions`/store call, the same error words. A policy change goes through
     `api::commit`, which checks it as `enterplace check` does, records it with who made it, and saves it as a store
     version or an atomic file write.
   - Status codes: 401 not signed in, 403 the role may not, 400 invalid input (message names the cause and the fix),
     404 the thing is gone, 409 it changed since it was read, 503 the store or the audit log cannot be reached.
   - Compute in Rust what tests should pin (status words, money and time formatting, lead lines, empty states via
     `start::empty_for`), and send it ready to show. The app only lays it out.
2. **`console-ui/src/pages/<Page>.tsx`**: the page, built from `src/components/ui` (shadcn, already themed) and
   `src/components/page.tsx` (`Head`, `Panel`, `Empty`, `Problem`, `Refusal`), `Copy` for values shown once, and
   `Remove` for confirm-to-delete.
   - `useData<T>("<page>", everyMs, paused)` loads the API and reloads after each change; a change goes through
     `change(() => api.post(...))`, which toasts the answer and returns the refusal for the dialog to show beside
     its form.
   - Dialogs and filters live in the `#` route's query (`#/people?issue=1`, `?edit=<sha>`), so old links and the
     redirect can open them. Set it with `window.location.hash`.

## The one line each shared file gets

| File | Line |
| --- | --- |
| `crates/enterplace-console/src/lib.rs` | `mod <page>;` beside `mod people;`, and `.merge(<page>::routes())` after `.merge(people::routes())`. Delete the old `.route(...)` lines of the page. |
| `console-ui/src/pages/index.ts` | one entry in `PAGES` (`{ route: "/<page>", label: "...", page: <Page> }`), and take the page's line out of `SERVER_PAGES`. |
| `crates/enterplace-console/app/` | rebuilt by `npm run build` in `console-ui/` and committed. Do not hand-merge it: on a rebase conflict, take either side and run the build again. |

Old code is deleted from where it lives (`pages.rs`, `lib.rs`, `edit.rs`, `insights.rs`, `start.rs`); that is the
only other place two ports may meet, and each port deletes only its own functions. If a helper of the old page is
used by another page, leave it and make it `pub(crate)` rather than moving it.

The server-rendered nav (`crates/enterplace-console/src/html.rs`, `GROUPS`) keeps the old href: it redirects to the
app, so it needs no change.

## Redirect of the old address

The old GET address answers `303` to `/console/app/#/<page>?<what its query asked for>` (see `people::moved`). It
needs no session: the app asks for one, and sign-in returns to the app route, `#` part included. Old POST form
routes are removed; their tests move to the API.

## Live updates

A page that showed live data keeps it by polling its API: `useData("<page>", 5000, dialogOpen)` reloads every 5
seconds while no dialog is open. A page that streamed (`/console/live.json`, `console.js`) reads the same JSON from
the app instead of the server-rendered script. The gateway applies each change within 2 seconds, so the next poll
shows it.

## Tests

- Rewrite each test of the old page against the API, in the file it was in (most are in
  `crates/enterplace-console/tests/console.rs`; it has `call`, `people` and `key_named` helpers to copy). Assert the
  JSON fields the page shows, not HTML. Keep every behavior the old test pinned: refusals, records, file contents,
  roles.
- The old address: assert its `303` and `Location`.
- Other crates call console routes too: `crates/enterplace-server/tests/`, `enterprise/src/enterprise/*/tests.rs`,
  and the browser checks in `scripts/` (`browser_check.py`, `console_edit_check.py`, `onboarding_check.py`,
  `ftue_check.py`). `grep -rn "/console/<page>"` across the repository before the commit.
- Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and
  `npm run build` in `console-ui/` (then `git diff --exit-code crates/enterplace-console/app`).

## Rules that still hold

No em-dashes or en-dashes. No `unwrap` or `expect`. Comments say why. No color, radius, shadow, spacing or font
size that is not a token: `src/index.css` clears Tailwind's own, so a stock class does nothing.
