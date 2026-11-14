# Gantry website

The site at https://gantry.eliran.me. Static, hand-written HTML, CSS and one small script. No framework and no dependencies.

## Layout

| Path | What it is |
|---|---|
| `src/pages/` | One file per page. `use-cases/coding-agents.html` becomes `/use-cases/coding-agents/`. |
| `src/partials/` | Shared pieces: `layout.html` (head, header, footer), `cta.html`, the mark and icons. |
| `src/static/` | Copied as they are: `styles.css`, `site.js`, fonts, logos, images, `robots.txt`, `_redirects`. |
| `build.py` | Builds `public/` from `src/`. Python standard library only. |
| `public/` | The built site. Committed, and served by the Cloudflare Worker `gantry-site`. Do not edit it by hand. |

## Build

```sh
python3 build.py --check
```

`--check` fails the build when an internal link, an image or an `#anchor` points at nothing, or when a page holds an en or em dash.

The build also writes `sitemap.xml`, fills each page's title, description, canonical URL and Open Graph tags, and marks the current page in the navigation.

## Write a page

A page starts with a comment of `key: value` lines, and the rest is the content of `<main>`:

```html
<!--
title: The text of the title tag
description: One or two sentences for search results and link previews.
nav: use-cases
-->
<section class="wrap head">...</section>
```

`nav` is the header group to mark: `product`, `use-cases`, `learn` or `enterprise`.

Short forms the build expands:

| In the source | Becomes |
|---|---|
| `href="docs:/start/why/"` | A link to that page of the docs site |
| `{{> name}}` | The partial `src/partials/name.html` |
| `{{version}}` | The version set at the top of `build.py` |
| `{{gate ... }}` | The request motif: lanes, discs and audit records. See `gate()` in `build.py` for the lines it takes. |

Add a new page to the header and footer in `src/partials/layout.html`.

## Rules for content

- Facts come from the docs. When unsure, leave it out.
- No customers exist: no customer names, logos, quotes, metrics, prices or latency numbers. Example rollouts are labelled as examples.
- Lime means a request passed. Flame means a request was stopped. Nothing else is colored.
- No en or em dashes.

## Preview and deploy

```sh
python3 -m http.server 4410 --bind 127.0.0.1 --directory public
npx --prefix /Users/lasso/Documents/private/gantry/gantry/docs wrangler deploy
```

Run the deploy from this folder. `wrangler.jsonc` serves `public/` with clean URLs and `404.html` for unknown paths.
