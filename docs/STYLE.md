# Docs style guide

The docs site is Astro Starlight. Pages live in `docs/src/content/docs/<section>/<page>.mdx`. Build with `npm run build` in `docs/`.

## Page shape

Every page:

```mdx
---
title: Budgets and rate limits
description: One sentence, under 160 characters, that says what the reader can do after this page.
sidebar:
  order: 3
---

import { Aside, Tabs, TabItem, Steps, Card, CardGrid, LinkCard } from '@astrojs/starlight/components';

One or two sentences: what this feature is and why an operator uses it.

## Section
```

Order inside a feature page: what it is, a minimal working example, configuration (table of fields), behavior and edge cases, errors (refusal codes), related pages (2 to 4 LinkCards or a short list).

## Components

- `<Steps>` around an ordered list for any procedure with more than two steps.
- `<Tabs>` when the same thing is done more than one way (Binary / Docker, curl / Python / TypeScript, macOS / Linux). Use `syncKey` for repeated tab sets (`syncKey="install"`, `syncKey="lang"`).
- `<Aside type="note|tip|caution|danger">` for one point that matters. At most three per page. `caution` for anything that exposes keys or loses audit records.
- Tables for fields, flags, codes. Columns: Field | Type | Default | Description.
- Code blocks always carry a language. Use a `title="gantry.policy.yaml"` on file contents. Show command output in a separate `text` block.
- Links between pages are root-relative with a trailing slash: `/governance/budgets/`. Anchors work: `/reference/refusal-codes/#budget_exceeded`.

## Voice

- Direct and declarative. Second person, present tense. "Gantry refuses the request with `budget_exceeded`."
- Short paragraphs, 1 to 3 sentences. One idea per sentence.
- Lead with what the reader gets, then how.
- No marketing words: blazing, seamless, powerful, robust, effortless, enterprise-grade, game-changing, simply, just.
- No em dashes or en dashes anywhere. Use a hyphen, a comma, a colon or parentheses.
- No hedging and no history ("in this version", "for now", "we tested on a laptop"). Limits go in one `Aside type="note"` or in the Project status page, not sprinkled through prose.
- Name things exactly: CLI flags, YAML keys, refusal codes, file names, in code spans.

## Accuracy

Every fact comes from the legacy docs in `docs/_legacy/` or the source in `crates/`. Do not invent flags, fields, routes, codes, numbers or integrations. When unsure, check `target/release/gantry --help` or grep the source. A full policy file in a ```yaml block (one with a top-level `version:`) is checked by `scripts/check_examples.py`, so it must pass `gantry check`.
