# Enterplace on Railway

The template: https://railway.com/deploy/ImwBt6 (made in the eliransu workspace).

Railway templates are made in the Railway dashboard, not from a file in the repository (`railway.json` sets build
and deploy options for a service built from source; it cannot name a prebuilt image or add a database). This is
the template to make once, then publish. The docs page links its button:
https://docs.enterplace.dev/deploy/one-click/#railway

## Make the template

1. Railway dashboard, Workspace, Templates, New Template.
2. Add a database: PostgreSQL. Keep its service name `Postgres` (the variable below refers to it by name).
3. Add a service: Docker Image, `ghcr.io/eliransu/enterplace:latest`. Name it `enterplace`.
4. In the `enterplace` service, Variables:

   | Variable | Value | Why |
   |---|---|---|
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` | The store: keys, the policy and spend |
   | `PGSSLMODE` | `require` | Railway's Postgres serves TLS with a self-signed certificate: encrypted, not verified. If the logs say the server offers no TLS, use `disable` (the private network is encrypted by Railway) |
   | `PORT` | `8080` | Where Enterplace listens |
   | `OPENAI_API_KEY` | empty, description "Your OpenAI API key (or set ANTHROPIC_API_KEY or GEMINI_API_KEY instead)" | Railway asks for it at deploy |
   | `ANTHROPIC_API_KEY` | empty, optional | |

5. In the `enterplace` service, Settings: Networking, Public Networking, generate a domain on port 8080; Deploy,
   Healthcheck Path `/healthz`. No volume: Railway volumes belong to root and the image runs as an unprivileged
   user. The audit log stays on the container's disk and starts a new chain at each deploy.
6. Create the template, then Publish. Railway shows its code; the button is
   `https://railway.com/new/template/<code>`. Put that code in
   `docs/src/content/docs/deploy/one-click.mdx` in place of `RAILWAY_TEMPLATE_CODE`.

## After a deploy

The `enterplace` service's Deploy Logs show the admin key once (`export ENTERPLACE_KEY=...`). The console is at
`https://<the generated domain>/console`.
