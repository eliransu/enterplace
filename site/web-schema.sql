-- The gantry-web D1 database, written by site/worker.js.
-- Apply: npx --prefix docs wrangler d1 execute gantry-web --remote --file site/web-schema.sql
CREATE TABLE IF NOT EXISTS hits (
  t TEXT NOT NULL,          -- UTC time, ISO 8601
  site TEXT NOT NULL,       -- host name: gantry.enterplace.dev, gantry-docs.enterplace.dev, or an old host
  kind TEXT NOT NULL,       -- view (a browser), agent (a bot, an AI agent or a script), install (install.sh), click
  path TEXT NOT NULL,
  event TEXT NOT NULL,      -- clicks: the button or link text, or "copy: " and the start of what was copied
  source TEXT NOT NULL,     -- utm_source or ref, else the referring host when it is another site
  agent TEXT NOT NULL,      -- empty for a browser
  country TEXT NOT NULL,
  status INTEGER NOT NULL   -- the response status; 0 for clicks
);
CREATE INDEX IF NOT EXISTS hits_t ON hits (t);
