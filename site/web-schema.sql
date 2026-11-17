-- The enterplace-web D1 database, written by site/worker.js.
-- Apply: npx --prefix docs wrangler d1 execute enterplace-web --remote --file site/web-schema.sql
CREATE TABLE IF NOT EXISTS hits (
  t TEXT NOT NULL,          -- UTC time, ISO 8601
  site TEXT NOT NULL,       -- host name: enterplace.dev, docs.enterplace.dev, or an old host
  kind TEXT NOT NULL,       -- view (a browser), agent (a bot, an AI agent or a script), install (install.sh), click
  path TEXT NOT NULL,
  event TEXT NOT NULL,      -- clicks: data-track, else the button or link text; "copy"; or a name passed to track()
  detail TEXT NOT NULL DEFAULT '', -- clicks: the link target or the copied code; copies: the start of the text
  source TEXT NOT NULL,     -- utm_source or ref, else the referring host when it is another site
  agent TEXT NOT NULL,      -- empty for a browser
  country TEXT NOT NULL,
  status INTEGER NOT NULL   -- the response status; 0 for clicks
);
CREATE INDEX IF NOT EXISTS hits_t ON hits (t);
-- Added 2026-11-16 on the live database: ALTER TABLE hits ADD COLUMN detail TEXT NOT NULL DEFAULT '';
