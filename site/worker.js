// The Worker in front of the website and the docs. It records page views, agent fetches, install.sh downloads and
// clicks in the gantry-web D1 database, then serves the static files. No cookie is set and no IP address is stored.
// It also serves /_t.js, the click script both sites load. Query it with scripts/web_stats.sh. The schema is in site/web-schema.sql.

// Matched in order against the lowercased user agent; the first hit names the agent.
const AGENTS = [
  ['claudebot', 'ClaudeBot'], ['claude-user', 'Claude user fetch'], ['claude-searchbot', 'Claude search'],
  ['claude-code', 'Claude Code'], ['claude-cli', 'Claude Code'], ['anthropic', 'Anthropic'],
  ['chatgpt-user', 'ChatGPT user fetch'], ['oai-searchbot', 'ChatGPT search'], ['gptbot', 'GPTBot'],
  ['perplexity-user', 'Perplexity user fetch'], ['perplexitybot', 'Perplexity'], ['google-extended', 'Google AI'],
  ['googlebot', 'Googlebot'], ['bingbot', 'Bing'], ['applebot', 'Applebot'], ['duckassistbot', 'DuckDuckGo AI'],
  ['meta-externalagent', 'Meta AI'], ['ccbot', 'Common Crawl'], ['bytespider', 'Bytespider'], ['cursor', 'Cursor'],
  ['curl', 'curl'], ['wget', 'wget'], ['python', 'Python'], ['go-http-client', 'Go'],
  ['undici', 'Node'], ['node', 'Node'], ['axios', 'Node'], ['bot', 'Other bot'], ['spider', 'Other bot'],
];

// Pages, plus the plain text files agents read. Styles, scripts, fonts and images are not counted.
const COUNTED = /(\/|\.html|\/[^./]+|\/install\.sh|\.txt|\.md)$/;

function agentOf(ua) {
  const low = ua.toLowerCase();
  const hit = AGENTS.find(([needle]) => low.includes(needle));
  if (hit) return hit[1];
  return low.startsWith('mozilla/') ? '' : 'Other agent';
}

function sourceOf(url, request) {
  const utm = url.searchParams.get('utm_source') || url.searchParams.get('ref');
  if (utm) return utm.slice(0, 80);
  try {
    const from = new URL(request.headers.get('referer') || '');
    return from.hostname === url.hostname ? '' : from.hostname;
  } catch {
    return '';
  }
}

function record(env, ctx, row) {
  if (!env.WEB) return;
  ctx.waitUntil(env.WEB.prepare(
    'INSERT INTO hits (t, site, kind, path, event, detail, source, agent, country, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).bind(new Date().toISOString(), row.site, row.kind, row.path, row.event || '', row.detail || '', row.source || '', row.agent || '',
    row.country || '', row.status || 0).run().catch(() => {}));
}

// The PostHog project (US cloud). The key is public by design: it can only send events, not read them.
const POSTHOG_KEY = 'phc_qZHhywTyXPLH8LuvmxoyUBcqMCwyGYegKAWuEjXKcW7P';

// Every click on a link or button, named by its data-track attribute, else its label; copies; and track(name, detail)
// for custom events from any script. Capture runs before a button relabels itself (Copied). Each event goes to D1
// (through /_e) and to PostHog, which also records page views, page leaves and autocaptured clicks. PostHog keeps its
// id in memory only: no cookie, no local storage, so no consent banner; a visitor is new on every page load.
const TRACKER = `(() => {
  const waiting = [];
  const ph = (e, d) => { if (window.posthog && window.posthog.__loaded) window.posthog.capture(e, d ? { detail: d } : {}); else waiting.push([e, d]); };
  const s = document.createElement('script');
  s.src = 'https://us-assets.i.posthog.com/static/array.js';
  s.async = true;
  s.onload = () => {
    if (!window.posthog || !window.posthog.init) return;
    window.posthog.init('${POSTHOG_KEY}', { api_host: 'https://us.i.posthog.com', defaults: '2025-05-24', persistence: 'memory', person_profiles: 'identified_only' });
    waiting.splice(0).forEach(([e, d]) => window.posthog.capture(e, d ? { detail: d } : {}));
  };
  document.head.appendChild(s);
  const send = (e, d) => { ph(String(e), d ? String(d) : ''); try { navigator.sendBeacon('/_e', JSON.stringify({ e: String(e), d: String(d || ''), p: location.pathname })); } catch (err) { /* not counted */ } };
  const words = (t) => (t || '').trim().replace(/\\s+/g, ' ').slice(0, 60);
  window.track = send;
  document.addEventListener('click', (ev) => {
    const el = ev.target.closest && ev.target.closest('[data-track], a, button');
    if (!el) return;
    const name = el.dataset.track || words(el.getAttribute('aria-label') || el.textContent) || words(el.title) || el.getAttribute('href') || '';
    send(name, el.getAttribute('href') || el.dataset.code || '');
  }, true);
  document.addEventListener('copy', () => { const t = words(String(getSelection())); if (t) send('copy', t); });
})();
`;

// /_stats: this host's numbers as a page, behind HTTP basic auth (any user name, the STATS_PASSWORD secret).
const REPORT = [
  ['By kind', "SELECT kind, count(*) n FROM hits WHERE site = ?1 AND t >= ?2 GROUP BY kind ORDER BY n DESC"],
  ['Pages, browsers', "SELECT path, count(*) n FROM hits WHERE site = ?1 AND t >= ?2 AND kind = 'view' GROUP BY path ORDER BY n DESC LIMIT 25"],
  ['Sources', "SELECT source, kind, count(*) n FROM hits WHERE site = ?1 AND t >= ?2 AND source != '' GROUP BY source, kind ORDER BY n DESC LIMIT 25"],
  ['Clicks, copies and events', "SELECT event, detail, path, count(*) n FROM hits WHERE site = ?1 AND t >= ?2 AND kind = 'click' GROUP BY event, detail, path ORDER BY n DESC LIMIT 40"],
  ['Agents', "SELECT agent, count(*) n, count(DISTINCT path) pages FROM hits WHERE site = ?1 AND t >= ?2 AND agent != '' GROUP BY agent ORDER BY n DESC LIMIT 25"],
  ['Installs by day', "SELECT substr(t, 1, 10) day, count(*) n FROM hits WHERE site = ?1 AND t >= ?2 AND kind = 'install' GROUP BY day ORDER BY day DESC"],
  ['Browser views by day', "SELECT substr(t, 1, 10) day, count(*) n FROM hits WHERE site = ?1 AND t >= ?2 AND kind = 'view' GROUP BY day ORDER BY day DESC"],
  ['Countries, browsers', "SELECT country, count(*) n FROM hits WHERE site = ?1 AND t >= ?2 AND kind = 'view' GROUP BY country ORDER BY n DESC LIMIT 15"],
];
const esc = (v) => String(v ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function allowed(request, env) {
  const [kind, value] = (request.headers.get('authorization') || '').split(' ');
  if (!env.STATS_PASSWORD || kind !== 'Basic' || !value) return false;
  try { return atob(value).split(':').slice(1).join(':') === env.STATS_PASSWORD; } catch { return false; }
}

async function stats(url, env) {
  const days = Math.min(Math.max(parseInt(url.searchParams.get('days') || '7', 10) || 7, 1), 365);
  const since = new Date(Date.now() - days * 864e5).toISOString();
  const sections = await Promise.all(REPORT.map(async ([title, sql]) => {
    const { results } = await env.WEB.prepare(sql).bind(url.hostname, since).all();
    const cols = results.length ? Object.keys(results[0]) : [];
    const body = results.length
      ? `<table><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr>${results.map((r) => `<tr>${cols.map((c) => `<td>${esc(r[c])}</td>`).join('')}</tr>`).join('')}</table>`
      : '<p>None yet.</p>';
    return `<h2>${esc(title)}</h2>${body}`;
  }));
  const pick = [1, 7, 30, 90].map((d) => d === days ? `<b>${d} days</b>` : `<a href="?days=${d}">${d} days</a>`).join(' · ');
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(url.hostname)} stats</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color-scheme:light dark}table{border-collapse:collapse;width:100%;margin-bottom:8px}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid #8884;overflow-wrap:anywhere}td:last-child,th:last-child{text-align:right}h2{font-size:15px;margin-top:28px}</style>
<h1>${esc(url.hostname)}</h1><p>Last ${days} days. ${pick}. Views are page loads, not people.</p>${sections.join('')}`,
  { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const country = request.cf?.country || '';

    if (url.pathname === '/_stats') {
      if (!allowed(request, env)) return new Response('Password needed', { status: 401, headers: { 'www-authenticate': 'Basic realm="Gantry stats"' } });
      return stats(url, env);
    }

    if (url.pathname === '/_t.js') {
      return new Response(TRACKER, { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=3600' } });
    }

    // Clicks, copies and custom events sent by /_t.js with navigator.sendBeacon.
    if (url.pathname === '/_e' && request.method === 'POST') {
      try {
        const body = JSON.parse((await request.text()).slice(0, 2000));
        const event = String(body.e || '').slice(0, 120);
        if (event) record(env, ctx, { site: url.hostname, kind: 'click', path: String(body.p || '').slice(0, 200), event, detail: String(body.d || '').slice(0, 200), country });
      } catch { /* a malformed beacon is dropped */ }
      return new Response(null, { status: 204 });
    }

    const response = await env.ASSETS.fetch(request);
    const prefetch = (request.headers.get('sec-purpose') || request.headers.get('purpose') || '').includes('prefetch');
    if ((request.method === 'GET' || request.method === 'HEAD') && !prefetch && COUNTED.test(url.pathname)) {
      const agent = agentOf(request.headers.get('user-agent') || '');
      const kind = url.pathname === '/install.sh' ? 'install' : agent ? 'agent' : 'view';
      record(env, ctx, { site: url.hostname, kind, path: url.pathname.slice(0, 200), source: sourceOf(url, request), agent, country, status: response.status });
    }
    return response;
  },
};
