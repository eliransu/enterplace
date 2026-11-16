// The Worker in front of the website and the docs. It records page views, agent fetches, install.sh downloads and
// clicks in the gantry-web D1 database, then serves the static files. No cookie is set and no IP address is stored.
// Query it with scripts/web_stats.sh. The schema is in site/web-schema.sql.

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
    'INSERT INTO hits (t, site, kind, path, event, source, agent, country, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).bind(new Date().toISOString(), row.site, row.kind, row.path, row.event || '', row.source || '', row.agent || '',
    row.country || '', row.status || 0).run().catch(() => {}));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const country = request.cf?.country || '';

    // Clicks and copies sent by site.js with navigator.sendBeacon.
    if (url.pathname === '/_e' && request.method === 'POST') {
      try {
        const body = JSON.parse((await request.text()).slice(0, 2000));
        const event = String(body.e || '').slice(0, 120);
        if (event) record(env, ctx, { site: url.hostname, kind: 'click', path: String(body.p || '').slice(0, 200), event, country });
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
