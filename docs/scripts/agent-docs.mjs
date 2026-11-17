// Docs for coding agents, after `astro build`: every page as Markdown beside its HTML (`/integrations/claude-code.md`
// and `/integrations/claude-code/index.md`), `/llms.txt` (the llms.txt index) and `/llms-full.txt` (every page in
// one file). Made from the .mdx sources with Node's standard library: the Starlight components become plain Markdown.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pages = join(root, 'src/content/docs');
const dist = join(root, 'dist');
const site = (process.env.DOCS_SITE ?? 'https://docs.enterplace.dev').replace(/\/$/, '');

function walk(dir) {
	return readdirSync(dir).flatMap((name) => {
		const path = join(dir, name);
		return statSync(path).isDirectory() ? walk(path) : /\.mdx?$/.test(name) ? [path] : [];
	});
}

const attr = (tag, name) => (tag.match(new RegExp(`${name}="([^"]*)"`)) ?? [])[1] ?? '';

/** The page's Markdown: its title and description, then the body with the components written out. */
export function toMarkdown(source, file) {
	const front = source.match(/^---\n([\s\S]*?)\n---\n/);
	const field = (name) => ((front?.[1] ?? '').match(new RegExp(`^${name}:\\s*(.*)$`, 'm')) ?? [])[1]?.trim() ?? '';
	const title = field('title').replace(/^['"]|['"]$/g, '');
	const description = field('description').replace(/^['"]|['"]$/g, '');
	let body = front ? source.slice(front[0].length) : source;
	if (/<Changelog\s*\/>/.test(body)) {
		body = body.replace(/<Changelog\s*\/>/, readFileSync(join(root, '..', 'CHANGELOG.md'), 'utf8'));
	}
	body = body
		.replace(/^import .*$/gm, '')
		.replace(/<LinkCard\b[^>]*\/>/g, (tag) => `- [${attr(tag, 'title')}](${link(attr(tag, 'href'))}): ${attr(tag, 'description')}`)
		.replace(/<Card\b[^>]*>/g, (tag) => `**${attr(tag, 'title')}**\n`)
		.replace(/<\/Card>/g, '')
		.replace(/<\/?CardGrid[^>]*>/g, '')
		.replace(/<\/?Steps>/g, '')
		.replace(/<\/?Tabs[^>]*>/g, '')
		.replace(/<TabItem\b[^>]*>/g, (tag) => `**${attr(tag, 'label')}**\n`)
		.replace(/<\/TabItem>/g, '')
		.replace(/<Aside\b[^>]*>([\s\S]*?)<\/Aside>/g, (whole, inner) => {
			const kind = attr(whole, 'type') || 'note';
			const label = attr(whole, 'title') || kind[0].toUpperCase() + kind.slice(1);
			return inner.trim().split('\n').map((line, i) => `> ${i === 0 ? `**${label}:** ` : ''}${line}`).join('\n');
		})
		// Links between pages point at the Markdown twins, so an agent can follow them.
		.replace(/\]\((\/[^)\s#]*)(#[^)\s]*)?\)/g, (whole, path, hash) => `](${link(path)}${hash ?? ''})`)
		.replace(/\n{3,}/g, '\n\n')
		.trim();
	return { title, description, text: `# ${title}\n\n${description ? `> ${description}\n\n` : ''}${body}\n` };
}

/** A page path as its Markdown twin's full address. */
function link(path) {
	if (!path.startsWith('/') || /\.\w+$/.test(path)) return path.startsWith('/') ? `${site}${path}` : path;
	const bare = path.replace(/\/$/, '');
	return `${site}${bare === '' ? '/index' : bare}.md`;
}

const all = [];
for (const file of walk(pages).sort()) {
	const route = relative(pages, file).replace(/\.mdx?$/, '').replace(/(^|\/)index$/, '');
	const page = toMarkdown(readFileSync(file, 'utf8'), file);
	const out = route === '' ? [join(dist, 'index.md')] : [join(dist, `${route}.md`), join(dist, route, 'index.md')];
	for (const target of out) {
		mkdirSync(dirname(target), { recursive: true });
		writeFileSync(target, page.text);
	}
	all.push({ route, ...page });
}

const section = (route) => (route.split('/')[0] || 'start');
const index = [
	'# Enterplace',
	'',
	'> The open source AI gateway built for governance: identity, policy and a tamper-evident audit log on every model request. Every page below is Markdown.',
	'',
];
let last = '';
for (const page of all) {
	const name = section(page.route);
	if (name !== last) {
		index.push('', `## ${name[0].toUpperCase()}${name.slice(1).replace(/-/g, ' ')}`, '');
		last = name;
	}
	index.push(`- [${page.title}](${link(`/${page.route}`)})${page.description ? `: ${page.description}` : ''}`);
}
writeFileSync(join(dist, 'llms.txt'), `${index.join('\n')}\n`);
writeFileSync(join(dist, 'llms-full.txt'), all.map((p) => p.text).join('\n\n---\n\n'));
console.log(`agent docs: ${all.length} pages as Markdown, llms.txt and llms-full.txt`);
