// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Served at the root of its own domain on Cloudflare.
const site = process.env.DOCS_SITE ?? 'https://gantry-docs.enterplace.dev';
const base = process.env.DOCS_BASE ?? '/';

const group = (label, directory) => ({ label, items: [{ autogenerate: { directory } }] });

export default defineConfig({
	site,
	base,
	integrations: [
		starlight({
			title: 'Gantry',
			description: 'The open source AI gateway built for governance: identity, policy and a tamper-evident audit log on every model request.',
			logo: { light: './src/assets/logo-light.svg', dark: './src/assets/logo-dark.svg' },
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/eliransu/gantry' }],
			editLink: { baseUrl: 'https://github.com/eliransu/gantry/edit/main/docs/' },
			customCss: ['./src/styles/gantry.css'],
			// Copy page and Open in Claude or ChatGPT under each title; the Markdown twins come from scripts/agent-docs.mjs.
			head: [{ tag: 'script', attrs: { src: '/agent-tools.js', defer: true } }],
			lastUpdated: true,
			sidebar: [
				{
					label: 'Start here',
					items: [
						// The install command first: a newcomer runs it, connects a tool, then reads why and how.
						// The getting-started pages keep their addresses, so no link to them breaks.
						'getting-started/quickstart',
						{ label: 'Connect Claude Code', link: '/integrations/claude-code/' },
						{ label: 'Connect another tool', link: '/integrations/coding-tools/' },
						'start/why',
						'start/step-1-see',
						'start/step-2-know',
						'start/step-3-limit',
						'start/step-4-protect',
						'start/step-5-prove',
						'start/plan',
						'getting-started/how-it-works',
						'getting-started/status',
						'getting-started/changelog',
					],
				},
				group('Deploy', 'deploy'),
				group('Integrations', 'integrations'),
				group('Governance', 'governance'),
				group('Providers', 'providers'),
				group('Routing', 'routing'),
				group('Operations', 'operations'),
				group('Reference', 'reference'),
				group('Migrate', 'migrate'),
			],
		}),
	],
});
