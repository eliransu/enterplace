// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Served at the root of its own domain on Cloudflare.
const site = process.env.DOCS_SITE ?? 'https://gantry-docs.eliran.me';
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
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/ggantry/gantry' }],
			editLink: { baseUrl: 'https://github.com/ggantry/gantry/edit/main/docs/' },
			customCss: ['./src/styles/gantry.css'],
			lastUpdated: true,
			sidebar: [
				{ label: 'Getting started', items: [{ label: 'Overview', link: '/' }, { autogenerate: { directory: 'getting-started' } }] },
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
