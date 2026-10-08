import { rich } from '../../types.ts';

/* The text around every page: header, footer, switcher, notices and breadcrumb names. */
export default {
	skipToContent: 'Skip to content',
	nav: {
		features: 'Features',
		pricing: 'Pricing',
		compare: 'Compare',
		blog: 'Blog',
		docs: 'Docs',
		changelog: 'Changelog',
		github: 'GitHub'
	},
	getStarted: 'Get started',
	ariaMain: 'Main',
	ariaMenu: 'Menu',
	ariaMainMenu: 'Main menu',
	ariaLanguage: 'Language',
	footer: {
		product: 'Product',
		docs: 'Docs',
		project: 'Project',
		contact: 'Contact',
		features: 'Features',
		pricing: 'Pricing',
		compare: 'Compare',
		blog: 'Blog',
		getStarted: 'Get started',
		deploy: 'Deploy',
		reference: 'Reference',
		github: 'GitHub',
		changelog: 'Changelog',
		security: 'Security',
		license: 'License',
		feed: 'Blog feed (RSS)',
		llms: 'For LLMs (llms.txt)',
		contactUs: 'Contact us',
		about:
			'FoxAuth is built on OAuth-server.ts, a source-available OAuth 2.1 / OpenID Connect server.',
		siteVersion: (version: string, unreleased: boolean): string =>
			`Site version ${version}${unreleased ? ' (unreleased)' : ''}`
	},
	/* The sentence around the comparison links (CompareLinks.astro); the names are joined between. */
	compareLinks: {
		before:
			'Already running something else? We keep dated, sourced comparisons with',
		after: ', each listing the pages we read and the date we read them.'
	},
	/* Shown, in the reader's language, on a page that exists only in English. */
	englishOnly: 'This page is available only in English',
	/* Shown on a translation made from an older revision of its English page. */
	staleTranslation: (href: string) =>
		rich(
			{ strong: 'The English version is newer.' },
			' This translation was made from an earlier revision of the page, and may be missing what changed since. ',
			{ link: 'Read the English version', href },
			'.'
		),
	breadcrumbs: {
		home: 'Home',
		docs: 'Documentation',
		'get-started': 'Get started',
		deploy: 'Deploy',
		reference: 'Reference',
		compare: 'Compare',
		blog: 'Blog'
	},
	/* The section names a social card shows under its title (scripts/seo/cards.ts). */
	sections: {
		'Start here': 'Start here',
		Product: 'Product',
		Compare: 'Compare',
		Blog: 'Blog',
		Documentation: 'Documentation',
		Reference: 'Reference',
		Project: 'Project'
	}
};
