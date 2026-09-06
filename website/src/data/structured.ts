import { SITE_ORIGIN } from './seo.ts';

/*
 * Typed builders for the structured data the site publishes.
 *
 * The type set is closed and scripts/seo/verify.ts rejects anything outside it, so this file is the
 * only place a new block can come from. Two rules shape what is here:
 *
 *  - Nothing may claim what the page does not visibly say. The verifier enforces a decidable slice
 *    of that — every human-readable string in a block must occur in the page's rendered text — so a
 *    builder must be fed the wording the page actually uses, not a tidier paraphrase.
 *  - Nothing goes in that outlives the copy it describes. A structured price on a page whose terms
 *    later change is worse than no price at all, so `offers` states the licence model rather than a
 *    figure, and Product/Offer, Review and HowTo are deliberately absent.
 */

const REPOSITORY = 'https://github.com/RedFox-Soft/OAuth-server.ts';

export interface JsonLd {
	'@context': 'https://schema.org';
	'@type': string;
	[key: string]: unknown;
}

export function organization(): JsonLd {
	return {
		'@context': 'https://schema.org',
		'@type': 'Organization',
		name: 'FoxAuth',
		url: SITE_ORIGIN,
		logo: new URL('/logo.svg', SITE_ORIGIN).href,
		sameAs: [REPOSITORY]
	};
}

export interface SoftwareApplicationInput {
	/** Must match how the page words the licence, because the verifier checks it appears there. */
	license: string;
	version?: string;
}

export function softwareApplication({
	license,
	version
}: SoftwareApplicationInput): JsonLd {
	return {
		'@context': 'https://schema.org',
		'@type': 'SoftwareApplication',
		name: 'FoxAuth',
		alternateName: 'OAuth-server.ts',
		applicationCategory: 'SecurityApplication',
		operatingSystem: 'Docker, Linux, macOS, Windows',
		url: SITE_ORIGIN,
		downloadUrl: REPOSITORY,
		license,
		...(version ? { softwareVersion: version } : {}),
		offers: {
			'@type': 'Offer',
			price: '0',
			priceCurrency: 'USD',
			description: 'Self-hosted under a source-available licence'
		}
	};
}

export interface TechArticleInput {
	/** The page's own h1, verbatim. */
	headline: string;
	description: string;
	canonical: string;
	dateModified?: string;
}

export function techArticle({
	headline,
	description,
	canonical,
	dateModified
}: TechArticleInput): JsonLd {
	return {
		'@context': 'https://schema.org',
		'@type': 'TechArticle',
		headline,
		description,
		url: canonical,
		author: { '@type': 'Organization', name: 'FoxAuth' },
		publisher: { '@type': 'Organization', name: 'FoxAuth' },
		...(dateModified ? { dateModified } : {})
	};
}

export interface FaqItem {
	question: string;
	answer: string;
}

/** Every question and answer must also be visible on the page — the verifier checks exactly that. */
export function faqPage(items: readonly FaqItem[]): JsonLd {
	return {
		'@context': 'https://schema.org',
		'@type': 'FAQPage',
		mainEntity: items.map((item) => ({
			'@type': 'Question',
			name: item.question,
			acceptedAnswer: { '@type': 'Answer', text: item.answer }
		}))
	};
}

export interface Crumb {
	name: string;
	url: string;
}

export function breadcrumbList(crumbs: readonly Crumb[]): JsonLd {
	return {
		'@context': 'https://schema.org',
		'@type': 'BreadcrumbList',
		itemListElement: crumbs.map((crumb, index) => ({
			'@type': 'ListItem',
			position: index + 1,
			name: crumb.name,
			item: new URL(crumb.url, SITE_ORIGIN).href
		}))
	};
}

/*
 * Breadcrumbs derived from the route. Names come from the section map's vocabulary so they match
 * what the navigation calls each area; the leaf uses the page's own heading, which is the string
 * the page visibly shows.
 */
const SEGMENT_NAMES: Record<string, string> = {
	docs: 'Documentation',
	'get-started': 'Get started',
	deploy: 'Deploy',
	reference: 'Reference',
	compare: 'Compare'
};

export function crumbsFor(route: string, leafName: string): Crumb[] {
	const segments = route.split('/').filter(Boolean);
	if (segments.length === 0) return [];

	const crumbs: Crumb[] = [{ name: 'Home', url: '/' }];
	let path = '';
	segments.forEach((segment, index) => {
		path += `/${segment}`;
		const isLeaf = index === segments.length - 1;
		crumbs.push({
			name: isLeaf ? leafName : (SEGMENT_NAMES[segment] ?? segment),
			url: `${path}/`
		});
	});
	return crumbs;
}
