/*
 * The shapes that pass between the post-build steps. One record per built page, collected once and
 * handed to every generator and every rule, so the sitemap, the machine-readable index and the
 * guardrail cannot disagree about what a page says.
 */

import type { SectionName } from '../../src/data/seo.ts';

export interface Heading {
	level: number;
	text: string;
}

export interface ImageRecord {
	/** Site-relative src as written in the markup. */
	src: string;
	alt: string;
	caption?: string;
	width?: number;
	height?: number;
	loading?: string;
}

export type StructuredType =
	| 'Organization'
	| 'SoftwareApplication'
	| 'TechArticle'
	| 'FAQPage'
	| 'BreadcrumbList';

export interface StructuredEntity {
	type: string;
	props: Record<string, unknown>;
	/*
	 * The human-readable strings the block claims. Each must occur in the owning page's visible
	 * text — narrower than "the structured data must not exceed the page", but decidable, and it
	 * catches the case that actually happens: the copy is rewritten and the JSON-LD is not.
	 */
	assertedStrings: string[];
}

export interface PageRecord {
	route: string;
	file: string;
	sourceFile?: string;
	dataSources: string[];
	title: string;
	description: string;
	canonical: string;
	lang: string;
	indexable: boolean;
	ogImage: string;
	ogTitle: string;
	ogDescription: string;
	ogUrl: string;
	twitterCard: string;
	lastmod?: string;
	headings: Heading[];
	images: ImageRecord[];
	outboundLinks: string[];
	structured: StructuredEntity[];
	text: string;
}

export interface LlmsEntry {
	url: string;
	label: string;
	summary: string;
	section: SectionName;
}

export interface VerificationResult {
	rule: string;
	route: string;
	detail: string;
}
