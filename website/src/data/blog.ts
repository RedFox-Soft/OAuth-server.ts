import { getCollection, type CollectionEntry } from 'astro:content';
import { translatedLocales, type LocaleKey } from './seo.ts';
import { sourceHash } from '../i18n/source-hash.ts';

/*
 * The one path from the stored articles to the published ones.
 *
 * Every consumer goes through this function: the index, the article route and the feed, in every
 * language. That is the point of it existing rather than each of them calling `getCollection('blog')`
 * with its own filter. "A draft must not appear anywhere" is a property of the whole published
 * surface, and the way it breaks is never that a filter is wrong — it is that the filter is right in
 * two places out of three, which no reviewer reading the index notices.
 *
 * The same holds for translations: a post is published in every language or in none (FR-011a), and
 * a Russian file must not leak into the English feed as `/blog/ru/<slug>/`. Both are decided here.
 */

type Entry = CollectionEntry<'blog'>;

export interface PostData {
	title: string;
	description: string;
	publishedAt: string;
	updatedAt?: string;
	tags: string[];
	storageScope?: string;
}

export interface BlogPost {
	/* The filename, which is the slug in every language. */
	slug: string;
	locale: LocaleKey;
	/* The entry whose body is rendered: the translation, or the English post itself. */
	entry: Entry;
	/* Title and description in this language; dates, tags and scope from the English post. */
	data: PostData;
	/* A translation made from an older revision of the English post (FR-017). */
	stale: boolean;
}

/*
 * Compared as ISO strings rather than Date objects, which sorts and compares identically and avoids
 * the question of whose midnight an article is published at. The site is statically built, so a
 * future-dated article appears on the next build after its date, not at the moment it arrives.
 */
function today(): string {
	return new Date().toISOString().slice(0, 10);
}

const TRANSLATION = /^(ru|zh-cn)\/([^/]+)$/;

function englishFields(entry: Entry): PostData {
	if (!entry.data.publishedAt) {
		throw new Error(
			`src/content/blog/${entry.id}.mdx has no publishedAt; every English post needs one`
		);
	}
	if (entry.data.source) {
		throw new Error(
			`src/content/blog/${entry.id}.mdx sets source, which only a translation carries`
		);
	}
	return {
		title: entry.data.title,
		description: entry.data.description,
		publishedAt: entry.data.publishedAt,
		updatedAt: entry.data.updatedAt,
		tags: entry.data.tags ?? [],
		storageScope: entry.data.storageScope
	};
}

function checkTranslation(entry: Entry): void {
	const { publishedAt, updatedAt, draft, tags, storageScope, source } =
		entry.data;
	const inherited = { publishedAt, updatedAt, draft, tags, storageScope };
	const set = Object.entries(inherited).filter(
		([, value]) => value !== undefined
	);
	if (set.length > 0) {
		throw new Error(
			`src/content/blog/${entry.id}.mdx sets ${set.map(([key]) => key).join(', ')}; ` +
				'a translation inherits those from the English post'
		);
	}
	if (!source) {
		throw new Error(
			`src/content/blog/${entry.id}.mdx has no source; run bun run i18n:stamp on it after translating`
		);
	}
}

export function isPublished(
	data: { draft?: boolean; publishedAt?: string },
	now = today()
): boolean {
	return (
		data.draft !== true &&
		data.publishedAt !== undefined &&
		data.publishedAt <= now
	);
}

/*
 * Newest first, with the slug breaking a tie. The tie-break is not decoration: two articles
 * published on the same day otherwise reorder between builds, which rewrites the sitemap and the
 * feed for no content change.
 */
export function sortPosts(posts: BlogPost[]): BlogPost[] {
	return [...posts].sort((a, b) => {
		if (a.data.publishedAt !== b.data.publishedAt) {
			return a.data.publishedAt < b.data.publishedAt ? 1 : -1;
		}
		return a.slug.localeCompare(b.slug);
	});
}

const warned = new Set<string>();

function warnOnce(message: string): void {
	if (warned.has(message)) return;
	warned.add(message);
	console.warn(`blog: ${message}`);
}

export async function publishedPosts(
	locale: LocaleKey = 'en'
): Promise<BlogPost[]> {
	const entries = await getCollection('blog');
	const english = new Map<string, Entry>();
	const translations = new Map<string, Entry>();

	for (const entry of entries) {
		const match = TRANSLATION.exec(entry.id);
		if (match) {
			// A language still being translated, not yet in LOCALES, is not published and not judged.
			if (!translatedLocales().some(({ key }) => key === match[1])) continue;
			checkTranslation(entry);
			translations.set(entry.id, entry);
		} else if (entry.id.includes('/')) {
			throw new Error(
				`src/content/blog/${entry.id}.mdx is in a directory that is not a published language`
			);
		} else {
			english.set(entry.id, entry);
		}
	}

	for (const id of translations.keys()) {
		const [, slug = ''] = id.split('/');
		const source = english.get(slug);
		if (!source)
			throw new Error(
				`src/content/blog/${id}.mdx translates ${slug}.mdx, which does not exist`
			);
		if (source.data.draft === true) {
			throw new Error(
				`src/content/blog/${id}.mdx translates a draft; translate it once it is published`
			);
		}
	}

	const posts: BlogPost[] = [];
	for (const [slug, source] of english) {
		const data = englishFields(source);
		if (!isPublished(source.data)) continue;

		const missing = translatedLocales().filter(
			({ key }) => !translations.has(`${key}/${slug}`)
		);
		if (missing.length > 0) {
			warnOnce(
				`"${slug}" is held back in every language until ${missing
					.map(({ key }) => `src/content/blog/${key}/${slug}.mdx`)
					.join(' and ')} exist`
			);
			continue;
		}

		if (locale === 'en') {
			posts.push({ slug, locale, entry: source, data, stale: false });
			continue;
		}
		const translation = translations.get(`${locale}/${slug}`);
		// Unreachable: a post missing a translation in any published language was held back above.
		if (!translation) continue;
		posts.push({
			slug,
			locale,
			entry: translation,
			data: {
				...data,
				title: translation.data.title,
				description: translation.data.description
			},
			stale:
				translation.data.source !== sourceHash(`src/content/blog/${slug}.mdx`)
		});
	}
	return sortPosts(posts);
}

/** The date a reader is told the article last changed — its revision if it has one. */
export function effectiveDate(post: BlogPost): string {
	return post.data.updatedAt ?? post.data.publishedAt;
}
