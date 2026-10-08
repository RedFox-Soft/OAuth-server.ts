import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { LOCALE_DEFINITIONS, type LocaleKey } from '../data/seo.ts';
import { publishedPosts } from '../data/blog.ts';
import { localizedRoute } from './locale.ts';
import { messagesFor } from './messages.ts';
import english from './messages/blog/en.ts';

/*
 * The feed, built from publishedPosts() and never from getCollection('blog') directly.
 *
 * That is the one rule worth guarding here. The index and the feed have to agree about what is
 * published, and the way they stop agreeing is not that somebody writes the wrong filter — it is
 * that somebody adds a rule to the index and does not know the feed exists. There is nothing in
 * the post-build sweep to catch it either: the guardrail collects only .html, so the feed is
 * outside all of its rules. Every language's feed comes from this one function for the same reason.
 *
 * No full-text `content`: a feed carrying whole articles competes with the canonical page for both
 * the reader and the attribution, and the description plus the link is what a reader needs in order
 * to decide.
 */
export async function blogFeed(
	context: APIContext,
	locale: LocaleKey
): Promise<Response> {
	const t = messagesFor('blog', english, locale);
	const posts = await publishedPosts(locale);

	return rss({
		title: t.feed.title,
		description: t.feed.description,
		// From the build context rather than a literal, so the feed cannot outlive a change of origin.
		site: context.site ?? 'https://foxauth.dev',
		items: posts.map((post) => ({
			title: post.data.title,
			description: post.data.description,
			pubDate: new Date(`${post.data.publishedAt}T00:00:00Z`),
			// The trailing slash matters: without it every link disagrees with the canonical URL the
			// page itself declares, and a reader following the feed is redirected on every article.
			link: localizedRoute(`/blog/${post.slug}/`, locale),
			author: 'FoxAuth',
			categories: post.data.tags.length > 0 ? post.data.tags : undefined
		})),
		customData: `<language>${LOCALE_DEFINITIONS[locale].key}</language>`
	});
}
