import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { publishedPosts } from '../../data/blog.ts';

/*
 * The feed, built from publishedPosts() and never from getCollection('blog') directly.
 *
 * That is the one rule worth guarding here. The index and this file have to agree about what is
 * published, and the way they stop agreeing is not that somebody writes the wrong filter — it is
 * that somebody adds a rule to the index and does not know this file exists. There is nothing in
 * the post-build sweep to catch it either: the guardrail collects only .html, so this file is
 * outside all of its rules.
 *
 * No full-text `content`: a feed carrying whole articles competes with the canonical page for both
 * the reader and the attribution, and the description plus the link is what a reader needs in order
 * to decide.
 */
export async function GET(context: APIContext): Promise<Response> {
	const posts = await publishedPosts();

	return rss({
		title: 'FoxAuth blog',
		description:
			'Notes on OAuth 2.1, OpenID Connect and running your own authorization server, written by the team building FoxAuth as we hit things worth writing down.',
		// From the build context rather than a literal, so the feed cannot outlive a change of origin.
		site: context.site ?? 'https://foxauth.dev',
		items: posts.map((post) => ({
			title: post.data.title,
			description: post.data.description,
			pubDate: new Date(`${post.data.publishedAt}T00:00:00Z`),
			// The trailing slash matters: without it every link disagrees with the canonical URL the
			// page itself declares, and a reader following the feed is redirected on every article.
			link: `/blog/${post.id}/`,
			author: 'FoxAuth',
			categories: post.data.tags.length > 0 ? post.data.tags : undefined
		})),
		customData: '<language>en</language>'
	});
}
