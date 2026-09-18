import { getCollection, type CollectionEntry } from 'astro:content';

/*
 * The one path from the stored articles to the published ones.
 *
 * Every consumer goes through this function: the index, the article route and the feed. That is the
 * point of it existing rather than each of them calling `getCollection('blog')` with its own filter.
 * "A draft must not appear anywhere" is a property of the whole published surface, and the way it
 * breaks is never that a filter is wrong — it is that the filter is right in two places out of
 * three, which no reviewer reading the index notices.
 */

export type BlogPost = CollectionEntry<'blog'>;

/*
 * Compared as ISO strings rather than Date objects, which sorts and compares identically and avoids
 * the question of whose midnight an article is published at. The site is statically built, so a
 * future-dated article appears on the next build after its date, not at the moment it arrives.
 */
function today(): string {
	return new Date().toISOString().slice(0, 10);
}

export function isPublished(post: BlogPost, now = today()): boolean {
	return post.data.draft !== true && post.data.publishedAt <= now;
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
		return a.id.localeCompare(b.id);
	});
}

export async function publishedPosts(): Promise<BlogPost[]> {
	return sortPosts(
		(await getCollection('blog')).filter((post) => isPublished(post))
	);
}

/** The date a reader is told the article last changed — its revision if it has one. */
export function effectiveDate(post: BlogPost): string {
	return post.data.updatedAt ?? post.data.publishedAt;
}
