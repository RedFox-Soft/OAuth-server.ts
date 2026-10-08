import type { APIContext } from 'astro';
import { blogFeed } from '../../../i18n/feed.ts';

export function GET(context: APIContext): Promise<Response> {
	return blogFeed(context, 'ru');
}
