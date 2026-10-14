/*
 * The language of a page that is not inside a sign-in: the person's choice, then whatever this page knows (the
 * caller's signals, in order), then the browser. Inside a sign-in the interaction decided once and every page
 * reads that instead (lib/actions/authorization/interactions.ts).
 */

import { languageFromCookieHeader } from './cookie.js';
import {
	acceptLanguageRanges,
	resolveLanguage,
	singleRange,
	type ResolvedLanguage
} from './resolve.js';

export function languageOfRequest(
	request: Pick<Request, 'headers'> | undefined,
	signals: readonly (readonly string[])[] = []
): ResolvedLanguage {
	const headers = request?.headers;
	return resolveLanguage([
		singleRange(languageFromCookieHeader(headers?.get('cookie'))),
		...signals,
		acceptLanguageRanges(headers?.get('accept-language'))
	]);
}

/*
 * The two request headers a sign-in's language is read from, for the pipeline context, which carries a header
 * map rather than the Request (lib/helpers/oidc_context.ts).
 */
export function languageHeaders(
	request: Pick<Request, 'headers'>
): Record<string, string | undefined> {
	return {
		cookie: request.headers.get('cookie') ?? undefined,
		'accept-language': request.headers.get('accept-language') ?? undefined
	};
}

/* The same resolution for a pipeline context, which reads its headers by name. */
export function languageOfContext(
	oidc: { get(name: string): string | undefined },
	signals: readonly (readonly string[])[] = []
): ResolvedLanguage {
	return resolveLanguage([
		singleRange(languageFromCookieHeader(oidc.get('cookie'))),
		...signals,
		acceptLanguageRanges(oidc.get('accept-language'))
	]);
}
