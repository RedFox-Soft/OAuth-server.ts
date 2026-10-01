import formatUri from '../helpers/redirect_uri.ts';
import { formPost } from '../html/formPost.js';

/*
 * An authorization response before it is sent: where it goes, and how.
 *
 * Kept apart from sending because one answer has two ways out. A response the server sends itself is
 * a redirect or an auto-submitting form; an answer the end user is asked to confirm first (an error for
 * a client whose redirect URIs no operator vouched for, RFC 9700 §4.11.2) is a link or a button. Both
 * are built from this one description, so the confirmed answer cannot drift from the one the redirect
 * would have carried.
 */
export type AnswerDescription =
	| { method: 'GET'; url: string }
	| { method: 'POST'; action: string; fields: Record<string, string> };

export function describeQuery(
	redirectUri: string,
	payload: Record<string, string>
): AnswerDescription {
	return { method: 'GET', url: formatUri(redirectUri, payload) };
}

export function describeFormPost(
	redirectUri: string,
	payload: Record<string, string>
): AnswerDescription {
	return { method: 'POST', action: redirectUri, fields: payload };
}

export function send(oidc: unknown, answer: AnswerDescription): Response {
	if (answer.method === 'GET') {
		return Response.redirect(answer.url, 303);
	}
	return formPost(oidc, answer.action, answer.fields);
}
