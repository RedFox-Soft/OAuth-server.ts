import { page } from './plainPage.js';
import { esc } from '../html/escape.js';
import type { AnswerDescription } from '../response_modes/describe.js';

/*
 * The page offered instead of redirecting an authorization error to a client whose redirect URIs no
 * operator vouched for — RFC 9700 §4.11.2's "inform the user and rely on the user to make the correct
 * decision". Without it, a client an attacker registered can send anyone to the attacker's site from
 * this server's address: by a deliberately malformed request, by a request the user then declines, or by
 * a silent one.
 *
 * What it shows is the destination's host, because the host is the one thing on the page the
 * registrant cannot choose freely: a client name, logo or description is the registrant's own text, and
 * showing it would hand the attacker the page's most prominent line. The error description is withheld
 * for the same reason — its text can carry what the request sent.
 *
 * The control carries exactly the answer the redirect would have: a link for an answer sent in the
 * query (not a GET form, which would replace a query the registered redirect URI may already have), or
 * a form posting the same fields for a form-post answer. No script: nothing leaves this page without the
 * user acting.
 */
export function confirmationPage({
	answer,
	error,
	redirectUri
}: {
	answer: AnswerDescription;
	error: string;
	redirectUri: string;
}): Response {
	const host = URL.parse(redirectUri)?.host ?? redirectUri;
	const declined = error === 'access_denied';
	const heading = declined
		? 'You declined the request'
		: 'The request could not be completed';
	const label = `Return to ${host}`;

	const control =
		answer.method === 'GET'
			? `<a href="${esc(answer.url)}" style="display:inline-block; padding:8px 16px; background:#1677ff; color:#fff; border-radius:6px; text-decoration:none;">${esc(label)}</a>`
			: `<form method="post" action="${esc(answer.action)}">${Object.entries(
					answer.fields
				)
					.map(
						([name, value]) =>
							`<input type="hidden" name="${esc(name)}" value="${esc(value)}"/>`
					)
					.join(
						''
					)}<button type="submit" style="padding:8px 16px; background:#1677ff; color:#fff; border:0; border-radius:6px; cursor:pointer;">${esc(label)}</button></form>`;

	const body = `<h2 style="margin-top:0;">${esc(heading)}</h2><p>The application at <strong>${esc(host)}</strong> is waiting for this answer. Continue only if you trust that site.</p><p style="color:#8c8c8c; font-size:12px;">Error: ${esc(error)}</p>${control}`;

	// The error's status, as a form-post error answer has it: the page reports a failed request, and a
	// 200 would tell a non-browser caller the opposite of what it says to a reader.
	return page(label, body, 400, { denyFraming: true });
}
