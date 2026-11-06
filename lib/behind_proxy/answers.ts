import type { Reason } from './decide.js';

/*
 * How every answer of the check is built (specs/122 contracts/check-endpoint.md): each carries `X-Auth-Reason`, so
 * the proxy's own access log says why, and `Cache-Control: no-store`, so no cache between the proxy and the
 * project ever answers for a person a second time.
 */

export type AnswerReason =
	| Reason
	| 'server_error'
	/* A sign-in came back unusable; no session was made. */
	| 'sign_in_failed'
	/* A `/_foxauth/` path the endpoint does not serve, or one asked for where only a status may be answered. */
	| 'reserved_path'
	| 'signing_in'
	| 'signed_in'
	| 'signed_out'
	/* The proxy self-test page (specs/124), and a fresh sign-in that came back older than asked. */
	| 'address_test'
	| 'sign_in_not_fresh'
	/* The API check (specs/123 contracts/api-check.md). */
	| ApiReason;

export type ApiReason =
	| 'allowed'
	| 'preflight'
	| 'missing_token'
	| 'invalid_token'
	| 'bound_token_unsupported'
	| 'insufficient_scope'
	| 'tool_unnamed'
	| 'tool_not_listed'
	| 'old_client'
	| 'bad_mcp_header'
	| 'not_found'
	| 'missing_forwarded'
	| 'unsafe_value'
	| 'rate_limited'
	| 'server_error'
	/* Access conditions on the API (specs/124 contracts/check.md). */
	| 'no_person'
	| 'cannot_sign_in'
	| 'not_in_group'
	| 'attribute_mismatch'
	| 'not_from_network'
	| 'outside_hours';

export function answer(
	status: number,
	reason: AnswerReason,
	headers: Record<string, string> = {},
	body: string | null = null
): Response {
	return new Response(body, {
		status,
		headers: {
			...headers,
			'X-Auth-Reason': reason,
			'Cache-Control': 'no-store',
			...(body === null ? {} : { 'Content-Type': 'text/plain; charset=utf-8' })
		}
	});
}

/* A rendered page given the headers every answer carries. */
export function withReason(
	page: Response,
	reason: AnswerReason,
	headers: Record<string, string> = {}
): Response {
	for (const [name, value] of Object.entries(headers)) {
		page.headers.set(name, value);
	}
	page.headers.set('X-Auth-Reason', reason);
	page.headers.set('Cache-Control', 'no-store');
	return page;
}

export function redirect(
	location: string,
	reason: AnswerReason,
	cookies: readonly string[] = []
): Response {
	const headers = new Headers({
		Location: location,
		'X-Auth-Reason': reason,
		'Cache-Control': 'no-store'
	});
	for (const cookie of cookies) headers.append('Set-Cookie', cookie);
	return new Response(null, { status: 302, headers });
}
