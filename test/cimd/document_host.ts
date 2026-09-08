import { mock, assertNoPendingInterceptors } from '../fetch_mock.js';

/*
 * A host that serves client description documents, for the Client ID Metadata Document specs.
 *
 * Built on `test/fetch_mock.ts` rather than a real socket, so a spec can describe the pathological
 * cases the governing draft's §6 asks an authorization server to survive — an oversized body, a
 * redirect chain, a document that disagrees with its own URL — without standing up a server per case.
 *
 * One property of the underlying mock is load-bearing here and worth stating: an interceptor is
 * consumed by the first matching request. So registering exactly one document and then authorizing
 * twice *proves* the cache was used, because a second retrieval would throw for want of an
 * interceptor. The cache specs rely on that rather than on counting calls.
 *
 * Address-class refusals (private, loopback, link-local) are deliberately NOT modelled here. Those
 * are refused before any request is made, so a fixture that could serve them would be describing a
 * code path that must not exist.
 */

export const DOC_ORIGIN = 'https://app.example.com';

/* A well-formed document, as the draft's own example has it. */
export function documentFor(
	identifier: string,
	overrides: Record<string, unknown> = {}
): Record<string, unknown> {
	return {
		client_id: identifier,
		client_name: 'Example MCP Client',
		client_uri: DOC_ORIGIN,
		redirect_uris: ['https://app.example.com/callback'],
		grant_types: ['authorization_code', 'refresh_token'],
		response_types: ['code'],
		token_endpoint_auth_method: 'none',
		...overrides
	};
}

interface ServeOptions {
	/* Path the document is served from. Must carry a path component — the draft requires one. */
	readonly path?: string;
	readonly status?: number;
	readonly headers?: Record<string, string>;
	/* Replaces the document body outright, for the malformed cases. */
	readonly rawBody?: string;
	readonly overrides?: Record<string, unknown>;
	readonly origin?: string;
}

export interface ServedDocument {
	/* The identifier a client presents as its `client_id`. */
	readonly identifier: string;
	readonly body: string;
}

/*
 * Registers one document and returns the identifier that names it. The document's own `client_id` is
 * set to that identifier by default, because the interesting failure is when it is not — so a spec
 * has to ask for the mismatch explicitly.
 */
export function serveDocument(opts: ServeOptions = {}): ServedDocument {
	const origin = opts.origin ?? DOC_ORIGIN;
	const path = opts.path ?? '/oauth/client-metadata.json';
	const identifier = `${origin}${path}`;

	const body =
		opts.rawBody ??
		JSON.stringify(documentFor(identifier, opts.overrides ?? {}));

	mock(origin)
		.intercept({ path })
		.reply(opts.status ?? 200, body, {
			headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) }
		});

	return { identifier, body };
}

/*
 * Registers a redirect from one path to another so a spec can check that every hop is re-validated
 * rather than only the first. The destination is given as a full URL because the point of the case is
 * usually that it leaves the original origin.
 */
export function serveRedirect(from: string, to: string, status = 302): string {
	const url = new URL(from);
	mock(url.origin)
		.intercept({ path: url.pathname + url.search })
		.reply(status, '', { headers: { location: to } });
	return from;
}

/* A body larger than the draft's recommended 5 KB ceiling, padded in a field that is ignored. */
export function oversizedDocument(identifier: string): string {
	return JSON.stringify(
		documentFor(identifier, { client_name: 'x'.repeat(6 * 1024) })
	);
}

export { assertNoPendingInterceptors, mock };
