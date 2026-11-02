import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

import { isPublicAddress } from '../helpers/public_address.js';

/*
 * Outbound requests to an address somebody other than the operator chose — a client's sector document,
 * key set or back-channel endpoint, or a client ID metadata document. Each is a request this server
 * makes on a stranger's behalf, so each goes through one boundary that can be reviewed for one
 * question only: can a caller make this server talk to something it should not.
 *
 * Four things are enforced, and a caller cannot opt out of any of them:
 *
 *  1. The resolved address, against the private, loopback and link-local ranges — including
 *     `169.254.0.0/16`, where cloud instance credentials live. Every answer, not merely one.
 *  2. Every redirect hop, followed by hand and re-checked. The platform following one for us would
 *     follow it to an address nothing checked.
 *  3. Time, so a host that accepts the connection and then stalls cannot pin a request open.
 *  4. Size, through `readBounded`, checked against the declared length and the bytes actually read.
 *
 * Extracted from the client ID metadata document fetcher when the other client-supplied addresses were
 * found going through plain `fetch`: followed redirects, no address check, no bound on time or size.
 */

/*
 * Name resolution, behind a seam so a spec can say what an answer *is* rather than depend on how the
 * network resolves a name today.
 *
 * It also serves the harder property. The check and the request must agree about the address, and
 * they cannot be made atomic here — the platform's fetch resolves the name again itself. So this is
 * pinned as far as it can be: the answer is taken once, checked, and the same host is what is
 * requested. A name that changes between the two remains the residual risk the MCP guidance calls
 * TOCTOU, and closing it properly needs an egress proxy, which is a deployment control rather than
 * something this module can assert.
 */
export const resolver = {
	realLookup: async (host: string): Promise<string[]> => {
		const answers = await dnsLookup(host, { all: true });
		return answers.map((answer) => answer.address);
	},
	lookup: async (host: string): Promise<string[]> => resolver.realLookup(host)
};

export type EgressFailure =
	| 'unresolvable'
	| 'blocked_address'
	| 'bad_redirect'
	| 'too_many_redirects'
	| 'too_large'
	| 'timeout'
	| 'unreachable';

/*
 * Why an outbound request was not made or not completed. The reason is for the event bus and for a
 * caller choosing its own refusal; it is never meant to reach the party that supplied the address, who
 * would otherwise learn which of their guesses landed on something.
 */
export class EgressRefused extends Error {
	constructor(readonly reason: EgressFailure) {
		super(`outbound request refused: ${reason}`);
		this.name = 'EgressRefused';
	}
}

/*
 * Whether an address is one this server must refuse to talk to: anything that is not a public address.
 * Applied to a literal from a URL and to every answer a resolver gives, so it cannot assume either
 * arrives in one spelling; the classifier lives in lib/helpers/public_address.ts because the caller
 * address of every request is judged by the same rules.
 */
export function isBlockedAddress(address: string): boolean {
	return !isPublicAddress(address);
}

/* Exported for a write that must refuse an address before anything is ever sent to it (specs/117 FR-007). */
export async function assertReachable(
	host: string
): Promise<EgressFailure | null> {
	/*
	 * A literal address needs no resolution, and passing one to the resolver would be a lookup of a
	 * name that is not one. It is still checked — `https://10.0.0.1/…` named directly is the simplest
	 * form of this attack. A bracketed IPv6 literal arrives from URL parsing with its brackets.
	 */
	const literal = host.startsWith('[') ? host.slice(1, -1) : host;
	if (isIP(literal) !== 0) {
		return isBlockedAddress(literal) ? 'blocked_address' : null;
	}

	let addresses: string[];
	try {
		addresses = await resolver.lookup(host);
	} catch {
		return 'unresolvable';
	}
	if (addresses.length === 0) return 'unresolvable';

	/*
	 * *Every* answer must be acceptable, not merely one of them. A name resolving to both a public and
	 * a private address would otherwise pass the check and then be connected to at whichever the
	 * platform picked.
	 */
	if (addresses.some(isBlockedAddress)) return 'blocked_address';
	return null;
}

export interface EgressOptions {
	/* A redirect is followed for GET only; DELETE is a provider's revocation (specs/117), answered where it is. */
	readonly method?: 'GET' | 'POST' | 'DELETE';
	readonly headers?: Record<string, string>;
	readonly body?: string | URLSearchParams;
	readonly timeoutMs: number;
	/* Nothing legitimate needs a long chain; a loop is refused in milliseconds. */
	readonly maxRedirects?: number;
	/*
	 * Whether a redirect may leave https. A document whose identity is its https URL may not be served
	 * from anywhere else; an address a client registered keeps the scheme it was registered with.
	 */
	readonly httpsRedirectsOnly?: boolean;
}

/*
 * Makes the request, or throws `EgressRefused`. The response is handed back unread, so a caller that
 * needs the body reads it through `readBounded`.
 *
 * A redirect is followed for GET only. A POST answered with one is returned as it is, which every
 * caller here treats as the failure it is: a notification endpoint that redirects is not one that
 * received the notification. So is a GET whose caller allows no redirect at all (`maxRedirects: 0`):
 * returned unread, its Location never parsed or requested, for a caller whose target must be answered
 * where it is or not at all.
 */
export async function guardedFetch(
	url: string | URL,
	options: EgressOptions
): Promise<Response> {
	const method = options.method ?? 'GET';
	const maxRedirects = options.maxRedirects ?? 4;
	let target = new URL(url);

	for (let hop = 0; hop <= maxRedirects; hop += 1) {
		const blocked = await assertReachable(target.hostname);
		if (blocked) throw new EgressRefused(blocked);

		let response: Response;
		try {
			response = await fetch(target.href, {
				method,
				headers: options.headers,
				body: options.body,
				redirect: 'manual',
				signal: AbortSignal.timeout(options.timeoutMs)
			});
		} catch (err) {
			throw new EgressRefused(
				err instanceof Error && err.name === 'TimeoutError'
					? 'timeout'
					: 'unreachable'
			);
		}

		if (
			method !== 'GET' ||
			maxRedirects === 0 ||
			response.status < 300 ||
			response.status >= 400
		) {
			return response;
		}

		const location = response.headers.get('location');
		const next = location ? URL.parse(location, target.href) : null;
		if (
			!next ||
			(next.protocol !== 'https:' && next.protocol !== 'http:') ||
			(options.httpsRedirectsOnly && next.protocol !== 'https:') ||
			(target.protocol === 'https:' && next.protocol !== 'https:')
		) {
			throw new EgressRefused('bad_redirect');
		}
		target = next;
	}

	throw new EgressRefused('too_many_redirects');
}

/*
 * The body, or `EgressRefused('too_large')`. A `content-length` is a claim by the host being guarded
 * against, so it is checked and then the stream is read no further than the bound — a lying or absent
 * one must not become an unbounded read held in memory.
 */
export async function readBounded(
	response: Response,
	maxBytes: number
): Promise<string> {
	const declared = Number(response.headers.get('content-length'));
	if (Number.isFinite(declared) && declared > maxBytes) {
		throw new EgressRefused('too_large');
	}
	if (!response.body) return '';

	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				await reader.cancel().catch(() => {});
				throw new EgressRefused('too_large');
			}
			chunks.push(value);
		}
	} catch (err) {
		if (err instanceof EgressRefused) throw err;
		throw new EgressRefused('unreachable');
	}
	return new TextDecoder().decode(Buffer.concat(chunks));
}
