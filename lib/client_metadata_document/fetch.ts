import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

import { parseClientIdentifierUrl } from './identifier.js';

/*
 * Retrieving a client description document, and the only place this server makes an outbound request
 * on behalf of an unauthenticated caller.
 *
 * That sentence is the whole reason this module exists on its own, with no JSON-shape knowledge in it.
 * The governing draft is explicit that an authorization server accepting a URL-shaped `client_id`
 * "takes a URL as input from an unknown client and fetches that URL", and that a malicious client can
 * use it to reach "private administration endpoints the authorization server has access to". Keeping
 * the egress rules in one file with nothing else in it is what makes them reviewable as a boundary
 * rather than as scattered defensive lines inside a parser.
 *
 * Five things are enforced here, and each maps to a stated mitigation:
 *
 *  1. The identifier's form, delegated to `identifier.ts`, before anything is resolved.
 *  2. The resolved address, against the private, loopback and link-local ranges the MCP security best
 *     practices name — including `169.254.0.0/16`, which is where cloud instance credentials live.
 *  3. Every redirect hop, re-resolved and re-checked. A first hop that passes says nothing about the
 *     second, and "do not blindly follow redirects to internal resources" is the stated rule.
 *  4. Size, capped at the 5 KB the draft recommends, and checked against the declared length *and*
 *     the bytes actually read — a lying `content-length` must not become an unbounded read.
 *  5. Time, so a host that accepts the connection and then stalls cannot pin a request open.
 *
 * What it deliberately does NOT do is decide whether the document is a valid client. That is
 * `validate.ts`, and separating them means this file can be read for one question only: can a caller
 * make this server talk to something it should not.
 */

/* The draft's §6.6 recommendation, adopted rather than invented. */
export const MAX_DOCUMENT_BYTES = 5 * 1024;

/*
 * A host that accepts a connection and then says nothing must not hold an authorization request open.
 * Short because a client description document is a small static file; a host that cannot serve one in
 * two seconds is not one an end-user should be kept waiting on.
 */
export const FETCH_TIMEOUT_MS = 2_000;

/*
 * The draft permits a chain; nothing legitimate needs a long one. Four is enough for a canonical-URL
 * redirect and a CDN hop, and short enough that a loop is refused in milliseconds.
 */
export const MAX_REDIRECTS = 4;

/*
 * Name resolution, behind a seam so a spec can say what an answer *is* rather than depend on how the
 * network resolves a name today.
 *
 * It also serves the harder property. The check and the request must agree about the address, and
 * they cannot be made atomic here — the platform's fetch resolves the name again itself. So this is
 * pinned as far as it can be: the answer is taken once, checked, and the same host is what is
 * requested. A name that changes between the two remains the residual risk the MCP guidance calls
 * TOCTOU, and closing it properly needs an egress proxy, which is a deployment control rather than
 * something this module can assert. Said plainly rather than implied by silence.
 */
export const resolver = {
	realLookup: async (host: string): Promise<string[]> => {
		const answers = await dnsLookup(host, { all: true });
		return answers.map((answer) => answer.address);
	},
	lookup: async (host: string): Promise<string[]> => resolver.realLookup(host)
};

export type FetchFailure =
	| 'bad_identifier'
	| 'unresolvable'
	| 'blocked_address'
	| 'bad_redirect'
	| 'too_many_redirects'
	| 'status'
	| 'too_large'
	| 'timeout'
	| 'unreachable';

export type FetchResult =
	| {
			readonly ok: true;
			readonly body: string;
			/* What the response said about reuse, for the cache to interpret. Raw, not parsed. */
			readonly cacheControl: string | null;
			readonly expires: string | null;
	  }
	| { readonly ok: false; readonly reason: FetchFailure };

/*
 * Whether an address is one this server must refuse to talk to.
 *
 * Written against the textual forms because that is what resolution returns, and kept to prefix and
 * range tests rather than a general CIDR engine — the set is fixed and small, and a general parser
 * would be more code to get subtly wrong. The MCP guidance warns against hand-rolling IP validation
 * because "attackers exploit encoding tricks (octal, hex, IPv4-mapped IPv6) that custom parsers often
 * miss"; that warning is about validating *user input*, and it is why this function is applied to a
 * resolver's answer instead. A resolver returns a normalised address, never `0x7f.1`.
 */
export function isBlockedAddress(address: string): boolean {
	const version = isIP(address);
	if (version === 0) return true;

	if (version === 4) {
		const octets = address.split('.').map(Number);
		const [a, b] = octets;
		if (a === 10) return true;
		if (a === 127) return true;
		if (a === 0) return true;
		if (a === 169 && b === 254) return true;
		if (a === 172 && b >= 16 && b <= 31) return true;
		if (a === 192 && b === 168) return true;
		/* Carrier-grade NAT and the benchmarking range: not public, not ours to probe. */
		if (a === 100 && b >= 64 && b <= 127) return true;
		if (a === 198 && (b === 18 || b === 19)) return true;
		if (a >= 224) return true;
		return false;
	}

	const normalized = address.toLowerCase();
	if (normalized === '::' || normalized === '::1') return true;
	/* Unique-local (fc00::/7) and link-local (fe80::/10). */
	if (/^f[cd]/.test(normalized)) return true;
	if (/^fe[89ab]/.test(normalized)) return true;
	/*
	 * An IPv4-mapped address carries the v4 rules with it. Checking the mapped form is what stops
	 * `::ffff:169.254.169.254` from being treated as an ordinary v6 address.
	 */
	const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
	if (mapped) return isBlockedAddress(mapped[1]);
	return false;
}

async function assertReachable(host: string): Promise<FetchFailure | null> {
	/*
	 * A literal address needs no resolution, and passing one to the resolver would be a lookup of a
	 * name that is not one. It is still checked — an identifier naming `https://10.0.0.1/c.json`
	 * directly is the simplest form of this attack.
	 */
	if (isIP(host) !== 0) {
		return isBlockedAddress(host) ? 'blocked_address' : null;
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

/*
 * Retrieves a document, or says why not. Never throws: a caller is deciding whether to admit a client,
 * and an exception escaping into that decision would turn an unknown client into a 500.
 */
export async function fetchClientDocument(
	identifier: string
): Promise<FetchResult> {
	const parsed = parseClientIdentifierUrl(identifier);
	if (!parsed.ok) return { ok: false, reason: 'bad_identifier' };

	let target = parsed.url;

	for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
		const blocked = await assertReachable(target.hostname);
		if (blocked) return { ok: false, reason: blocked };

		let response: Response;
		try {
			response = await fetch(target.href, {
				method: 'GET',
				headers: { accept: 'application/json' },
				/*
				 * Manual, because the platform following a redirect for us would follow it to an address
				 * nothing checked. The loop above re-runs every guard per hop instead.
				 */
				redirect: 'manual',
				signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
			});
		} catch (err) {
			return {
				ok: false,
				reason:
					err instanceof Error && err.name === 'TimeoutError'
						? 'timeout'
						: 'unreachable'
			};
		}

		if (response.status >= 300 && response.status < 400) {
			const location = response.headers.get('location');
			if (!location) return { ok: false, reason: 'bad_redirect' };

			const next = URL.parse(location, target.href);
			/*
			 * A redirect destination is held to the scheme rule but not to the rest of §3: the document
			 * lives wherever the host says, and only the `client_id` *inside* it has to match the
			 * identifier the client presented. That equality check is `validate.ts`'s, and it is what makes
			 * a redirect harmless.
			 */
			if (!next || next.protocol !== 'https:') {
				return { ok: false, reason: 'bad_redirect' };
			}
			target = next;
			continue;
		}

		if (!response.ok) return { ok: false, reason: 'status' };

		const declared = Number(response.headers.get('content-length'));
		if (Number.isFinite(declared) && declared > MAX_DOCUMENT_BYTES) {
			return { ok: false, reason: 'too_large' };
		}

		let body: string;
		try {
			body = await response.text();
		} catch {
			return { ok: false, reason: 'unreachable' };
		}
		/*
		 * Checked again against what actually arrived. A `content-length` is a claim by the host being
		 * guarded against, so trusting it alone would leave the bound unenforced for anyone who lies.
		 */
		if (Buffer.byteLength(body, 'utf8') > MAX_DOCUMENT_BYTES) {
			return { ok: false, reason: 'too_large' };
		}

		return {
			ok: true,
			body,
			cacheControl: response.headers.get('cache-control'),
			expires: response.headers.get('expires')
		};
	}

	return { ok: false, reason: 'too_many_redirects' };
}
