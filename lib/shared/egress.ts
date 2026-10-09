import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

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
 * The ranges this server refuses to reach, as a `node:net` BlockList, which compares addresses as
 * numbers rather than as text. Text was the first version and it was wrong the first time it met URL
 * parsing: `https://[::ffff:169.254.169.254]/` arrives with the hostname `[::ffff:a9fe:a9fe]`, which a
 * pattern written for the dotted form let through to the cloud metadata endpoint.
 */
const BLOCKED = new BlockList();
for (const [network, prefix] of [
	['0.0.0.0', 8],
	['10.0.0.0', 8],
	/* Carrier-grade NAT: not public, not ours to probe. */
	['100.64.0.0', 10],
	['127.0.0.0', 8],
	['169.254.0.0', 16],
	['172.16.0.0', 12],
	/* IETF protocol assignments, the documentation ranges and the retired 6to4 relay anycast. */
	['192.0.0.0', 24],
	['192.0.2.0', 24],
	['192.88.99.0', 24],
	['192.168.0.0', 16],
	/* The benchmarking range. */
	['198.18.0.0', 15],
	['198.51.100.0', 24],
	['203.0.113.0', 24],
	/* Multicast, the reserved block and broadcast. */
	['224.0.0.0', 3]
] as const) {
	BLOCKED.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
	['::', 128],
	['::1', 128],
	/* Discard-only, Teredo (which carries an obfuscated IPv4) and the documentation ranges. */
	['100::', 64],
	['2001::', 32],
	['2001:db8::', 32],
	['3fff::', 20],
	/* The NAT64 local-use prefix, whose IPv4 layout depends on how a network configured it. */
	['64:ff9b:1::', 48],
	/* Unique-local, link-local, the deprecated site-local, and multicast. */
	['fc00::', 7],
	['fe80::', 10],
	['fec0::', 10],
	['ff00::', 8]
] as const) {
	BLOCKED.addSubnet(network, prefix, 'ipv6');
}

/* An IPv6 address as its sixteen bytes, embedded dotted IPv4 tail included. */
function ipv6Bytes(address: string): number[] {
	let text = address;
	const tail = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
	if (tail) {
		const [a, b, c, d] = tail[1].split('.').map(Number);
		text = `${text.slice(0, -tail[1].length)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
	}
	const halves = text.split('::');
	const head = halves[0];
	const rest = halves.at(1);
	const left = head ? head.split(':') : [];
	const right = rest ? rest.split(':') : [];
	const groups =
		rest === undefined
			? left
			: [
					...left,
					...Array<string>(8 - left.length - right.length).fill('0'),
					...right
				];
	return groups.flatMap((group) => {
		const value = parseInt(group, 16);
		return [value >> 8, value & 0xff];
	});
}

/*
 * The IPv4 address an IPv6 one carries, in the layouts where reaching the IPv6 address reaches that IPv4
 * host: mapped (`::ffff:0:0/96`), compatible (`::/96`), SIIT (`::ffff:0:0:0/96`), well-known NAT64
 * (`64:ff9b::/96`) and 6to4 (`2002::/16`). The NAT64 prefix is not refused outright: on an IPv6-only
 * network with DNS64 every IPv4-only public host is reached through it, so it is judged by what it carries.
 */
function embeddedIPv4(address: string): string | undefined {
	const b = ipv6Bytes(address);
	const zero = (from: number, to: number) =>
		b.slice(from, to).every((byte) => byte === 0);
	const dotted = (at: number) => b.slice(at, at + 4).join('.');

	if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return dotted(12);
	if (zero(0, 12)) return dotted(12);
	if (zero(0, 8) && b[8] === 0xff && b[9] === 0xff && zero(10, 12)) {
		return dotted(12);
	}
	if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
		if (zero(4, 12)) return dotted(12);
	}
	if (b[0] === 0x20 && b[1] === 0x02) return dotted(2);
	return undefined;
}

/*
 * Whether an address is one this server must refuse to talk to. Applied to a literal from a URL and to
 * every answer a resolver gives, so it cannot assume either arrives in one spelling.
 */
export function isBlockedAddress(address: string): boolean {
	/* A zone index names an interface, not a host; it is not part of the address being judged. */
	const literal = address.replace(/%.*$/, '');
	const version = isIP(literal);
	if (version === 0) return true;
	if (version === 4) return BLOCKED.check(literal, 'ipv4');

	if (BLOCKED.check(literal, 'ipv6')) return true;
	const carried = embeddedIPv4(literal);
	return carried !== undefined && BLOCKED.check(carried, 'ipv4');
}

async function assertReachable(host: string): Promise<EgressFailure | null> {
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
	readonly method?: 'GET' | 'POST';
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
 * received the notification.
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

		if (method !== 'GET' || response.status < 300 || response.status >= 400) {
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
