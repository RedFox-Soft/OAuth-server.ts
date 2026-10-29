import { isIP, type BlockList } from 'node:net';

import {
	ApplicationConfig,
	onSettingsApplied
} from '../configs/application.js';
import { CLOUDFLARE_RANGES } from '../consts/cloudflare_ranges.js';
import {
	inRanges,
	isProxyNetworkAddress,
	rangeList
} from './public_address.js';

/*
 * The one answer to "who is calling": the address every limit and record attributes a request to.
 *
 * WHY one place. The rate limit, the credential charges, the error store and the mail limit each used to
 * read the address themselves, and two of them read the first entry of X-Forwarded-For, which is
 * whatever the caller wrote. A forwarded header is now believed only on a connection from a proxy the
 * operator's choice trusts (`clientAddress.source`), and only the part that proxy wrote is read.
 */

export type CallerAddressSource =
	'connection' | 'x-forwarded-for' | 'fly-client-ip' | 'unattributed';

export interface CallerAddress {
	readonly address: string;
	readonly from: CallerAddressSource;
	/* The socket peer, for the console's address check; null when there is none. */
	readonly connection: string | null;
}

/*
 * A request with no connection at all — one the server dispatched to itself — still needs a key. One
 * shared marker, never a header value, so nothing a caller sends can become it.
 */
export const UNATTRIBUTED = 'unknown';

/* Bounded before parsing, as the old resolver did, so a header cannot make a key of any length. */
const MAX_ADDRESS_LENGTH = 64;

const CLOUDFLARE = rangeList(CLOUDFLARE_RANGES);

let listed: BlockList | null | undefined;
onSettingsApplied((appliedKeys) => {
	if (appliedKeys.includes('clientAddress.trustedProxies')) {
		listed = undefined;
	}
});

function listedProxies(): BlockList | null {
	listed ??= rangeList(ApplicationConfig['clientAddress.trustedProxies']);
	return listed;
}

export function isTrustedProxy(address: string): boolean {
	switch (ApplicationConfig['clientAddress.source']) {
		case 'direct':
			return false;
		case 'cloudflare':
			return (
				isProxyNetworkAddress(address) ||
				(CLOUDFLARE !== null && inRanges(CLOUDFLARE, address))
			);
		case 'listed': {
			const list = listedProxies();
			return (
				isProxyNetworkAddress(address) ||
				(list !== null && inRanges(list, address))
			);
		}
		default:
			return isProxyNetworkAddress(address);
	}
}

/*
 * An entry as some load balancers write it — `203.0.113.7:51234`, `[2001:db8::1]:443` — reduced to the
 * address. Anything else that is not an IP literal stays unparseable and stops the walk.
 */
function literalOf(entry: string): string | null {
	const value = entry.trim().slice(0, MAX_ADDRESS_LENGTH);
	if (isIP(value) !== 0) return value;
	const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
	if (bracketed && isIP(bracketed[1]) === 6) return bracketed[1];
	const withPort = /^(\d+\.\d+\.\d+\.\d+):\d+$/.exec(value);
	if (withPort && isIP(withPort[1]) === 4) return withPort[1];
	return null;
}

/*
 * A proxy appends the address it received from, so everything left of its entry is whatever arrived with
 * the request. Read right to left: each entry a trusted proxy wrote is skipped, and the first one that is
 * not is the caller. When every entry is a trusted proxy the rightmost is taken — the one the nearest
 * proxy wrote — so a client inside the operator's own network cannot rotate forged private entries. An
 * entry that is not an address stops the walk at the last trusted hop, never at the raw text.
 */
function walkForwardedFor(header: string, peer: string): CallerAddress {
	const entries = header.split(',');
	const connection = peer;
	let lastTrusted: CallerAddress = {
		address: peer,
		from: 'connection',
		connection
	};
	let rightmost: string | null = null;
	for (let i = entries.length - 1; i >= 0; i -= 1) {
		const literal = literalOf(entries[i]);
		if (literal === null) return lastTrusted;
		rightmost ??= literal;
		if (!isTrustedProxy(literal)) {
			return { address: literal, from: 'x-forwarded-for', connection };
		}
		lastTrusted = { address: literal, from: 'x-forwarded-for', connection };
	}
	return rightmost === null
		? lastTrusted
		: { address: rightmost, from: 'x-forwarded-for', connection };
}

type PeerResolver = (request: Request) => string | undefined;

/*
 * `elysia.handle()` has no socket, so a spec states the connection's address through this seam rather
 * than never exercising one. Production leaves it null.
 */
let peerResolverForTests: PeerResolver | null = null;
export function setPeerResolverForTests(resolver: PeerResolver | null): void {
	peerResolverForTests = resolver;
}

function peerOf(request: Request, server: unknown): string | undefined {
	if (peerResolverForTests) return peerResolverForTests(request);
	return (
		server as {
			requestIP?: (r: Request) => { address?: string } | null;
		} | null
	)?.requestIP?.(request)?.address;
}

function resolve(request: Request, server: unknown): CallerAddress {
	const peer = peerOf(request, server)?.slice(0, MAX_ADDRESS_LENGTH);
	if (!peer) {
		return { address: UNATTRIBUTED, from: 'unattributed', connection: null };
	}
	if (!isTrustedProxy(peer)) {
		return { address: peer, from: 'connection', connection: peer };
	}

	if (ApplicationConfig['clientAddress.source'] === 'fly') {
		const fly = literalOf(request.headers.get('fly-client-ip') ?? '');
		return fly === null
			? { address: peer, from: 'connection', connection: peer }
			: { address: fly, from: 'fly-client-ip', connection: peer };
	}

	const forwarded = request.headers.get('x-forwarded-for');
	return forwarded
		? walkForwardedFor(forwarded, peer)
		: { address: peer, from: 'connection', connection: peer };
}

/*
 * Memoised per request, so every consumer gets the same answer and none needs `server`: the
 * first onRequest hook (lib/plugins/instancePlane.ts) computes it with the socket, and later readers — an error
 * handler, a mail route — take what it found.
 */
const memo = new WeakMap<Request, CallerAddress>();

export function callerAddressOf(
	request: Request,
	server?: unknown
): CallerAddress {
	const known = memo.get(request);
	if (known) return known;
	const resolved = resolve(request, server);
	memo.set(request, resolved);
	return resolved;
}
