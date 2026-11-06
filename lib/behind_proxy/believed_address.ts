import type { UserBucket } from '../adapters/types.js';
import { CLOUDFLARE_RANGES } from '../consts/cloudflare_ranges.js';
import {
	formatAddress,
	inAnyRange,
	isPublic,
	parseAddress,
	parseRanges
} from './net.js';
import { matchProxyKey, PROXY_KEY_HEADER, proxyKeysOf } from './proxy_key.js';

/*
 * The person's address at a check (specs/124 FR-006, research R4). It comes from `X-Forwarded-For`, which a browser
 * can write as easily as a proxy, so it is believed only when the check carries one of the project's proxy keys —
 * a proxy running the recipe that overwrites that header — and only when the header holds exactly one address in a
 * form no two parsers read differently.
 *
 * The address is only ever compared with the ranges of a condition. It is not the caller of the check, never goes
 * into a rate limit, an attack report, a log line or an event, and is not kept: the Connect page sees only the flags.
 */

const FORWARDED_FOR = 'x-forwarded-for';

/* The address the console's proxy test sends; reaching the check, it shows the proxy passed a browser's value on. */
export const PROBE_ADDRESS = '192.0.2.66';

const CLOUDFLARE = parseRanges(CLOUDFLARE_RANGES);

export interface AddressFlags {
	keyPresent: boolean;
	keyValid: boolean;
	addressPresent: boolean;
	/* Exactly one address, in strict form. */
	single: boolean;
	isPublic: boolean;
	/* One of Cloudflare's edge addresses: the proxy sees the CDN, not the person. */
	cloudflare: boolean;
	probe: boolean;
}

export interface Believed {
	/* The canonical address, or null when none is believed. */
	address: string | null;
	/*
	 * The single address the header held, believed or not — only for the requester's own self-test page, never kept,
	 * logged or compared.
	 */
	reported: string | null;
	flags: AddressFlags;
}

export function believedAddressWith(
	request: Request,
	bucket: Pick<UserBucket, 'proxyKeys'>
): Believed {
	const key = matchProxyKey(bucket, request.headers.get(PROXY_KEY_HEADER));
	const raw = request.headers.get(FORWARDED_FOR);
	/* Two headers arrive joined by a comma, and a chain is written with one: either way, no single answer. */
	const parsed = raw === null || raw.includes(',') ? null : parseAddress(raw);
	const flags: AddressFlags = {
		keyPresent: key.present,
		keyValid: key.valid,
		addressPresent: raw !== null && raw !== '',
		single: parsed !== null,
		isPublic: parsed !== null && isPublic(parsed),
		cloudflare: parsed !== null && inAnyRange(parsed, CLOUDFLARE),
		probe: parsed !== null && formatAddress(parsed) === PROBE_ADDRESS
	};
	return {
		address: key.valid && parsed ? formatAddress(parsed) : null,
		reported: parsed ? formatAddress(parsed) : null,
		flags
	};
}

/* A check that proves the proxy passes people's addresses: the key, one public address, neither the CDN nor the probe. */
export function proves(flags: AddressFlags): boolean {
	return (
		flags.keyValid &&
		flags.single &&
		flags.isPublic &&
		!flags.cloudflare &&
		!flags.probe
	);
}

/* A check that shows the proxy passed the console's probe — a value a browser chose — on to the check. */
export function forged(flags: AddressFlags): boolean {
	return flags.keyValid && flags.probe;
}

/* The project's keys are read only when the check presents one: without a key no address is believed anyway. */
export async function believedAddress(
	request: Request,
	bucketId: string
): Promise<Believed> {
	const presented = request.headers.get(PROXY_KEY_HEADER);
	const keys =
		presented === null || presented === ''
			? { proxyKeys: [] }
			: await proxyKeysOf(bucketId);
	return believedAddressWith(request, keys);
}
