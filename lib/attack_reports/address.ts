import { isIP } from 'node:net';

import type { CallerAddress } from '../helpers/caller_address.js';
import { isPublicAddress } from '../helpers/public_address.js';

const IPV4_MAPPED = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i;

/*
 * The eight hextets of an IPv6 literal. Through the WHATWG URL parser first, which validates it and writes
 * every form, an embedded dotted IPv4 included, as lowercase hex with at most one `::`.
 */
function hextetsOf(address: string): string[] {
	const host = new URL(`http://[${address}]`).hostname.slice(1, -1);
	const gap = host.indexOf('::');
	if (gap === -1) return host.split(':');
	const head = host.slice(0, gap);
	const tail = host.slice(gap + 2);
	const left = head ? head.split(':') : [];
	const right = tail ? tail.split(':') : [];
	return [
		...left,
		...Array<string>(8 - left.length - right.length).fill('0'),
		...right
	];
}

/* The /64 network of an IPv6 address, in RFC 5952 text, which the same parser produces when given it back. */
function network64(address: string): string {
	const prefix = [...hextetsOf(address).slice(0, 4), '0', '0', '0', '0'].join(
		':'
	);
	return `${new URL(`http://[${prefix}]`).hostname.slice(1, -1)}/64`;
}

/*
 * The form an attacking caller leaves the instance in, or null when it must not leave at all (specs/114,
 * FR-007, FR-008): only a globally routable address, IPv4 in full and IPv6 as its /64.
 *
 * An IPv4-mapped address is read as its IPv4 address first. Bun reports every IPv4 connection on a
 * dual-stack socket in that form, and without this step every IPv4 attacker would leave as the /64 of
 * `::ffff:0:0`, one network for the whole IPv4 internet.
 */
export function reportedAddressOf(caller: CallerAddress): string | null {
	if (caller.from === 'unattributed') return null;
	const mapped = IPV4_MAPPED.exec(caller.address);
	const address = mapped ? mapped[1] : caller.address;
	const family = isIP(address);
	if (family === 0 || !isPublicAddress(address)) return null;
	return family === 4 ? address : network64(address);
}
