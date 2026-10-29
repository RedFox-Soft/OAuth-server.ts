import { BlockList, isIP } from 'node:net';

/*
 * Every range that is not a public address, as a `node:net` BlockList, which compares addresses as
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
 * Applies `check` to an address in every spelling that reaches the same host: as written, and as the
 * IPv4 address an IPv6 one carries. A zone index names an interface, not a host, so it is dropped first.
 */
function judged(
	address: string,
	check: (literal: string, family: 'ipv4' | 'ipv6') => boolean
): boolean | undefined {
	const literal = address.replace(/%.*$/, '');
	const version = isIP(literal);
	if (version === 0) return undefined;
	if (version === 4) return check(literal, 'ipv4');
	if (check(literal, 'ipv6')) return true;
	const carried = embeddedIPv4(literal);
	return carried !== undefined && check(carried, 'ipv4');
}

/*
 * Whether an address is routable on the public internet. The outbound boundary refuses everything that
 * is not (lib/shared/egress.ts), and a caller address that is not public is never a remote attacker
 * worth naming to anyone. A value that is not an IP address is not public.
 */
export function isPublicAddress(address: string): boolean {
	const blocked = judged(address, (literal, family) =>
		BLOCKED.check(literal, family)
	);
	return blocked === false;
}

/*
 * The networks a reverse proxy in front of this server is found on: the IPv4 private ranges, loopback,
 * link-local and IPv6 unique-local. Narrower than "not public" on purpose. Shared address space
 * (100.64.0.0/10) is where carrier-grade NAT and overlay networks such as Tailscale put their clients,
 * and a client trusted as a proxy could write the caller address itself.
 */
const PROXY_NETWORKS = new BlockList();
for (const [network, prefix] of [
	['10.0.0.0', 8],
	['127.0.0.0', 8],
	['169.254.0.0', 16],
	['172.16.0.0', 12],
	['192.168.0.0', 16]
] as const) {
	PROXY_NETWORKS.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
	['::1', 128],
	['fc00::', 7],
	['fe80::', 10]
] as const) {
	PROXY_NETWORKS.addSubnet(network, prefix, 'ipv6');
}

export function isProxyNetworkAddress(address: string): boolean {
	return (
		judged(address, (literal, family) =>
			PROXY_NETWORKS.check(literal, family)
		) === true
	);
}

/*
 * A BlockList of `address` or `address/prefix` entries, for ranges an operator or a platform publishes.
 * Returns null when an entry is malformed, so a caller can refuse the whole list rather than trust part
 * of it.
 */
export function rangeList(entries: readonly string[]): BlockList | null {
	const list = new BlockList();
	for (const entry of entries) {
		const slash = entry.indexOf('/');
		const network = (slash === -1 ? entry : entry.slice(0, slash)).trim();
		const bits = slash === -1 ? null : entry.slice(slash + 1).trim();
		const family = isIP(network);
		if (family === 0) return null;
		const max = family === 4 ? 32 : 128;
		if (bits !== null && !/^\d+$/.test(bits)) return null;
		const prefix = bits === null ? max : Number(bits);
		if (prefix > max) return null;
		list.addSubnet(network, prefix, family === 4 ? 'ipv4' : 'ipv6');
	}
	return list;
}

export function inRanges(list: BlockList, address: string): boolean {
	return (
		judged(address, (literal, family) => list.check(literal, family)) === true
	);
}
