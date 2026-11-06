/*
 * Network addresses and ranges for the "from where" condition (specs/124 research R4). Imports nothing: the console
 * bundles it beside `decide()`, so the address a person types into "Check access" is read exactly as the check reads
 * the one a proxy reports.
 *
 * Only strict forms are addresses. A port, brackets, a zone, a leading zero, a short or integer IPv4 form, or any
 * embedded IPv4 other than the mapped one is no address at all: parsers disagree on those, and an address this
 * module read differently from the operator's proxy would be compared as something it is not.
 */

export interface Address {
	readonly version: 4 | 6;
	readonly value: bigint;
}

export interface Range {
	readonly version: 4 | 6;
	readonly base: bigint;
	readonly bits: number;
}

export type RangeError = 'malformed' | 'host_bits' | 'everything';

const IPV4_PART = /^(0|[1-9][0-9]{0,2})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/;
const MAPPED_PREFIX = 0xffffn << 32n;

function widthOf(version: 4 | 6): number {
	return version === 4 ? 32 : 128;
}

function parseIpv4(text: string): bigint | null {
	const parts = text.split('.');
	if (parts.length !== 4) return null;
	let value = 0n;
	for (const part of parts) {
		if (!IPV4_PART.test(part)) return null;
		const octet = Number(part);
		if (octet > 255) return null;
		value = (value << 8n) | BigInt(octet);
	}
	return value;
}

function parseGroups(text: string): bigint[] | null {
	if (text === '') return [];
	const groups: bigint[] = [];
	for (const group of text.split(':')) {
		if (!HEX_GROUP.test(group)) return null;
		groups.push(BigInt(parseInt(group, 16)));
	}
	return groups;
}

function parseIpv6(raw: string): bigint | null {
	const text = raw.toLowerCase();
	if (text.includes('.')) {
		/* The one embedded form this module reads: an IPv4-mapped address, which is that IPv4 address. */
		const match = /^::ffff:([0-9.]+)$/.exec(text);
		if (!match) return null;
		const v4 = parseIpv4(match[1]);
		return v4 === null ? null : MAPPED_PREFIX | v4;
	}
	const halves = text.split('::');
	if (halves.length > 2) return null;
	let groups: bigint[];
	if (halves.length === 2) {
		const head = parseGroups(halves[0]);
		const tail = parseGroups(halves[1]);
		if (!head || !tail || head.length + tail.length > 7) return null;
		groups = [
			...head,
			...Array<bigint>(8 - head.length - tail.length).fill(0n),
			...tail
		];
	} else {
		const all = parseGroups(text);
		if (!all || all.length !== 8) return null;
		groups = all;
	}
	return groups.reduce((value, group) => (value << 16n) | group, 0n);
}

/* An IPv6 address in the mapped space is the IPv4 address it carries. */
function normalised(version: 4 | 6, value: bigint): Address {
	if (version === 6 && value >> 32n === 0xffffn) {
		return { version: 4, value: value & 0xffffffffn };
	}
	return { version, value };
}

export function parseAddress(text: string): Address | null {
	if (text === '' || text.length > 45 || text !== text.trim()) return null;
	if (text.includes(':')) {
		const value = parseIpv6(text);
		return value === null ? null : normalised(6, value);
	}
	const value = parseIpv4(text);
	return value === null ? null : { version: 4, value };
}

export function formatAddress(address: Address): string {
	if (address.version === 4) {
		const v = address.value;
		return [24n, 16n, 8n, 0n]
			.map((shift) => String((v >> shift) & 255n))
			.join('.');
	}
	const groups = Array.from({ length: 8 }, (_, i) =>
		Number((address.value >> BigInt((7 - i) * 16)) & 0xffffn)
	);
	/* RFC 5952 §4.2: the longest run of two or more zero groups, the first on a tie, becomes `::`. */
	let bestStart = -1;
	let bestLength = 1;
	for (let i = 0; i < 8;) {
		if (groups[i] !== 0) {
			i += 1;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === 0) j += 1;
		if (j - i > bestLength) {
			bestStart = i;
			bestLength = j - i;
		}
		i = j;
	}
	const hex = groups.map((group) => group.toString(16));
	if (bestStart === -1) return hex.join(':');
	const head = hex.slice(0, bestStart).join(':');
	const tail = hex.slice(bestStart + bestLength).join(':');
	return `${head}::${tail}`;
}

function maskOf(version: 4 | 6, bits: number): bigint {
	const width = widthOf(version);
	return ((1n << BigInt(width)) - 1n) ^ ((1n << BigInt(width - bits)) - 1n);
}

/*
 * A range as an operator writes it: an address with a prefix length, or a bare address meaning that address alone.
 * Host bits set beyond the prefix, and a prefix of zero bits, are refused rather than read generously: the first is
 * a typo more often than an intention, and the second would mean every address there is.
 */
export function parseRange(text: string): Range | { error: RangeError } {
	const slash = text.indexOf('/');
	const addressText = slash === -1 ? text : text.slice(0, slash);
	const lengthText = slash === -1 ? null : text.slice(slash + 1);
	const isV6 = addressText.includes(':');
	const raw = isV6 ? parseIpv6(addressText) : parseIpv4(addressText);
	if (raw === null || addressText !== addressText.trim()) {
		return { error: 'malformed' };
	}
	const version: 4 | 6 = isV6 ? 6 : 4;
	const width = widthOf(version);
	let bits = width;
	if (lengthText !== null) {
		if (!/^(0|[1-9][0-9]{0,2})$/.test(lengthText))
			return { error: 'malformed' };
		bits = Number(lengthText);
		if (bits > width) return { error: 'malformed' };
	}
	if (bits === 0) return { error: 'everything' };
	if ((raw & ~maskOf(version, bits)) !== 0n) return { error: 'host_bits' };
	/* A range wholly inside the mapped space is an IPv4 range, so it matches the addresses read as IPv4. */
	if (version === 6 && bits >= 96 && raw >> 32n === 0xffffn) {
		if (bits === 96) return { error: 'everything' };
		return { version: 4, base: raw & 0xffffffffn, bits: bits - 96 };
	}
	return { version, base: raw, bits };
}

export function formatRange(range: Range): string {
	return `${formatAddress({ version: range.version, value: range.base })}/${String(range.bits)}`;
}

export function inRange(address: Address, range: Range): boolean {
	if (address.version !== range.version) return false;
	return (address.value & maskOf(range.version, range.bits)) === range.base;
}

export function inAnyRange(
	address: Address,
	ranges: readonly Range[]
): boolean {
	return ranges.some((range) => inRange(address, range));
}

const NOT_PUBLIC: readonly Range[] = [
	'0.0.0.0/8',
	'10.0.0.0/8',
	'100.64.0.0/10',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.168.0.0/16',
	'224.0.0.0/3',
	'::/128',
	'::1/128',
	'fc00::/7',
	'fe80::/10',
	'ff00::/8'
].map((text) => parseRange(text) as Range);

/*
 * Whether the address belongs to the public Internet. A private, loopback, link-local, shared (CGNAT), multicast or
 * unspecified address reaching the check means the proxy saw its own network — a load balancer, a container bridge —
 * and not the person.
 */
export function isPublic(address: Address): boolean {
	return !inAnyRange(address, NOT_PUBLIC);
}

/* Whether any address of the range is one `isPublic` refuses: two CIDR ranges overlap when one holds the other's base. */
export function overlapsNotPublic(range: Range): boolean {
	return NOT_PUBLIC.some(
		(other) =>
			other.version === range.version &&
			(inRange({ version: range.version, value: range.base }, other) ||
				inRange({ version: other.version, value: other.base }, range))
	);
}

/* The ranges as closed intervals per version, merged where they touch. */
function merged(ranges: readonly Range[], version: 4 | 6): [bigint, bigint][] {
	const width = BigInt(widthOf(version));
	const intervals = ranges
		.filter((range) => range.version === version)
		.map((range): [bigint, bigint] => [
			range.base,
			range.base + (1n << (width - BigInt(range.bits))) - 1n
		])
		.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
	const out: [bigint, bigint][] = [];
	for (const [start, end] of intervals) {
		const last = out.at(-1);
		if (last && start <= last[1] + 1n) {
			if (end > last[1]) last[1] = end;
		} else {
			out.push([start, end]);
		}
	}
	return out;
}

/* Whether every address of `range` is in one of `ranges` — what deciding that a list did not grow needs. */
export function coveredBy(range: Range, ranges: readonly Range[]): boolean {
	const width = BigInt(widthOf(range.version));
	const end = range.base + (1n << (width - BigInt(range.bits))) - 1n;
	return merged(ranges, range.version).some(
		([start, stop]) => start <= range.base && end <= stop
	);
}

export function parseRanges(texts: readonly string[]): Range[] {
	const out: Range[] = [];
	for (const text of texts) {
		const range = parseRange(text);
		if (!('error' in range)) out.push(range);
	}
	return out;
}
