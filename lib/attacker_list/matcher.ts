import type { Address } from '../behind_proxy/net.js';
import type { ParsedEntry } from './parse.js';

/*
 * The list in a form a sign-in can ask synchronously (specs/125 research R4): one sorted typed array per family —
 * IPv4 addresses, and the first 64 bits of IPv6 /64 networks, the only widths FoxTrust's format 1 lists — with the
 * last sighting and the corroboration marker beside each, found by binary search. Built whole before it replaces the
 * previous one, so a request sees one list or the other, never half of one.
 */

export interface ListEntry {
	/* Unix seconds of the hour of the latest sighting. */
	readonly lastSeen: number;
	readonly corroborated: boolean;
}

interface Family<K extends Uint32Array | BigUint64Array> {
	readonly keys: K;
	readonly lastSeen: Float64Array;
	readonly corroborated: Uint8Array;
}

export interface Matcher {
	readonly size: number;
	lookup(address: Address): ListEntry | null;
}

function familyOf(
	entries: readonly ParsedEntry[],
	version: 4 | 6
): { keys: bigint[]; lastSeen: number[]; corroborated: boolean[] } {
	const sorted = entries
		.filter((entry) => entry.version === version)
		.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
	const keys: bigint[] = [];
	const lastSeen: number[] = [];
	const corroborated: boolean[] = [];
	for (const entry of sorted) {
		const last = keys.length - 1;
		if (last >= 0 && keys[last] === entry.key) {
			// One line per network and code in format 1; should two ever meet, the stronger reading wins.
			lastSeen[last] = Math.max(lastSeen[last], entry.lastSeen);
			corroborated[last] = corroborated[last] || entry.corroborated;
			continue;
		}
		keys.push(entry.key);
		lastSeen.push(entry.lastSeen);
		corroborated.push(entry.corroborated);
	}
	return { keys, lastSeen, corroborated };
}

function search<K extends Uint32Array | BigUint64Array>(
	family: Family<K>,
	key: K extends Uint32Array ? number : bigint
): ListEntry | null {
	let lo = 0;
	let hi = family.keys.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		const at = family.keys[mid] as K extends Uint32Array ? number : bigint;
		if (at < key) lo = mid + 1;
		else if (at > key) hi = mid - 1;
		else {
			return {
				lastSeen: family.lastSeen[mid],
				corroborated: family.corroborated[mid] === 1
			};
		}
	}
	return null;
}

export function buildMatcher(entries: readonly ParsedEntry[]): Matcher {
	const four = familyOf(entries, 4);
	const six = familyOf(entries, 6);
	const v4: Family<Uint32Array> = {
		keys: Uint32Array.from(four.keys, Number),
		lastSeen: Float64Array.from(four.lastSeen),
		corroborated: Uint8Array.from(four.corroborated, (c) => (c ? 1 : 0))
	};
	const v6: Family<BigUint64Array> = {
		keys: BigUint64Array.from(six.keys),
		lastSeen: Float64Array.from(six.lastSeen),
		corroborated: Uint8Array.from(six.corroborated, (c) => (c ? 1 : 0))
	};
	return {
		size: v4.keys.length + v6.keys.length,
		lookup(address) {
			return address.version === 4
				? search(v4, Number(address.value))
				: search(v6, address.value >> 64n);
		}
	};
}
