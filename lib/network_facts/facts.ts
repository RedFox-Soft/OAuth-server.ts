import type { NetworkFacts } from '../behind_proxy/conditions.js';
import type { Address } from '../behind_proxy/net.js';
import {
	FOXTRUST_CATEGORY_MAP,
	NETWORK_FACTS_CACHE_ENTRIES,
	type NetworkCategory
} from '../consts/network_facts.js';
import { UNREADABLE, type MmdbReader, type MmdbValue } from './mmdb.js';

/*
 * A loaded pair of FoxTrust files and what it says about one address (specs/129 research R6, data-model §4 and §6).
 *
 * The update is looked at first: a record `{ removed: true }` there means the address has no record now, and no data
 * there means the full file decides — FoxTrust's own consumer reads it this way (FT src/mmdb/reader.ts `overlay`).
 * Only `categories` and `country.iso_code` are read; risk, level and reasons never are (FR-010).
 */

export interface LoadedPair {
	readonly full: MmdbReader;
	readonly delta: MmdbReader | null;
	readonly fullVersion: string;
	readonly deltaVersion: string | null;
	readonly builtAt: string;
	readonly ranges: number;
	factsOf(address: Address): NetworkFacts;
}

const NOTHING: NetworkFacts = Object.freeze({
	known: true,
	categories: Object.freeze([]),
	country: null
});
const UNKNOWN: NetworkFacts = Object.freeze({ known: false });
const COUNTRY = /^[A-Z]{2}$/;
const MAPPED = 0xffffn;

type Projected = NetworkFacts | 'removed';

/* Reads one record; anything not shaped as FoxTrust documents makes the address unknown, never an error. */
export function project(record: MmdbValue): Projected {
	if (typeof record !== 'object' || Array.isArray(record)) return UNKNOWN;
	if (record.removed === true) return 'removed';
	const categories: NetworkCategory[] = [];
	const raw = record.categories;
	if (raw !== undefined) {
		if (!Array.isArray(raw)) return UNKNOWN;
		for (const value of raw) {
			if (typeof value !== 'string') return UNKNOWN;
			const mapped = FOXTRUST_CATEGORY_MAP[value];
			if (mapped && !categories.includes(mapped)) categories.push(mapped);
		}
	}
	let country: string | null = null;
	const place = record.country;
	if (place !== undefined) {
		if (typeof place !== 'object' || Array.isArray(place)) return UNKNOWN;
		const code = place.iso_code;
		if (code !== undefined) {
			if (typeof code !== 'string' || !COUNTRY.test(code)) return UNKNOWN;
			country = code;
		}
	}
	if (categories.length === 0 && country === null) return NOTHING;
	return Object.freeze({
		known: true,
		categories: Object.freeze(categories),
		country
	});
}

/* An IPv4-mapped IPv6 address is that IPv4 address: the tree holds IPv4 once, at ::/96. */
export function lookupForm(address: Address): Address {
	if (address.version === 6 && address.value >> 32n === MAPPED) {
		return { version: 4, value: address.value & 0xffffffffn };
	}
	return address;
}

export function makePair(options: {
	full: MmdbReader;
	delta: MmdbReader | null;
	fullVersion: string;
	deltaVersion: string | null;
	builtAt: string;
	onUnreadable: () => void;
}): LoadedPair {
	const { full, delta, onUnreadable } = options;
	/* Projections by file and data offset; FoxTrust's full file held 16,193 distinct records on 2026-11-11. */
	const cache = new Map<string, Projected>();

	const projected = (
		reader: MmdbReader,
		tag: 'f' | 'd',
		offset: number
	): Projected => {
		const key = `${tag}${String(offset)}`;
		const known = cache.get(key);
		if (known !== undefined) return known;
		const record = reader.decodeAt(offset);
		const out = record === UNREADABLE ? UNKNOWN : project(record);
		if (cache.size >= NETWORK_FACTS_CACHE_ENTRIES) cache.clear();
		cache.set(key, out);
		return out;
	};

	const unknown = (): NetworkFacts => {
		onUnreadable();
		return UNKNOWN;
	};

	return Object.freeze({
		full,
		delta,
		fullVersion: options.fullVersion,
		deltaVersion: options.deltaVersion,
		builtAt: options.builtAt,
		ranges: full.leaves,
		factsOf(raw: Address): NetworkFacts {
			const address = lookupForm(raw);
			if (delta) {
				const at = delta.lookup(address);
				if (at === UNREADABLE) return unknown();
				if (at !== null) {
					const out = projected(delta, 'd', at);
					if (out === 'removed') return NOTHING;
					if (!out.known) return unknown();
					return out;
				}
			}
			const at = full.lookup(address);
			if (at === UNREADABLE) return unknown();
			if (at === null) return NOTHING;
			const out = projected(full, 'f', at);
			/* A tombstone belongs only in an update; in a full file it is a record this release cannot read. */
			if (out === 'removed' || !out.known) return unknown();
			return out;
		}
	});
}
