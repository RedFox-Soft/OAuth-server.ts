import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import { openMmdb, UNREADABLE } from 'lib/network_facts/mmdb.ts';
import { makePair } from 'lib/network_facts/facts.ts';
import { parseAddress } from 'lib/behind_proxy/net.ts';
import { broken, writeMmdb, type Entry } from './mmdb_writer.ts';
import { present } from '../shape.ts';

const addr = (text: string) =>
	present(parseAddress(text), `the address ${text}`);
const opened = (bytes: Uint8Array) =>
	present(openMmdb(bytes), 'a file the reader opens');

/**
 * @proves The snapshot reader finds, for every address, the record a plain range table finds, in every record size
 * and for IPv4, IPv6 and IPv4-mapped addresses; and a damaged file makes an address unknown, never an error.
 */

const V4 = (n: number) =>
	`${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;

/* Disjoint IPv4 blocks: /24s at distinct indexes, each with its own country. */
const blocks = fc.uniqueArray(fc.integer({ min: 1, max: 4000 }), {
	minLength: 1,
	maxLength: 40
});

function entriesOf(indexes: readonly number[]): Entry[] {
	return indexes.map((i) => ({
		cidr: `${V4((10 << 24) + i * 256)}/24`,
		value: {
			categories: i % 3 === 0 ? ['tor'] : i % 3 === 1 ? ['cloud'] : [],
			country: { iso_code: i % 2 === 0 ? 'DE' : 'FR' }
		}
	}));
}

function pairOf(entries: readonly Entry[], recordSize: 24 | 28 | 32) {
	const full = openMmdb(writeMmdb(entries, { recordSize }));
	if (!full) throw new Error('the test writer wrote an unreadable file');
	return makePair({
		full,
		delta: null,
		fullVersion: 'f20261111',
		deltaVersion: null,
		builtAt: '2026-11-11T04:50:00.000Z',
		onUnreadable: () => {}
	});
}

describe('Reading FoxTrust snapshot files', () => {
	for (const recordSize of [24, 28, 32] as const) {
		it(`for every generated set of blocks and address, finds what a range table finds (record size ${String(recordSize)})`, () => {
			fc.assert(
				fc.property(
					blocks,
					fc.integer({ min: 0, max: 4200 }),
					fc.integer({ min: 0, max: 255 }),
					fc.boolean(),
					(indexes, block, host, mapped) => {
						const pair = pairOf(entriesOf(indexes), recordSize);
						const text = V4((10 << 24) + block * 256 + host);
						const address = parseAddress(mapped ? `::ffff:${text}` : text);
						if (!address) return false;
						const facts = pair.factsOf(address);
						if (!indexes.includes(block)) {
							return (
								facts.known &&
								facts.categories.length === 0 &&
								facts.country === null
							);
						}
						const expected = {
							categories:
								block % 3 === 0 ? ['tor'] : block % 3 === 1 ? ['hosting'] : [],
							country: block % 2 === 0 ? 'DE' : 'FR'
						};
						return (
							facts.known &&
							JSON.stringify(facts.categories) ===
								JSON.stringify(expected.categories) &&
							facts.country === expected.country
						);
					}
				),
				{ numRuns: 60 }
			);
		});
	}

	it('finds an IPv6 network and nothing beside it', () => {
		const pair = pairOf(
			[{ cidr: '2a05:d000::/32', value: { categories: ['cloud'] } }],
			24
		);
		expect(pair.factsOf(addr('2a05:d000:1::7'))).toEqual({
			known: true,
			categories: ['hosting'],
			country: null
		});
		expect(pair.factsOf(addr('2a05:d001::1'))).toEqual({
			known: true,
			categories: [],
			country: null
		});
	});

	it('ignores categories no condition names', () => {
		const pair = pairOf(
			[
				{
					cidr: '172.224.0.0/16',
					value: {
						categories: ['private_relay', 'search_crawler'],
						country: { iso_code: 'GB' }
					}
				}
			],
			24
		);
		expect(pair.factsOf(addr('172.224.3.4'))).toEqual({
			known: true,
			categories: [],
			country: 'GB'
		});
	});

	it('makes an address unknown when its record is not shaped as FoxTrust documents', () => {
		let counted = 0;
		const full = opened(
			writeMmdb([
				{ cidr: '10.0.0.0/24', value: { categories: 'tor' } },
				{ cidr: '10.0.1.0/24', value: { country: { iso_code: 'germany' } } }
			])
		);
		const pair = makePair({
			full,
			delta: null,
			fullVersion: 'f20261111',
			deltaVersion: null,
			builtAt: '2026-11-11T04:50:00.000Z',
			onUnreadable: () => {
				counted += 1;
			}
		});
		expect(pair.factsOf(addr('10.0.0.1'))).toEqual({ known: false });
		expect(pair.factsOf(addr('10.0.1.1'))).toEqual({ known: false });
		expect(counted).toBe(2);
	});

	it('makes an address unknown, never an error, when its record is of a type these files never hold', () => {
		const bytes = broken(
			writeMmdb([{ cidr: '10.0.0.0/24', value: { categories: ['tor'] } }]),
			'record'
		);
		const full = opened(bytes);
		const at = full.lookup(addr('10.0.0.1'));
		expect(typeof at).toBe('number');
		expect(full.decodeAt(at as number)).toBe(UNREADABLE);
	});

	it('refuses to open a file cut short', () => {
		const bytes = broken(
			writeMmdb([{ cidr: '10.0.0.0/24', value: { categories: ['tor'] } }]),
			'truncate'
		);
		const full = openMmdb(bytes);
		const lookedUp = full?.lookup(addr('10.0.0.1'));
		const decoded =
			full && typeof lookedUp === 'number'
				? full.decodeAt(lookedUp)
				: UNREADABLE;
		expect(
			full === null || lookedUp === UNREADABLE || decoded === UNREADABLE
		).toBe(true);
	});

	it('hides a record of the full file behind a removal in the update', () => {
		const full = opened(
			writeMmdb([{ cidr: '10.0.0.0/24', value: { categories: ['tor'] } }])
		);
		const delta = opened(
			writeMmdb([
				{ cidr: '10.0.0.0/25', value: { removed: true } },
				{ cidr: '10.0.2.0/24', value: { categories: ['vpn'] } }
			])
		);
		const pair = makePair({
			full,
			delta,
			fullVersion: 'f20261111',
			deltaVersion: 'd20261111T07',
			builtAt: '2026-11-11T07:50:00.000Z',
			onUnreadable: () => {}
		});
		expect(pair.factsOf(addr('10.0.0.1'))).toEqual({
			known: true,
			categories: [],
			country: null
		});
		expect(pair.factsOf(addr('10.0.0.200')).known).toBe(true);
		expect(pair.factsOf(addr('10.0.0.200'))).toMatchObject({
			categories: ['tor']
		});
		expect(pair.factsOf(addr('10.0.2.9'))).toMatchObject({
			categories: ['vpn']
		});
	});
});
