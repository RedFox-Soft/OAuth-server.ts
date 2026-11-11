import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { present } from '../shape.ts';
import { getTelemetryStateStore } from 'lib/adapters/index.ts';
import { parseAddress } from 'lib/behind_proxy/net.ts';
import { NETWORK_FACTS_FULL_MAX_BYTES } from 'lib/consts/network_facts.ts';
import {
	factsAt,
	networkFactsStatus,
	resetNetworkFactsForTests
} from 'lib/network_facts/state.ts';
import {
	resetNetworkFactsFetchForTests,
	type PassOutcome
} from 'lib/network_facts/fetch.ts';
import {
	ADDRESSES,
	at,
	clockAt,
	deltaVersion,
	fullVersion,
	iso,
	loadStandard,
	pass,
	publication,
	resetNetworkFacts,
	signer,
	STANDARD,
	type Publication,
	type Signer
} from './publication.ts';

await bootstrap(import.meta.url);

function factsOf(address: string, hours: number) {
	return factsAt(
		present(parseAddress(address), 'an address'),
		at(hours).getTime()
	);
}

/**
 * @proves A snapshot is used only when it verifies with a pinned key, matches the manifest, is FoxTrust's kind of file
 * and is not older than what was accepted before (also after a restart); anything else leaves the data in use as it
 * was, and the status says what is held.
 */
describe("FoxTrust's network facts, as a server process takes them", () => {
	let foxtrust: Signer;
	let stranger: Signer;
	let published: Publication;
	let undoClock: () => void;

	beforeEach(async () => {
		resetNetworkFacts();
		foxtrust = await signer('foxtrust');
		stranger = await signer('stranger');
		published = publication();
		undoClock = clockAt(0.2);
	});

	afterEach(() => {
		undoClock();
	});

	it('loads a signed snapshot and shows its version, build time, age and ranges', async () => {
		expect(await loadStandard(published, foxtrust)).toBe('accepted');
		const status = networkFactsStatus(at(0.2).getTime());
		expect(status.state).toBe('current');
		expect(status.held).toMatchObject({
			fullVersion: fullVersion(),
			deltaVersion: null,
			builtAt: iso(0),
			ageSeconds: 720
		});
		expect(status.held?.ranges).toBeGreaterThan(0);
		expect(factsOf(ADDRESSES.tor, 0.2)).toMatchObject({ categories: ['tor'] });
	});

	it('uses a new hourly update after the next look', async () => {
		await loadStandard(published, foxtrust);
		await published.publish({
			by: foxtrust,
			full: { version: fullVersion(), builtAt: iso(0), entries: STANDARD },
			delta: {
				version: deltaVersion(3),
				builtAt: iso(3),
				entries: [
					{
						cidr: '91.20.0.0/16',
						value: { categories: ['vpn'], country: { iso_code: 'DE' } }
					}
				]
			}
		});
		undoClock();
		undoClock = clockAt(3.1);
		expect(await pass(foxtrust)).toBe('accepted');
		expect(factsOf(ADDRESSES.homeDe, 3.1)).toMatchObject({
			categories: ['vpn']
		});
		expect(networkFactsStatus(at(3.1).getTime()).held?.deltaVersion).toBe(
			deltaVersion(3)
		);
	});

	it('drops an update made against another full file', async () => {
		await loadStandard(published, foxtrust);
		await published.publish({
			by: foxtrust,
			full: { version: fullVersion(), builtAt: iso(0), entries: STANDARD },
			delta: {
				version: deltaVersion(3),
				builtAt: iso(3),
				base: 'f20200101',
				entries: [{ cidr: '91.20.0.0/16', value: { categories: ['vpn'] } }]
			}
		});
		undoClock();
		undoClock = clockAt(3.1);
		expect(await pass(foxtrust)).toBe('base');
		expect(factsOf(ADDRESSES.homeDe, 3.1)).toMatchObject({ categories: [] });
	});

	it('costs one conditional request when nothing changed', async () => {
		await loadStandard(published, foxtrust);
		const before = published.requests.length;
		expect(await pass(foxtrust)).toBe('unchanged');
		const after = published.requests.slice(before);
		expect(after.map((r) => r.url)).toEqual([
			'https://publication.test/v1/manifest.json'
		]);
		expect(after[0].headers.get('if-none-match')).not.toBeNull();
	});

	describe('keeps the data in use when', () => {
		beforeEach(async () => {
			await loadStandard(published, foxtrust);
		});

		const replaced = async (
			outcome: PassOutcome,
			change: Parameters<Publication['publish']>[0]
		) => {
			await published.publish(change);
			undoClock();
			undoClock = clockAt(24.5);
			expect(await pass(foxtrust)).toBe(outcome);
			expect(factsOf(ADDRESSES.tor, 24.5)).toMatchObject({
				categories: ['tor']
			});
			expect(networkFactsStatus(at(24.5).getTime()).held?.fullVersion).toBe(
				fullVersion()
			);
		};
		const next = { version: fullVersion(1), builtAt: iso(24), entries: [] };

		it('a file is larger than the manifest says', () =>
			replaced('size', { by: foxtrust, full: { ...next, manifestSize: 12 } }));

		it('a file does not match the digest in the manifest', () =>
			replaced('digest', {
				by: foxtrust,
				full: { ...next, manifestSha256: '0'.repeat(64) }
			}));

		it('a file is signed by a key this release does not pin', () =>
			replaced('signature', {
				by: foxtrust,
				full: { ...next, signedBy: stranger }
			}));

		it('the manifest is signed by a key this release does not pin', () =>
			replaced('signature', { by: stranger, full: next }));

		it("a file is not FoxTrust's kind of database", () =>
			replaced('format', {
				by: foxtrust,
				full: { ...next, options: { databaseType: 'GeoLite2-City' } }
			}));

		it('a file is larger than this release reads', () =>
			replaced('size', {
				by: foxtrust,
				full: { ...next, manifestSize: NETWORK_FACTS_FULL_MAX_BYTES + 1 }
			}));

		it('a snapshot was built before the one in use', () =>
			replaced('older', {
				by: foxtrust,
				full: { version: fullVersion(1), builtAt: iso(-1), entries: [] }
			}));
	});

	it('refuses after a restart a snapshot built before one this instance accepted', async () => {
		await loadStandard(published, foxtrust, 0);
		resetNetworkFactsForTests();
		resetNetworkFactsFetchForTests();
		expect((await getTelemetryStateStore().read())?.networkFactsBuiltAt).toBe(
			iso(0)
		);
		await published.publish({
			by: foxtrust,
			full: { version: fullVersion(-1), builtAt: iso(-24), entries: STANDARD }
		});
		expect(await pass(foxtrust)).toBe('older');
		expect(networkFactsStatus(at(0.2).getTime()).state).toBe('not-yet');
	});
});
