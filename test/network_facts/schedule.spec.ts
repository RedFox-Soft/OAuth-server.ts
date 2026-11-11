import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { present } from '../shape.ts';
import { parseAddress } from 'lib/behind_proxy/net.ts';
import { NETWORK_FACTS_MAX_OFFSET_MS } from 'lib/consts/network_facts.ts';
import { networkFactsTick } from 'lib/network_facts/scheduler.ts';
import { factsAt } from 'lib/network_facts/state.ts';
import { setClockForTests } from 'lib/telemetry/clock.ts';
import { networkFactsPass } from 'lib/network_facts/fetch.ts';
import {
	ADDRESSES,
	BASE,
	at,
	deltaVersion,
	fullVersion,
	iso,
	publication,
	resetNetworkFacts,
	signer,
	STANDARD,
	type Publication,
	type Signer
} from './publication.ts';

await bootstrap(import.meta.url);

const MINUTE = 60 * 1000;

/**
 * @proves A new hourly update FoxTrust publishes is in use within 10 minutes, however the process's own offset falls.
 */
describe('How soon a new update of network facts is used', () => {
	let foxtrust: Signer;
	let published: Publication;
	let nowMs = 0;
	let undoClock: () => void;

	beforeEach(async () => {
		resetNetworkFacts();
		foxtrust = await signer('foxtrust');
		published = publication();
		nowMs = at(0).getTime();
		undoClock = setClockForTests(() => new Date(nowMs));
		await published.publish({
			by: foxtrust,
			full: { version: fullVersion(), builtAt: iso(0), entries: STANDARD }
		});
		await networkFactsPass({ base: BASE, keys: foxtrust.keys });
	});

	afterEach(() => {
		undoClock();
	});

	it('uses an update published right after a look within 10 minutes, at the largest offset', async () => {
		/* The tick under test is the server's own; point its pass at the stand-in through the keys it trusts. */
		const tick = () =>
			networkFactsTick(NETWORK_FACTS_MAX_OFFSET_MS, {
				base: BASE,
				keys: foxtrust.keys
			});
		await tick();
		const publishedAt = nowMs + 1000;
		await published.publish({
			by: foxtrust,
			full: { version: fullVersion(), builtAt: iso(0), entries: STANDARD },
			delta: {
				version: deltaVersion(1),
				builtAt: new Date(publishedAt).toISOString(),
				entries: [{ cidr: '91.20.0.0/16', value: { categories: ['vpn'] } }]
			}
		});
		let usedAt: number | null = null;
		/* The process looks every 30 seconds whether a look is due, as startNetworkFacts does. */
		for (let t = publishedAt; t <= publishedAt + 15 * MINUTE; t += 30 * 1000) {
			nowMs = t;
			await tick();
			const facts = factsAt(
				present(parseAddress(ADDRESSES.homeDe), 'an address'),
				nowMs
			);
			if (facts.known && facts.categories.includes('vpn')) {
				usedAt = t;
				break;
			}
		}
		expect(usedAt).not.toBeNull();
		expect(
			present(usedAt, 'the moment the update was used') - publishedAt
		).toBeLessThanOrEqual(10 * MINUTE);
	});

	it('never starts a look while the one before it is still running', async () => {
		const before = published.requests.length;
		await Promise.all([
			networkFactsTick(0, { base: BASE, keys: foxtrust.keys }),
			networkFactsTick(0, { base: BASE, keys: foxtrust.keys })
		]);
		const manifests = published.requests
			.slice(before)
			.filter((r) => r.url.endsWith('/v1/manifest.json'));
		expect(manifests.length).toBe(1);
	});
});
