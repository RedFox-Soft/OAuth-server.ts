import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { present } from '../shape.ts';
import { parseAddress } from 'lib/behind_proxy/net.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { factsAt } from 'lib/network_facts/state.ts';
import { packageVersion } from 'lib/helpers/package_version.ts';
import {
	at,
	clockAt,
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

/**
 * @proves Downloading network facts sends FoxTrust nothing about the people whose addresses this server looks up, and
 * nothing about the server but, while usage reports are on, its version.
 */
describe('What the download of network facts sends', () => {
	let foxtrust: Signer;
	let published: Publication;
	let undoClock: () => void;

	beforeEach(async () => {
		resetNetworkFacts();
		foxtrust = await signer('foxtrust');
		published = publication();
		undoClock = clockAt(0.2);
	});

	afterEach(() => {
		undoClock();
		ApplicationConfig['telemetry.enabled'] = false;
	});

	it('carries no address the server looked up', async () => {
		await loadStandard(published, foxtrust);
		const looked = ['45.10.20.30', '203.0.113.77', '2001:db8:dead:beef::1'];
		for (const address of looked) {
			factsAt(present(parseAddress(address), 'an address'), at(0.2).getTime());
		}
		await published.publish({
			by: foxtrust,
			full: { version: fullVersion(1), builtAt: iso(24), entries: STANDARD }
		});
		undoClock();
		undoClock = clockAt(24.2);
		expect(await pass(foxtrust)).toBe('accepted');
		for (const request of published.requests) {
			const sent = [
				request.url,
				request.body ?? '',
				...[...request.headers.entries()].map(([k, v]) => `${k}: ${v}`)
			].join('\n');
			for (const address of looked) expect(sent).not.toContain(address);
			expect(request.headers.get('cookie')).toBeNull();
			expect(request.headers.get('authorization')).toBeNull();
		}
	});

	it('names only FoxAuth while usage reports are off', async () => {
		await loadStandard(published, foxtrust);
		for (const request of published.requests) {
			expect(request.headers.get('user-agent')).toBe('FoxAuth');
		}
	});

	it('adds the version while usage reports are on', async () => {
		ApplicationConfig['telemetry.enabled'] = true;
		await loadStandard(published, foxtrust);
		expect(
			present(published.requests[0], 'a request').headers.get('user-agent')
		).toBe(`FoxAuth/${packageVersion() ?? ''}`);
	});
});
