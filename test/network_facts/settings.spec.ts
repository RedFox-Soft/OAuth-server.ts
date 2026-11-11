import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { ApplicationConfig, settingsApplied } from 'lib/configs/application.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { networkFactsTick } from 'lib/network_facts/scheduler.ts';
import { agent, call, cookieOf, rpc, tool } from './agents.ts';
import {
	BASE,
	clockAt,
	fullVersion,
	loadStandard,
	publication,
	resetNetworkFacts,
	signer,
	iso,
	STANDARD
} from './publication.ts';

let undoClock: () => void = () => {};

/**
 * @proves A super administrator turns network facts on and off and reads what the process holds; turning them off
 * drops the data and turning them on looks for a snapshot within a minute; no other administrator reads the state,
 * and an agent reads it through the console's own route.
 */
describe("network facts' switch and state", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	beforeEach(() => {
		resetNetworkFacts();
		undoClock = clockAt(0.2);
		ApplicationConfig['mcp.enabled'] = true;
	});

	afterEach(() => {
		undoClock();
		ApplicationConfig['networkFacts.enabled'] = true;
	});

	it('shows a super administrator the snapshot held', async () => {
		const foxtrust = await signer();
		await loadStandard(publication(), foxtrust);

		const answer = await call(
			'GET',
			'/admin/api/settings/network-facts',
			await cookieOf('super')
		);

		expect(answer.status).toBe(200);
		expect(await answer.json()).toMatchObject({
			enabled: true,
			state: 'current',
			held: { fullVersion: fullVersion(), builtAt: iso(0) },
			scope: 'process'
		});
	});

	it('refuses the state to an administrator who is not a super administrator', async () => {
		const answer = await call(
			'GET',
			'/admin/api/settings/network-facts',
			await cookieOf('plain')
		);

		expect(answer.status).toBe(403);
	});

	it('drops the data held when a super administrator turns the download off', async () => {
		const foxtrust = await signer();
		await loadStandard(publication(), foxtrust);
		const cookie = await cookieOf('super');

		const saved = await call('PUT', '/admin/api/settings', cookie, {
			'networkFacts.enabled': false
		});
		const answer = await call(
			'GET',
			'/admin/api/settings/network-facts',
			cookie
		);
		await call('PUT', '/admin/api/settings', cookie, {
			'networkFacts.enabled': true
		});

		expect(saved.status).toBe(200);
		expect(await answer.json()).toMatchObject({
			enabled: false,
			state: 'off',
			held: null
		});
	});

	it('looks for a snapshot within a minute of the download being turned on', async () => {
		const foxtrust = await signer();
		const published = publication();
		await published.publish({
			by: foxtrust,
			full: { version: fullVersion(), builtAt: iso(0), entries: STANDARD }
		});
		await networkFactsTick(0, { base: BASE, keys: foxtrust.keys });
		const before = published.requests.length;

		settingsApplied(['networkFacts.enabled']);
		await networkFactsTick(0, { base: BASE, keys: foxtrust.keys });

		expect(published.requests.length).toBeGreaterThan(before);
	});

	it('lets an agent read the state', async () => {
		const foxtrust = await signer();
		await loadStandard(publication(), foxtrust);

		const { payload } = await rpc(
			tool('network_facts_status_get', {}),
			await agent()
		);

		expect(payload.result?.isError).not.toBe(true);
		expect(payload.result?.structuredContent?.result).toMatchObject({
			state: 'current',
			held: { fullVersion: fullVersion() }
		});
	});
});
