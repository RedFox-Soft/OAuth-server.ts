import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { ApplicationConfig, settingsApplied } from 'lib/configs/application.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { attackerListTick } from 'lib/attacker_list/scheduler.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import {
	clockAt,
	iso,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer
} from './helper.ts';

async function cookieOf(kind: AdminKind): Promise<string> {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

function call(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
): Promise<Response> {
	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
}

let undoClock: () => void = () => {};

/**
 * @proves A super administrator turns FoxTrust's attacker list on only while attack reporting is on, sees its state
 * without any address, and the server checks for a list within a minute of it being turned on; no other
 * administrator reads that state.
 */
describe("the attacker list's switch and state", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	beforeEach(() => {
		resetAttackerList();
		undoClock = clockAt(0.1);
	});

	afterEach(() => {
		undoClock();
		ApplicationConfig['attackReports.enabled'] = true;
		ApplicationConfig['attackerList.enabled'] = true;
	});

	it('refuses turning attack reporting off while the list stays on', async () => {
		const saved = await call(
			'PUT',
			'/admin/api/settings',
			await cookieOf('super'),
			{ 'attackReports.enabled': false }
		);

		expect(saved.status).toBe(422);
	});

	it('refuses turning the list on while attack reporting is off', async () => {
		const cookie = await cookieOf('super');
		await call('PUT', '/admin/api/settings', cookie, {
			'attackReports.enabled': false,
			'attackerList.enabled': false
		});

		try {
			const saved = await call('PUT', '/admin/api/settings', cookie, {
				'attackerList.enabled': true
			});

			expect(saved.status).toBe(422);
		} finally {
			// The stored settings outlive the case; the next one starts from both switches on, as configured.
			await call('PUT', '/admin/api/settings', cookie, {
				'attackReports.enabled': true
			});
			await call('PUT', '/admin/api/settings', cookie, {
				'attackerList.enabled': true
			});
		}
	});

	it('shows the list held without any address in it', async () => {
		const foxtrust = await signer();
		const published = publication();
		const address = listedAddress();
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: address, lastSeen: seconds(-1) }],
			by: foxtrust
		});
		await pass(foxtrust);

		const answer = await call(
			'GET',
			'/admin/api/settings/attacker-list',
			await cookieOf('super')
		);
		const text = await answer.text();

		expect({
			status: answer.status,
			mentionsAddress: text.includes(address)
		}).toEqual({
			status: 200,
			mentionsAddress: false
		});
		expect(JSON.parse(text)).toMatchObject({
			state: 'current',
			held: { version: 'a1', entries: 1 },
			scope: 'process'
		});
	});

	it('refuses the state to an administrator who is not a super administrator', async () => {
		const answer = await call(
			'GET',
			'/admin/api/settings/attacker-list',
			await cookieOf('plain')
		);

		expect(answer.status).toBe(403);
	});

	it('checks for a list within a minute of the list being turned on', async () => {
		const foxtrust = await signer();
		const published = publication();
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: foxtrust
		});
		// A check already ran, so the next one is due only at the coming :55.
		await attackerListTick();
		const before = published.requests.length;

		settingsApplied(['attackerList.enabled']);
		await attackerListTick();

		expect(published.requests.length).toBeGreaterThan(before);
	});
});
