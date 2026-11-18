import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { shaped } from '../shape.ts';
import {
	PASSWORD,
	PersonBrowser,
	WRONG,
	from,
	typePassword
} from '../person_activity/helpers.ts';
import { CONSOLE, OwnView, administrator, ownSignIns } from './helpers.ts';
import { adminAuditStore, getPersonActivityStore } from 'lib/adapters/index.ts';
import type { PersonActivityRow } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

async function listOf(cookie: string): Promise<OwnView> {
	const reply = await ownSignIns(cookie);
	expect(reply.status).toBe(200);
	return shaped(OwnView, reply.body);
}

/**
 * @proves An administrator reads their own last ten sign-ins, refused ones included, newest first, with where, how,
 * which browser and which country; reading them leaves nothing in the audit trail; and the list says when this server
 * keeps no sign-ins or has none since it began.
 */
describe("an administrator's own sign-ins", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		from('203.0.113.9');
	});

	afterEach(() => {
		ApplicationConfig['personActivity.enabled'] = true;
	});

	it('lists their last ten sign-ins and refusals, newest first', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);
		for (let i = 0; i < 11; i += 1) {
			await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		}

		const view = await listOf(max.cookie);
		if (view.state !== 'list')
			throw new Error(`expected a list, got ${view.state}`);
		expect(view.rows).toHaveLength(10);
		expect(view.rows[0]).toEqual({
			at: view.rows[0].at,
			outcome: 'let_in',
			place: 'Console',
			method: 'Password',
			reason: null,
			device: 'Chrome on Windows',
			country: null
		});
		const times = view.rows.map((row) => row.at);
		expect([...times].sort().reverse()).toEqual(times);
	});

	it('lists a refused sign-in with its reason', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);

		const view = await listOf(max.cookie);
		if (view.state !== 'list')
			throw new Error(`expected a list, got ${view.state}`);
		expect(view.rows.map((row) => [row.outcome, row.reason])).toEqual([
			['refused', 'Wrong password']
		]);
	});

	it('leaves nothing in the audit trail', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		await listOf(max.cookie);

		const { entries } = await adminAuditStore.list({ actor: max.user._id });
		expect(entries).toEqual([]);
	});

	it('says this server keeps no sign-ins when recording is off', async () => {
		ApplicationConfig['personActivity.enabled'] = false;
		const max = await administrator();

		expect(await listOf(max.cookie)).toEqual({ state: 'off' });
	});

	it('says since when there are none', async () => {
		const max = await administrator();

		const view = await listOf(max.cookie);
		expect(view.state).toBe('empty');
	});
});

const ADDRESSES = ['203.0.113.77', '2001:db8:85a3::8a2e:370:7334'];

function seeded(accountId: string, n: number): PersonActivityRow {
	const at = new Date(Date.now() - n * 60_000);
	return {
		_id: `seed-${accountId}-${String(n)}`,
		bucketId: ADMIN_BUCKET_ID,
		accountId,
		day: at.toISOString().slice(0, 10),
		kind: 'signIn',
		outcome: n % 2 === 0 ? 'let_in' : 'refused',
		reason: n % 2 === 0 ? 'signed_in' : 'wrong_code',
		place: { clientId: CONSOLE },
		method: 'password',
		address: ADDRESSES[n % ADDRESSES.length],
		addressFrom: 'sign_in',
		facts: { country: 'NL', categories: ['tor', 'vpn', 'hosting'] },
		lookup: {
			asn: 64500,
			asName: 'Example Net',
			regionCode: 'BY',
			region: 'Bavaria',
			city: 'Munich'
		},
		device: { browser: 'firefox', system: 'linux' },
		count: 1,
		firstAt: at,
		lastAt: at,
		expiresAt: new Date(at.getTime() + 90 * 86_400_000)
	};
}

/**
 * @proves An administrator's own list never carries a network address, in any form, nor its network categories,
 * owner or location, whatever the rows hold: a thief signed in as the administrator learns nothing of where the real
 * one signs in from.
 */
describe("what an administrator's own list never shows", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('has no address, category, owner or location', async () => {
		const max = await administrator();
		await getPersonActivityStore().write(
			Array.from({ length: 6 }, (_, n) => seeded(max.user._id, n))
		);

		const reply = await ownSignIns(max.cookie);
		const body = JSON.stringify(reply.body);
		expect(reply.status).toBe(200);
		for (const never of [
			...ADDRESSES,
			'2001:db8',
			'203.0.113',
			'tor',
			'vpn',
			'hosting',
			'64500',
			'Example Net',
			'Bavaria',
			'Munich'
		]) {
			/* As a word: "tor" is inside "authenticator", which a refused code's reason rightly says. */
			const word = new RegExp(
				`(^|[^a-z0-9])${never.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^a-z0-9])`,
				'i'
			);
			expect(word.test(body)).toBe(false);
		}
	});
});
