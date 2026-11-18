import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { person, project } from '../person_activity/helpers.ts';
import {
	HOME,
	HOSTING,
	newSignInMailsTo,
	ready,
	signInFrom
} from './helpers.ts';
import { getBucketStore, getPersonActivityStore } from 'lib/adapters/index.ts';
import type { PersonActivityRow } from 'lib/adapters/types.ts';
import { alertsFor } from 'lib/sign_in_alerts/alerts.ts';

let bucketId: string;
let anna: { email: string; accountId: string };
let n = 0;

function signIn(minutes: number, asn: number): PersonActivityRow {
	const at = new Date(Date.now() - 60 * 60_000 + minutes * 60_000);
	n += 1;
	return {
		_id: `limit-${String(n)}`,
		bucketId,
		accountId: anna.accountId,
		day: at.toISOString().slice(0, 10),
		kind: 'signIn',
		outcome: 'let_in',
		reason: 'signed_in',
		place: { clientId: 'activity-app' },
		method: 'password',
		address: '203.0.113.7',
		addressFrom: 'sign_in',
		lookup: { asn },
		device: { browser: 'chrome', system: 'windows' },
		count: 1,
		firstAt: at,
		lastAt: at,
		expiresAt: new Date(at.getTime() + 90 * 86_400_000)
	};
}

/**
 * @proves No account is emailed twice about the same network and browser in a day, nor more than five times a day,
 * and two processes deciding about the same sign-ins email once between them.
 */
describe('how many emails a new sign-in sends', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ready();
		bucketId = await project();
		await getBucketStore().update(bucketId, { newSignInAlerts: true });
		anna = await person(bucketId);
	});

	it('sends one email for two sign-ins from the same new place in a day', async () => {
		await signInFrom(anna.email, 'activity-app', HOME);
		await signInFrom(anna.email, 'activity-app', HOSTING);
		await signInFrom(anna.email, 'activity-app', HOSTING);

		expect(newSignInMailsTo(anna.email)).toHaveLength(1);
	});

	it('sends at most five a day, and marks no sign-in beyond them', async () => {
		await getPersonActivityStore().write([signIn(0, 64500)]);
		const decided: PersonActivityRow[] = [];
		for (let i = 1; i <= 6; i += 1) {
			const row = signIn(i, 64500 + i);
			await alertsFor([row]);
			await getPersonActivityStore().write([row]);
			decided.push(row);
		}

		expect(decided.map((row) => row.alerted ?? null)).toEqual([
			'network',
			'network',
			'network',
			'network',
			'network',
			null
		]);
	});

	it('sends one email when two processes decide about the same sign-in', async () => {
		await getPersonActivityStore().write([signIn(0, 64500)]);
		const row = signIn(5, 64501);

		const first = await alertsFor([structuredClone(row)]);
		const second = await alertsFor([structuredClone(row)]);
		expect([first.length, second.length]).toEqual([1, 0]);
	});
});
