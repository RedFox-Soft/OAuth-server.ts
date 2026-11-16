import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import { getActivityStore } from 'lib/adapters/index.ts';
import { dayOf } from 'lib/activity/periods.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import {
	PersonBrowser,
	WRONG,
	from,
	person,
	project,
	signIn,
	typePassword
} from './helpers.ts';

let cookie: string;
let bucketId: string;

const Summary = Type.Object({
	activity: Type.Object({
		recordingBegan: Type.Union([Type.String(), Type.Null()]),
		keptDays: Type.Number(),
		lastSignIn: Type.Union([
			Type.Null(),
			Type.Object({
				at: Type.String(),
				clientId: Type.Union([Type.String(), Type.Null()]),
				name: Type.Union([Type.String(), Type.Null()]),
				method: Type.Union([Type.String(), Type.Null()])
			})
		]),
		notLetInSince: Type.Union([
			Type.Null(),
			Type.Object({
				at: Type.String(),
				count: Type.Number(),
				reason: Type.String(),
				kind: Type.String()
			})
		]),
		lastActive: Type.Union([
			Type.Null(),
			Type.Object({ day: Type.String() }),
			Type.Object({ month: Type.String() })
		])
	})
});

async function summaryOf(accountId: string) {
	await flushPersonActivityNow();
	const reply = await admin(
		'GET',
		`/admin/api/projects/${bucketId}/users/${accountId}`,
		cookie
	);
	expect(reply.status).toBe(200);
	return shaped(Summary, reply.body).activity;
}

/**
 * @proves The person's page tells an administrator when they last signed in and how, whether a sign-in or a check
 * turned them away after that, and the last day they were active — token renewals counting — without opening the
 * timeline, and says "nothing yet" rather than "never" when nothing was recorded.
 */
describe("a person's activity summary", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		bucketId = await project();
		from('203.0.113.9');
	});

	it('shows the last sign-in with its application and method', async () => {
		const anna = await person(bucketId);
		await signIn(anna.email);

		const summary = await summaryOf(anna.accountId);
		expect([summary.lastSignIn?.name, summary.lastSignIn?.method]).toEqual([
			'Acme web',
			'Password'
		]);
	});

	it('shows refusals after the last sign-in as not let in since', async () => {
		const anna = await person(bucketId);
		await signIn(anna.email);
		await typePassword(new PersonBrowser(), anna.email, WRONG);
		await typePassword(new PersonBrowser(), anna.email, WRONG);

		const summary = await summaryOf(anna.accountId);
		expect([
			summary.notLetInSince?.count,
			summary.notLetInSince?.reason
		]).toEqual([2, 'Wrong password']);
	});

	it('shows nothing not let in when the refusal came before the last sign-in', async () => {
		const anna = await person(bucketId);
		await typePassword(new PersonBrowser(), anna.email, WRONG);
		await new Promise((resolve) => setTimeout(resolve, 5));
		await signIn(anna.email);

		expect((await summaryOf(anna.accountId)).notLetInSince).toBeNull();
	});

	it('shows a recent last active day for a person whose apps only renew tokens', async () => {
		const anna = await person(bucketId);
		await getActivityStore().mark({
			bucketId,
			accountId: anna.accountId,
			kind: 'renewal',
			provisioned: false,
			at: new Date()
		});

		expect((await summaryOf(anna.accountId)).lastActive).toEqual({
			day: dayOf(new Date())
		});
	});

	it('shows no sign-in and no activity for a person with nothing recorded', async () => {
		const anna = await person(bucketId);

		const summary = await summaryOf(anna.accountId);
		expect([
			summary.lastSignIn,
			summary.notLetInSince,
			summary.lastActive
		]).toEqual([null, null, null]);
	});
});
