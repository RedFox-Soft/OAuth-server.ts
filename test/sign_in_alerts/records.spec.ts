import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { administrator, signInsOf } from '../admin_sign_ins/helpers.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { activityOf, person, project } from '../person_activity/helpers.ts';
import {
	FIREFOX_ON_LINUX,
	HOME,
	HOSTING,
	ready,
	signInFrom
} from './helpers.ts';
import { getBucketStore } from 'lib/adapters/index.ts';

/**
 * @proves A sign-in the owner was emailed about says so, and why, wherever its row is read: a person's Activity and an
 * administrator's Sign-ins; a new sign-in that sent no email carries no mark.
 */
describe('a sign-in its owner was emailed about', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ready();
	});

	it("says so on a person's Activity", async () => {
		const bucketId = await project();
		await getBucketStore().update(bucketId, { newSignInAlerts: true });
		const anna = await person(bucketId);
		await signInFrom(anna.email, 'activity-app', HOME);
		await signInFrom(anna.email, 'activity-app', HOSTING, FIREFOX_ON_LINUX);

		const { rows } = await activityOf(
			await adminCookie(),
			bucketId,
			anna.accountId,
			{
				kind: 'signIn'
			}
		);
		expect(rows.map((row) => row.words.alerted)).toEqual([
			'Emailed about a new network and browser',
			null
		]);
	});

	it("says so on an administrator's Sign-ins", async () => {
		const max = await administrator();
		const olga = await administrator('super');
		await signInFrom(max.email, 'admin-panel', HOME);
		await signInFrom(max.email, 'admin-panel', HOSTING);

		const page = await signInsOf(olga.cookie, max.user._id);
		expect(page.rows.map((row) => row.words.alerted)).toEqual([
			'Emailed about a new network',
			null
		]);
	});

	it('carries no mark for a new sign-in nobody was emailed about', async () => {
		const bucketId = await project();
		const anna = await person(bucketId);
		await signInFrom(anna.email, 'activity-app', HOME);
		await signInFrom(anna.email, 'activity-app', HOSTING);

		const { rows } = await activityOf(
			await adminCookie(),
			bucketId,
			anna.accountId,
			{
				kind: 'signIn'
			}
		);
		expect(rows.map((row) => row.words.alerted)).toEqual([null, null]);
	});
});
