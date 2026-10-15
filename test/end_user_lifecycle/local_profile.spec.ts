import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import {
	adminAuditStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { type Setup } from '../test_helper.js';
import { present } from '../shape.ts';
import { adminCall } from './admin_call.ts';
import { adminCookie, defaultBucket, signIn, userinfo } from './fixtures.ts';

const PROFILE = {
	name: { givenName: 'Grace', familyName: 'Hopper' },
	locale: 'en-US',
	timezone: 'America/New_York',
	phoneNumbers: [{ value: '+14155550100', primary: true }]
};

function setProfile(
	cookie: string,
	bucketId: string,
	uid: string,
	profile: unknown
) {
	return adminCall(
		cookie,
		'PATCH',
		`/admin/api/projects/${bucketId}/users/${uid}`,
		{ profile }
	);
}

/**
 * @proves An administrator gives a person they manage a profile, which applications then receive as standard
 * claims under the scopes that release them; values those claims do not allow are refused naming the field, a
 * directory's person stays read-only, and the trail names the fields that changed, never their values.
 */
describe('a local person’s profile', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await defaultBucket();
		cookie = await adminCookie();
	});

	afterEach(() => {
		mock.restore();
	});

	it('reaches the application as standard claims under the profile and phone scopes', async () => {
		const user = await signIn(setup, 'openid profile phone');

		const res = await setProfile(
			cookie,
			DEFAULT_BUCKET_ID,
			user.accountId,
			PROFILE
		);

		expect(res.status).toBe(200);
		expect(await userinfo(user.accessToken)).toMatchObject({
			given_name: 'Grace',
			family_name: 'Hopper',
			locale: 'en-US',
			zoneinfo: 'America/New_York',
			phone_number: '+14155550100'
		});
	});

	for (const [field, profile] of [
		['profile.locale', { locale: 'en_US!' }],
		['profile.timezone', { timezone: 'Mars/Base' }],
		['profile.phoneNumbers', { phoneNumbers: [{ value: '555-1234' }] }]
	] as const) {
		it(`refuses an invalid ${field} naming the field, and stores nothing`, async () => {
			const user = await getUserStore(DEFAULT_BUCKET_ID).create(
				`${nanoid()}@x.io`,
				'h',
				true
			);

			const res = await setProfile(
				cookie,
				DEFAULT_BUCKET_ID,
				user._id,
				profile
			);

			expect(res.status).toBe(422);
			expect(res.body).toHaveProperty('field', field);
			expect(
				(await getUserStore(DEFAULT_BUCKET_ID).find(user._id))?.profile
			).toBeUndefined();
		});
	}

	it('refuses a person a directory provisions', async () => {
		const created = await getBucketStore().create({
			name: `Profile ${nanoid()}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const bucket = present(await getBucketStore().find(created._id), 'bucket');
		const user = await createEndUser(
			bucket,
			{ kind: 'connection', connectionId: 'conn-a' },
			{ id: nanoid(), email: `${nanoid()}@x.io` },
			async () => {}
		);

		const res = await setProfile(cookie, bucket._id, user._id, PROFILE);

		expect(res.status).toBe(409);
	});

	it('records the names of the fields that changed and none of their values', async () => {
		const user = await getUserStore(DEFAULT_BUCKET_ID).create(
			`${nanoid()}@x.io`,
			'h',
			true
		);
		await getUserStore(DEFAULT_BUCKET_ID).update(user._id, {
			profile: { locale: 'en-US' }
		});

		await setProfile(cookie, DEFAULT_BUCKET_ID, user._id, {
			locale: 'en-US',
			name: { givenName: 'Grace', familyName: 'Hopper' }
		});

		const { entries } = await adminAuditStore.list({
			action: 'enduser.update',
			targetId: user._id
		});
		expect(entries.map((e) => e.attributes)).toEqual([
			['profile.familyName', 'profile.givenName']
		]);
		expect(JSON.stringify(entries)).not.toContain('Hopper');
	});
});
