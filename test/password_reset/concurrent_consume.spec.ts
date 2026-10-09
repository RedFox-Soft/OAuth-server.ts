import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { agent } from '../test_helper.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { request as requestReset } from 'lib/password_reset/challenge.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { lastEmail, extractResetUrl } from '../mail_capture.ts';
import { present, textOf } from 'test/shape.js';

/*
 * A reset link is single use under concurrency, not only in sequence. Redeeming one looked the secret up
 * and then destroyed it, so two submissions arriving together both found it and both set a password —
 * the last to land winning, and the holder of a leaked link able to race the owner using it.
 */

/**
 * @proves A reset link redeemed by several requests at once sets a password for exactly one of them.
 */
describe('a reset link redeemed concurrently', () => {
	let bucketId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'reset' });
		bucketId = (
			await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: 'Concurrent reset'
			})
		)._id;
	});

	it('changes the password for exactly one of the redemptions', async () => {
		await getUserStore(bucketId).create(
			'racing@x.io',
			await Bun.password.hash('the old password'),
			true
		);
		await requestReset('racing@x.io', bucketId);
		const token = present(
			new URL(
				present(extractResetUrl(present(lastEmail(), 'an email')), 'a link')
			).searchParams.get('token'),
			'a token'
		);

		const results = await Promise.all(
			['first new password', 'second new password'].map((password) =>
				agent['reset-password'].post({
					token,
					password,
					confirmPassword: password
				})
			)
		);

		const updated = results.filter((res) =>
			textOf(res.data).includes('Password updated')
		);
		expect(updated).toHaveLength(1);
	});
});
