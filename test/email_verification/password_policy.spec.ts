import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { request as requestReset } from 'lib/password_reset/challenge.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { extractResetUrl, lastEmail } from '../mail_capture.ts';
import { present, textOf } from 'test/shape.js';
import { END_USER_PASSWORD_TOO_SHORT } from 'lib/consts/password_policy.ts';

/*
 * The two places an end user chooses a password accepted any string, the empty one included: the
 * minimum lived only in the form's `required` attribute, which a direct POST does not send through.
 * Every password an administrator sets is held to eight characters; these are now held to the same.
 */

const CLIENT_ID = 'verify-code-app';

let bucketId: string;

/**
 * @proves An end user cannot register with, or reset to, a password shorter than the minimum.
 */
describe('the password an end user chooses', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'code' });
		resetAdminMemoryStores();
		bucketId = (
			await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: 'Password policy'
			})
		)._id;
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Password policy',
			slug: `policy-${Math.random().toString(36).slice(2)}`
		});
		await getProjectStore().update(project._id, {
			bucketId,
			clientIds: [CLIENT_ID]
		});
	});

	it('creates no account for a registration with a short password', async () => {
		const auth = new AuthorizationRequest({
			client_id: CLIENT_ID,
			scope: 'openid'
		});
		const { response } = await agent.auth.get({ query: auth.params });
		const uid = getHeader(response, 'location').split('/')[2];
		const cookie = present(
			response.headers.get('set-cookie'),
			'an interaction cookie'
		);

		await agent
			.ui({ uid })
			.registration.post(
				{ email: 'short@x.io', password: 'abc', confirmPassword: 'abc' },
				{ headers: { cookie } }
			);

		expect(await getUserStore(bucketId).findByEmail('short@x.io')).toBeFalsy();
	});

	it('keeps the old password when a reset asks for a short one', async () => {
		const user = await getUserStore(bucketId).create(
			'resetting@x.io',
			await Bun.password.hash('the old password'),
			true
		);
		await requestReset('resetting@x.io', bucketId);
		const token = present(
			new URL(
				present(extractResetUrl(present(lastEmail(), 'an email')), 'a link')
			).searchParams.get('token'),
			'a token'
		);

		const res = await agent['reset-password'].post({
			token,
			password: 'abc',
			confirmPassword: 'abc'
		});
		// Refused as a form to correct, as a mismatch is — a 400, not the 500 of a fault.
		expect(res.response.status).toBe(400);
		expect(textOf(res.error?.value)).toContain(END_USER_PASSWORD_TOO_SHORT);

		const after = await getUserStore(bucketId).find(user._id);
		expect(
			await Bun.password.verify('the old password', after?.password ?? '')
		).toBe(true);
	});
});
