import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { findAccount } from 'lib/addon/index.ts';
import { createEndUser, updateEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { type Setup } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import {
	admin,
	adminCookie,
	defaultBucket,
	introspect,
	refresh,
	signIn
} from './fixtures.ts';

function lock(cookie: string, uid: string, reason: string) {
	return admin.admin.api
		.buckets({ id: DEFAULT_BUCKET_ID })
		.users({ uid })
		.lock.post({ reason }, { headers: { cookie } });
}

function unlock(cookie: string, uid: string) {
	return admin.admin.api
		.buckets({ id: DEFAULT_BUCKET_ID })
		.users({ uid })
		.unlock.post(undefined, { headers: { cookie } });
}

const CONNECTION = { kind: 'connection', connectionId: 'conn-a' } as const;

/**
 * @proves An administrator's local lock ends a user's access at once and holds until an
 * administrator lifts it, whatever the user's provisioning connection does (spec 069, FR-007, FR-008).
 */
describe('locking an end user', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await defaultBucket();
		cookie = await adminCookie();
	});

	afterEach(() => {
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	it('ends the user’s sessions and tokens at once', async () => {
		const user = await signIn(setup);
		for (const host of [
			'https://client.example.com',
			'https://second-client.example.com'
		]) {
			mockHttp(host)
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);
		}

		const res = await lock(cookie, user.accountId, 'suspected compromise');

		expect(res.status).toBe(200);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
		expect(await introspect(user.accessToken)).toEqual({ active: false });
	});

	it('keeps a provisioned user unable to sign in after their connection marks them active', async () => {
		const bucket = await defaultBucket();
		const user = await createEndUser(
			bucket,
			CONNECTION,
			{ id: nanoid(), email: `locked-${nanoid()}@x.io` },
			async () => {}
		);
		await lock(cookie, user._id, 'suspected compromise');

		await updateEndUser(
			bucket,
			CONNECTION,
			user._id,
			{ active: true },
			async () => {}
		);

		expect(await findAccount(undefined, user._id)).toBeUndefined();
	});

	it('lets an unlocked, active user sign in again', async () => {
		const bucket = await defaultBucket();
		const user = await createEndUser(
			bucket,
			CONNECTION,
			{ id: nanoid(), email: `unlocked-${nanoid()}@x.io` },
			async () => {}
		);
		await lock(cookie, user._id, 'suspected compromise');

		const res = await unlock(cookie, user._id);

		expect(res.status).toBe(200);
		expect(await findAccount(undefined, user._id)).toHaveProperty(
			'accountId',
			user._id
		);
	});
});
