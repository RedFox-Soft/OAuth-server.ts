import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import { createEndUser } from 'lib/end_users/service.ts';
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

const NEW_PASSWORD = 'a new password that is long enough';

function setPassword(cookie: string, uid: string, signOut?: boolean) {
	return admin.admin.api
		.buckets({ id: DEFAULT_BUCKET_ID })
		.users({ uid })
		.password.post(
			{ password: NEW_PASSWORD, ...(signOut === undefined ? {} : { signOut }) },
			{ headers: { cookie } }
		);
}

function acceptLogouts(): void {
	for (const host of [
		'https://client.example.com',
		'https://second-client.example.com'
	]) {
		mockHttp(host)
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
	}
}

/**
 * @proves An administrator who sets a person's password can end every sign-in that person holds in the same
 * step, or leave them signed in, and the account then says a password was set.
 */
describe('setting an end user’s password', () => {
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

	it('ends the person’s refresh and access tokens when asked to sign them out', async () => {
		const user = await signIn(setup);
		acceptLogouts();

		const res = await setPassword(cookie, user.accountId, true);

		expect(res.status).toBe(200);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
		expect(await introspect(user.accessToken)).toEqual({ active: false });
	});

	it('keeps the person signed in when not asked to sign them out', async () => {
		const user = await signIn(setup);

		const res = await setPassword(cookie, user.accountId);

		expect(res.status).toBe(200);
		expect(await introspect(user.accessToken)).toHaveProperty('active', true);
	});

	it('records that the person was signed out with the new password', async () => {
		const user = await signIn(setup);
		acceptLogouts();

		await setPassword(cookie, user.accountId, true);

		const { entries } = await adminAuditStore.list({
			targetId: user.accountId,
			action: 'enduser.password.reset'
		});
		expect(entries[0]?.attributes).toEqual(['signOut']);
	});

	it('marks an account created without a password as having one once it is set', async () => {
		const bucket = await defaultBucket();
		const created = await createEndUser(
			bucket,
			{ kind: 'admin' },
			{ id: nanoid(), email: `passwordless-${nanoid()}@x.io` },
			async () => {}
		);
		expect(created.passwordSet).toBe(false);

		await setPassword(cookie, created._id);

		const stored = await getUserStore(DEFAULT_BUCKET_ID).find(created._id);
		expect(stored?.passwordSet).toBe(true);
	});
});
