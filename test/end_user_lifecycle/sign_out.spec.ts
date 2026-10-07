import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { adapter, getUserStore } from 'lib/adapters/index.ts';
import { findAccount } from 'lib/addon/index.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import * as base64url from 'lib/helpers/base64url.js';
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

const RELYING_PARTIES = [
	['client', 'https://client.example.com'],
	['second-client', 'https://second-client.example.com']
] as const;

function signOut(cookie: string, uid: string) {
	const user = admin.admin.api
		.buckets({ id: DEFAULT_BUCKET_ID })
		.users({ uid });
	return user['sign-out'].post(undefined, { headers: { cookie } });
}

function sidOfLogoutToken(body: string): unknown {
	const match = body.match(/^logout_token=([\w-]+)\.([\w-]+)\.([\w-]+)$/);
	if (!match?.[2]) throw new Error('expected a logout token');
	return JSON.parse(base64url.decode(match[2])).sid;
}

function acceptLogouts(): void {
	for (const [, host] of RELYING_PARTIES) {
		mockHttp(host)
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
	}
}

/**
 * @proves An administrator can sign an end user out everywhere: every session and token ends and relying
 * parties are told, while the account stays active and unlocked (spec 072, FR-014a).
 */
describe('signing an end user out everywhere', () => {
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

	it('ends the user’s refresh token and access token', async () => {
		const user = await signIn(setup);
		acceptLogouts();

		const res = await signOut(cookie, user.accountId);

		expect(res.status).toBe(200);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
		expect(await introspect(user.accessToken)).toEqual({ active: false });
	});

	it('sends a logout notice to every client registered for back-channel logout', async () => {
		const user = await signIn(setup);
		const { authorizations = {} } = setup.getSession();
		const delivered: Record<string, unknown> = {};
		for (const [clientId, host] of RELYING_PARTIES) {
			mockHttp(host)
				.intercept({
					path: '/backchannel_logout',
					method: 'POST',
					body(value) {
						delivered[clientId] = sidOfLogoutToken(value);
						return true;
					}
				})
				.reply(200);
		}

		await signOut(cookie, user.accountId);

		expect(delivered).toEqual({
			client: authorizations.client?.sid,
			'second-client': authorizations['second-client']?.sid
		});
	});

	it('leaves the account active and unlocked', async () => {
		const user = await signIn(setup);
		acceptLogouts();

		await signOut(cookie, user.accountId);

		const stored = await getUserStore(DEFAULT_BUCKET_ID).find(user.accountId);
		expect(stored?.active).toBe(true);
		expect(stored?.lockedLocally).toBeUndefined();
		expect(await findAccount(undefined, user.accountId)).toHaveProperty(
			'accountId',
			user.accountId
		);
	});

	it('signs out a user a provisioning connection manages', async () => {
		const bucket = await defaultBucket();
		const user = await createEndUser(
			bucket,
			{ kind: 'connection', connectionId: 'conn-a' },
			{ id: nanoid(), email: `managed-${nanoid()}@x.io` },
			async () => {}
		);

		const res = await signOut(cookie, user._id);

		expect(res.status).toBe(200);
	});

	it('answers 500 naming the area whose records survived', async () => {
		const user = await signIn(setup);
		acceptLogouts();
		spyOn(adapter('RefreshToken'), 'destroyByOwner').mockRejectedValue(
			new Error('the datastore is unavailable')
		);

		const res = await signOut(cookie, user.accountId);

		expect(res.status).toBe(500);
		expect(res.error?.value).toHaveProperty('failedAreas', ['RefreshToken']);
	});

	it('answers 404 for a user the bucket does not hold', async () => {
		const res = await signOut(cookie, `absent-${nanoid()}`);

		expect(res.status).toBe(404);
	});
});
