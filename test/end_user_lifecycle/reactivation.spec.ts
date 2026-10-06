import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import {
	adminCookie,
	defaultBucket,
	introspect,
	refresh,
	setActive,
	signIn
} from './fixtures.ts';

/**
 * @proves Reactivating a user restores only the ability to sign in: nothing issued before the
 * deactivation works again (spec 069, FR-004).
 */
describe('reactivating an end user', () => {
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

	it('leaves tokens issued before the deactivation refused', async () => {
		const user = await signIn(setup);
		for (const host of [
			'https://client.example.com',
			'https://second-client.example.com'
		]) {
			mockHttp(host)
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);
		}
		await setActive(cookie, user.accountId, false);

		await setActive(cookie, user.accountId, true);

		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
		expect(await introspect(user.accessToken)).toEqual({ active: false });
	});
});
