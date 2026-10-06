import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import { adapter } from 'lib/adapters/index.ts';
import bootstrap, { type Setup } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import {
	adminCookie,
	defaultBucket,
	refresh,
	setActive,
	signIn
} from './fixtures.ts';

/**
 * @proves A deactivation that cannot clear every storage area still ends the user's access, and the
 * administrator is told which area was left (spec 069, FR-003).
 */
describe('deactivating an end user when one storage area fails to clear', () => {
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

	it('refuses the user and names the area left behind', async () => {
		const user = await signIn(setup);
		for (const host of [
			'https://client.example.com',
			'https://second-client.example.com'
		]) {
			mockHttp(host)
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);
		}
		spyOn(adapter('RefreshToken'), 'destroyByOwner').mockRejectedValue(
			new Error('the datastore is unavailable')
		);

		const res = await setActive(cookie, user.accountId, false);

		expect(res.status).toBe(500);
		expect(res.error?.value).toHaveProperty('failedAreas', ['RefreshToken']);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
	});
});
