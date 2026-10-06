import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import bootstrap, { type Setup } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import { admin, adminCookie, defaultBucket, signIn } from './fixtures.ts';

/**
 * @proves Deleting an end user tells the relying parties the user signed out, as deactivating does
 * (spec 069, FR-005).
 */
describe('deleting an end user', () => {
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

	it('sends a logout notice to every client registered for back-channel logout', async () => {
		const user = await signIn(setup);
		const notified: string[] = [];
		for (const [clientId, host] of [
			['client', 'https://client.example.com'],
			['second-client', 'https://second-client.example.com']
		] as const) {
			mockHttp(host)
				.intercept({
					path: '/backchannel_logout',
					method: 'POST',
					body() {
						notified.push(clientId);
						return true;
					}
				})
				.reply(200);
		}

		const res = await admin.admin.api
			.buckets({ id: DEFAULT_BUCKET_ID })
			.users({ uid: user.accountId })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(200);
		expect(notified.sort()).toEqual(['client', 'second-client']);
	});
});
