import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';
import { Type } from '@sinclair/typebox';

import * as base64url from 'lib/helpers/base64url.js';
import bootstrap, { type Setup } from '../test_helper.js';
import { present, shaped } from '../shape.ts';
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

function sidOfLogoutToken(body: string): string {
	const match = body.match(/^logout_token=([\w-]+)\.([\w-]+)\.([\w-]+)$/);
	if (!match?.[2]) throw new Error('expected a logout token');
	return shaped(
		Type.Object({ sid: Type.String() }),
		JSON.parse(base64url.decode(match[2]))
	).sid;
}

/**
 * @proves Deactivating an end user ends their access at once: the relying parties are told, and the
 * user's refresh and access tokens stop working (spec 069, User Story 1).
 */
describe('deactivating an end user', () => {
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
		const { authorizations = {} } = setup.getSession();
		const delivered: Record<string, unknown> = {};
		for (const [clientId, host] of [
			['client', 'https://client.example.com'],
			['second-client', 'https://second-client.example.com']
		] as const) {
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

		const res = await setActive(cookie, user.accountId, false);

		expect(res.status).toBe(200);
		expect(delivered).toEqual({
			client: present(authorizations.client, 'the client authorization').sid,
			'second-client': present(
				authorizations['second-client'],
				'the second client authorization'
			).sid
		});
	});

	it('refuses the user’s refresh token with invalid_grant afterwards', async () => {
		const user = await signIn(setup);
		mockHttp('https://client.example.com')
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
		mockHttp('https://second-client.example.com')
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
		await setActive(cookie, user.accountId, false);

		const { error } = await refresh(user.refreshToken);

		expect(error?.value).toHaveProperty('error', 'invalid_grant');
	});

	it('answers active: false when the user’s access token is introspected', async () => {
		const user = await signIn(setup);
		mockHttp('https://client.example.com')
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
		mockHttp('https://second-client.example.com')
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
		await setActive(cookie, user.accountId, false);

		expect(await introspect(user.accessToken)).toEqual({ active: false });
	});
});
