import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';
import url from 'node:url';

import base64url from 'base64url';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Client } from 'lib/models/client.js';

/*
 * A pairwise client's logout token must name the subject that client already knows — spec 023,
 * FR-007a.
 *
 * Regression coverage, not a fix. This was raised as a defect on the reasoning that
 * lib/actions/end_session.ts hands `session.payload.accountId` straight to backchannelLogout and
 * IdToken applies no derivation of its own. The first half is true and the second is not: the
 * notification is built as an ID token, and IdToken.payload() runs the claim pipeline, where
 * Claims.result() derives the pairwise sub for a pairwise client. So the pseudonym has always gone
 * out; the raw account id never leaves the process.
 *
 * The test stays because nothing pinned that, and because the derivation living a layer away from the
 * notification is exactly what made it look absent — a future refactor that builds the logout token
 * without the claim pipeline would reintroduce the defect silently, and this is what would catch it.
 */

const ACCOUNT = 'pairwise-logout-account';

function decodeLogoutToken(value: string) {
	const match = value.match(/^logout_token=(([\w-]+\.?){3})$/);
	expect(match).toBeTruthy();
	const [, payload] = match![1].split('.');
	return JSON.parse(base64url.decode(payload));
}

describe('back-channel logout: pairwise client', () => {
	let setup: Setup;
	let idTokenSub: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'pairwise_logout' });
		const cookie = await setup.login({
			scope: 'openid',
			accountId: ACCOUNT
		});

		// Establish what this relying party actually holds, by getting it the way it would: an ID
		// token from the code flow. Every assertion below compares against this rather than against a
		// recomputed value, because "the same sub the client received" is the property under test.
		const auth = new AuthorizationRequest({
			client_id: 'pairwise-rp',
			scope: 'openid'
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});
		expect(response.status).toBe(303);

		const location = response.headers.get('location');
		if (!location) throw new Error('no location');
		const { code } = url.parse(location, true).query;

		const { data } = await auth.getToken(code);
		if (!data?.id_token) {
			throw new Error(`no id_token: ${JSON.stringify(data)}`);
		}
		idTokenSub = JSON.parse(base64url.decode(data.id_token.split('.')[1])).sub;

		expect(idTokenSub).not.toBe(ACCOUNT);
	});

	afterEach(() => {
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	it('sends the pairwise sub, not the account identifier', async () => {
		const client = await Client.find('pairwise-rp');

		mockHttp('https://pairwise-rp.example.com')
			.intercept({
				path: '/backchannel_logout',
				method: 'POST',
				body(value: string) {
					const payload = decodeLogoutToken(value);

					// The property under test: the notification names what the client already holds.
					expect(payload.sub).toBe(idTokenSub);
					expect(payload.sub).not.toBe(ACCOUNT);
					expect(payload).toHaveProperty('aud', 'pairwise-rp');
					expect(payload).toHaveProperty('sid', 'sid-value');
					return true;
				}
			})
			.reply(200);

		return client.backchannelLogout(ACCOUNT, 'sid-value');
	});
});
