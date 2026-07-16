import { parse as parseUrl } from 'node:url';

import {
	describe,
	it,
	beforeAll,
	afterAll,
	expect,
	spyOn,
	mock
} from 'bun:test';

import bootstrap, { agent, getHeader, type Setup } from '../test_helper.js';
import { decode as decodeJWT } from '../../lib/helpers/jwt.ts';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const scope = 'openid email offline_access';

describe('configuration conformIdTokenClaims=true', () => {
	let setup: Setup;
	let cookie = null;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'conform' });
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		cookie = await setup.login({
			scope,
			claims: JSON.stringify({ id_token: { gender: null, email: null } }),
			rejectedClaims: ['email_verified']
		});
	});

	afterAll(function () {
		mock.restore();
	});

	describe('response_type=code', () => {
		let userinfo = null;
		let userinfoSigned = null;
		let tokenIdToken = null;
		let refreshIdToken = null;

		beforeAll(async () => {
			const client = await Client.find('client');

			const claims = JSON.stringify({
				id_token: { gender: null, email: null, email_verified: null },
				userinfo: { gender: null }
			});

			const auth = new AuthorizationRequest({
				scope,
				claims,
				prompt: 'consent'
			});

			const authResponse = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(authResponse.status).toBe(303);
			auth.validateClientLocation(authResponse.response);

			const {
				query: { code }
			} = parseUrl(getHeader(authResponse.response, 'location'), true);

			const tokenRes = await auth.getToken(code);
			expect(tokenRes.status).toBe(200);
			if (!tokenRes.data) throw new Error('expected response data');
			tokenIdToken = tokenRes.data.id_token;
			const refresh_token = tokenRes.data.refresh_token;

			const refreshRes = await agent.token.post(
				{
					grant_type: 'refresh_token',
					refresh_token
				},
				{ headers: AuthorizationRequest.basicAuthHeader('client', 'secret') }
			);
			expect(refreshRes.status).toBe(200);
			if (!refreshRes.data) throw new Error('expected response data');
			refreshIdToken = refreshRes.data.id_token;
			const access_token = refreshRes.data.access_token;

			if (access_token) {
				delete client.userinfoSignedResponseAlg;
				const uiRes = await agent.userinfo.get({
					headers: { authorization: `Bearer ${access_token}` }
				});
				userinfo = uiRes.data;

				client.userinfoSignedResponseAlg = 'HS256';
				await Client.find('client');
				const uiSignedRes = await agent.userinfo.get({
					headers: { authorization: `Bearer ${access_token}` }
				});
				userinfoSigned = uiSignedRes.data;
			}
		});

		it('userinfo has scope requested claims', function () {
			expect(userinfo).toContainKeys(['email', 'gender']);
			expect(userinfo).not.toContainKeys(['email_verified']);
		});

		it('signed userinfo has scope requested claims', function () {
			const { payload } = decodeJWT(userinfoSigned);
			expect(payload).toContainKeys(['email', 'gender']);
			expect(payload).not.toContainKeys(['email_verified']);
		});

		it('token endpoint id_token does not have scope requested claims', function () {
			const { payload } = decodeJWT(tokenIdToken);
			expect(payload).toContainKeys(['gender', 'email']);
			expect(payload).not.toContainKeys(['email_verified']);
		});

		it('refreshed id_token does not have scope requested claims', function () {
			const { payload } = decodeJWT(refreshIdToken);
			expect(payload).toContainKeys(['gender', 'email']);
			expect(payload).not.toContainKeys(['email_verified']);
		});
	});
});
