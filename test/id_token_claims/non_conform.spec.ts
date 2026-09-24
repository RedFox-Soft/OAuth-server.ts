import {
	describe,
	it,
	beforeAll,
	afterAll,
	expect,
	spyOn,
	mock
} from 'bun:test';

import bootstrap, {
	agent,
	getHeader,
	type Setup,
	changeClient,
	redirectParameter
} from '../test_helper.js';
import { decode as decodeJWT } from '../../lib/helpers/jwt.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const scope = 'openid email offline_access';

/**
 * @proves With the non-conforming option an operator opts into, scope-requested claims appear in
 * the id_token as well, including after a refresh.
 */
describe('configuration conformIdTokenClaims=false', () => {
	let setup: Setup;
	let cookie: string;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'non_conform' });
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		cookie = await setup.login({
			scope,
			rejectedClaims: ['email_verified']
		});
	});

	afterAll(function () {
		mock.restore();
	});

	describe('response_type=code', () => {
		let userinfo: unknown;
		let userinfoSigned: string;
		let tokenIdToken: string;
		let refreshIdToken: string;

		beforeAll(async () => {
			const auth = new AuthorizationRequest({
				scope,
				prompt: 'consent'
			});

			const authResponse = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(authResponse.status).toBe(303);
			auth.validateClientLocation(authResponse.response);

			const code = redirectParameter(authResponse.response, 'code');

			const tokenRes = await auth.getToken(code);
			expect(tokenRes.status).toBe(200);
			if (!tokenRes.data?.id_token) throw new Error('expected an id_token');
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
			if (!refreshRes.data?.id_token) throw new Error('expected an id_token');
			refreshIdToken = refreshRes.data.id_token;
			const access_token = refreshRes.data.access_token;

			if (access_token) {
				const unsigned = await changeClient('client', {
					userinfo_signed_response_alg: undefined
				});
				const uiRes = await agent.userinfo.get({
					headers: { authorization: `Bearer ${access_token}` }
				});
				userinfo = uiRes.data;
				await unsigned();

				const signed = await changeClient('client', {
					userinfo_signed_response_alg: 'HS256'
				});
				const uiSignedRes = await agent.userinfo.get({
					headers: { authorization: `Bearer ${access_token}` }
				});
				if (typeof uiSignedRes.data !== 'string') {
					throw new Error('expected a signed userinfo response');
				}
				userinfoSigned = uiSignedRes.data;
				await signed();
			}
		});

		it('userinfo has scope requested claims', function () {
			expect(userinfo).toContainKeys(['email']);
			expect(userinfo).not.toContainKeys(['email_verified']);
		});

		it('signed userinfo has scope requested claims', function () {
			const { payload } = decodeJWT(userinfoSigned);
			expect(payload).toContainKeys(['email']);
			expect(payload).not.toContainKeys(['email_verified']);
		});

		it('token endpoint id_token has scope requested claims', function () {
			const { payload } = decodeJWT(tokenIdToken);
			expect(payload).toContainKeys(['email']);
			expect(payload).not.toContainKeys(['email_verified']);
		});

		it('refreshed id_token has scope requested claims', function () {
			const { payload } = decodeJWT(refreshIdToken);
			expect(payload).toContainKeys(['email']);
			expect(payload).not.toContainKeys(['email_verified']);
		});
	});
});
