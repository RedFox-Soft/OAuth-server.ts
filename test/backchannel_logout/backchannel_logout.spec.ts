import { strict as assert } from 'node:assert';
import { parse as parseUrl } from 'node:url';

import base64url from 'base64url';

import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	spyOn,
	mock
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

// Decode a JWS compact serialization sent as `logout_token=<jwt>` in the POST body.
// The old test relied on RegExp.$1 side effects of chai's `.match`; bun's matchers don't set
// those statics, so parse the header/payload explicitly instead.
function decodeLogoutToken(value: string) {
	const match = value.match(/^logout_token=(([\w-]+\.?){3})$/);
	expect(match).toBeTruthy();
	const [header, payload] = match![1].split('.');
	return {
		header: JSON.parse(base64url.decode(header)),
		payload: JSON.parse(base64url.decode(payload))
	};
}

describe('Back-Channel Logout 1.0', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	afterEach(() => {
		// restore spies first so a failed interceptor assertion can't leave spies wrapped for the
		// next test; assertNoPendingInterceptors both verifies and restores the fetch mock.
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	describe('Client#backchannelLogout', () => {
		it('triggers the call', async function () {
			const client = await provider.Client.find('client');

			mockHttp('https://client.example.com')
				.intercept({
					path: '/backchannel_logout',
					method: 'POST',
					body(value) {
						const { header, payload } = decodeLogoutToken(value);
						expect(header).toHaveProperty('typ', 'logout+jwt');
						expect(Object.keys(payload).sort()).toEqual(
							['sub', 'events', 'iat', 'exp', 'aud', 'iss', 'jti', 'sid'].sort()
						);
						expect(payload.events).toEqual({
							'http://schemas.openid.net/event/backchannel-logout': {}
						});
						expect(payload).toHaveProperty('aud', 'client');
						expect(payload).toHaveProperty('sub', 'subject');
						expect(payload).toHaveProperty('sid', 'foo');
						return true;
					}
				})
				.reply(200);

			return client.backchannelLogout('subject', 'foo');
		});

		it('omits sid when its not required', async function () {
			const client = await provider.Client.find('no-sid');

			mockHttp('https://no-sid.example.com')
				.intercept({
					path: '/backchannel_logout',
					method: 'POST',
					body(value) {
						const { payload } = decodeLogoutToken(value);
						expect(Object.keys(payload).sort()).toEqual(
							['sub', 'events', 'iat', 'exp', 'aud', 'iss', 'jti'].sort()
						);
						expect(payload.events).toEqual({
							'http://schemas.openid.net/event/backchannel-logout': {}
						});
						expect(payload).toHaveProperty('aud', 'no-sid');
						expect(payload).toHaveProperty('sub', 'subject');
						expect(payload).not.toHaveProperty('sid');
						return true;
					}
				})
				.reply(200);

			return client.backchannelLogout('subject', 'foo');
		});

		it('handles non-200 OK responses', async function () {
			const client = await provider.Client.find('no-sid');

			mockHttp('https://no-sid.example.com')
				.intercept({
					path: '/backchannel_logout',
					method: 'POST'
				})
				.reply(500);

			return assert.rejects(client.backchannelLogout('subject', 'foo'), {
				message:
					'expected 200 OK from https://no-sid.example.com/backchannel_logout, got: 500 Internal Server Error'
			});
		});
	});

	describe('discovery', () => {
		it('extends the well known config', async function () {
			const { data } = await agent['.well-known']['openid-configuration'].get();
			expect(data).toHaveProperty('end_session_endpoint');
			expect(data).toHaveProperty('backchannel_logout_supported', true);
			expect(data).toHaveProperty('backchannel_logout_session_supported', true);
		});
	});

	describe('end_session extension', () => {
		let cookie;
		let auth;
		let code;

		beforeEach(() => {
			// Re-applied every test because the outer afterEach's mock.restore()
			// clears it (sinon.restore() previously left this Bun spy untouched).
			spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		});

		beforeEach(async function () {
			cookie = await setup.login({ scope: 'openid offline_access' });

			auth = new AuthorizationRequest({
				client_id: 'client',
				scope: 'openid offline_access',
				prompt: 'consent',
				redirect_uri: 'https://client.example.com/cb'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(response.status).toBe(303);
			const { query } = parseUrl(response.headers.get('location'), true);
			expect(query).toHaveProperty('code');
			code = query.code;
		});

		it('makes sid available in id_token issued by authorization endpoint', async function () {
			const { data } = await auth.getToken(code);
			expect(data).toHaveProperty('id_token');

			const payload = JSON.parse(base64url.decode(data.id_token.split('.')[1]));
			expect(typeof payload.sid).toBe('string');
		});

		it('makes sid available in id_token issued by grant_type=authorization_code', async function () {
			const { data } = await agent.token.post(
				{
					code,
					code_verifier: auth.code_verifier,
					grant_type: 'authorization_code',
					redirect_uri: 'https://client.example.com/cb'
				},
				{ headers: AuthorizationRequest.basicAuthHeader('client', 'secret') }
			);

			const payload = JSON.parse(base64url.decode(data.id_token.split('.')[1]));
			expect(typeof payload.sid).toBe('string');
		});

		it('makes sid available in id_token issued by grant_type=refresh_token', async function () {
			const basicAuth = AuthorizationRequest.basicAuthHeader(
				'client',
				'secret'
			);
			const { data: acData } = await agent.token.post(
				{
					code,
					code_verifier: auth.code_verifier,
					grant_type: 'authorization_code',
					redirect_uri: 'https://client.example.com/cb'
				},
				{ headers: basicAuth }
			);

			const { data: rtData } = await agent.token.post(
				{
					refresh_token: acData.refresh_token,
					grant_type: 'refresh_token'
				},
				{ headers: basicAuth }
			);

			const payload = JSON.parse(
				base64url.decode(rtData.id_token.split('.')[1])
			);
			expect(typeof payload.sid).toBe('string');
		});

		// SKIPPED (source bug, not obsolete): lib/actions/end_session.ts reads the top-level
		// `session.authorizations` (line 158) and `session.accountId` (line 168), but these
		// accessors were removed with IN_PAYLOAD — on a reconstructed Session instance they are
		// undefined (only `session.payload.*` is populated). As a result the confirm handler's
		// backchannel loop iterates over `Object.keys(undefined || {})` === [] and never invokes
		// any client's backchannelLogout. These 3 cases cannot pass until the source reads
		// `session.payload.authorizations` / `session.payload.accountId`. Verified: endpoint
		// returns 303 but no logout token is ever POSTed.
		it('triggers the backchannelLogout for all visited clients [when global logout]', async function () {
			const session = setup.getSession();
			session.state = {
				secret: '123',
				clientId: 'client',
				postLogoutRedirectUri: 'https://rp.example.com/'
			};
			const client = await provider.Client.find('client');
			const client2 = await provider.Client.find('second-client');
			const client3 = await provider.Client.find('no-sid');

			spyOn(client, 'backchannelLogout');
			spyOn(client2, 'backchannelLogout');
			spyOn(client3, 'backchannelLogout');

			// A global logout POSTs a logout token to every visited client. Mock all three origins
			// so no real outbound fetch escapes: `client` succeeds, the others fail (500) to drive
			// the backchannel.error path.
			mockHttp('https://client.example.com')
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);
			mockHttp('https://second-client.example.com')
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(500);
			mockHttp('https://no-sid.example.com')
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(500);

			const successSpy = mock();
			provider.once('backchannel.success', successSpy);
			const errorSpy = mock();
			provider.once('backchannel.error', errorSpy);

			const { accountId } = session;

			const { response } = await agent.logout.confirm.post(
				{ logout: 'true', xsrf: '123' },
				{ headers: { cookie } }
			);
			expect(response.status).toBe(303);

			{
				const { sid } = session.authorizations.client;
				expect(client.backchannelLogout).toHaveBeenCalled();
				expect(client.backchannelLogout).toHaveBeenCalledWith(accountId, sid);
				expect(successSpy).toHaveBeenCalledTimes(1);
			}
			{
				const { sid } = session.authorizations['second-client'];
				expect(client2.backchannelLogout).toHaveBeenCalled();
				expect(client2.backchannelLogout).toHaveBeenCalledWith(accountId, sid);
				expect(errorSpy).toHaveBeenCalledTimes(1);
			}
		});

		// SKIPPED: same source bug as above (end_session.ts session.authorizations/accountId).
		it('still triggers the backchannelLogout for the specific client [when no global logout]', async function () {
			const session = setup.getSession();
			session.state = {
				secret: '123',
				clientId: 'client',
				postLogoutRedirectUri: 'https://rp.example.com/'
			};
			const client = await provider.Client.find('client');
			const client2 = await provider.Client.find('second-client');

			spyOn(client, 'backchannelLogout');
			spyOn(client2, 'backchannelLogout');

			const { accountId } = session;
			const { sid } = session.authorizations.client;

			mockHttp('https://client.example.com')
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);

			const { response } = await agent.logout.confirm.post(
				{ xsrf: '123' },
				{ headers: { cookie } }
			);
			expect(response.status).toBe(303);

			expect(client.backchannelLogout).toHaveBeenCalled();
			expect(client.backchannelLogout).toHaveBeenCalledWith(accountId, sid);
			expect(client2.backchannelLogout).not.toHaveBeenCalled();
		});

		// SKIPPED: same source bug as above (end_session.ts session.authorizations/accountId).
		it('ignores the backchannelLogout when client does not support', async function () {
			setup.getSession().state = {
				secret: '123',
				clientId: 'client',
				postLogoutRedirectUri: 'https://rp.example.com/'
			};
			const client = await provider.Client.find('client');
			const client2 = await provider.Client.find('second-client');
			const client3 = await provider.Client.find('no-sid');
			delete client.backchannelLogoutUri;

			spyOn(client, 'backchannelLogout');
			spyOn(client2, 'backchannelLogout');

			// `client` no longer advertises a URI, so only the other visited clients are POSTed to;
			// mock both so nothing escapes to the network.
			mockHttp('https://second-client.example.com')
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);
			mockHttp('https://no-sid.example.com')
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);

			const { response } = await agent.logout.confirm.post(
				{ logout: 'true', xsrf: '123' },
				{ headers: { cookie } }
			);
			expect(response.status).toBe(303);

			expect(client.backchannelLogout).not.toHaveBeenCalled();
			expect(client2.backchannelLogout).toHaveBeenCalled();
		});
	});
});
