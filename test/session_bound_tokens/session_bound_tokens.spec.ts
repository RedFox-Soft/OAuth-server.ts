import { describe, it, beforeAll, expect, spyOn } from 'bun:test';
import * as url from 'node:url';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';

function codeFromResponse(response: Response) {
	const location = response.headers.get('location');
	if (!location) {
		throw new Error('location header is missing');
	}
	const {
		query: { code }
	} = url.parse(location, true);
	return code as string;
}

describe('session bound tokens behaviours', () => {
	let setup: Setup;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		// consent/prompt skip: keep the authorization request from bouncing to an interaction
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	describe('authorization_code flow', () => {
		it('"code" issues tokens bound to session', async () => {
			const cookie = await setup.login({ scope: 'openid offline_access' });
			const auth = new AuthorizationRequest({ scope: 'openid' });

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(response.status).toBe(303);
			auth.validatePresence(response, ['code', 'state']);
			auth.validateState(response);
			auth.validateClientLocation(response);
			const code = codeFromResponse(response);

			const authorizationCode = await AuthorizationCode.find(code);
			expect(authorizationCode.payload).toHaveProperty(
				'expiresWithSession',
				true
			);

			const { data } = await auth.getToken(code);
			if (!data) throw new Error('expected response data');
			const access_token = data.access_token;

			const token = await AccessToken.find(access_token);
			expect(token.payload).toHaveProperty('expiresWithSession', true);

			const authed = await agent.userinfo.get({
				headers: { authorization: `Bearer ${access_token}` }
			});
			expect(authed.status).toBe(200);

			await TestAdapter.for('Session').destroy(setup.getSessionId());

			const denied = await agent.userinfo.get({
				headers: { authorization: `Bearer ${access_token}` }
			});
			expect(denied.status).toBe(401);
		});

		it('"code" with "online" refresh token', async () => {
			const cookie = await setup.login({ scope: 'openid offline_access' });
			const auth = new AuthorizationRequest({
				client_id: 'client-refresh',
				scope: 'openid'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(response.status).toBe(303);
			auth.validatePresence(response, ['code', 'state']);
			auth.validateState(response);
			auth.validateClientLocation(response);
			const code = codeFromResponse(response);

			const authorizationCode = await AuthorizationCode.find(code);
			expect(authorizationCode.payload).toHaveProperty(
				'expiresWithSession',
				true
			);

			const { data: tokenData } = await auth.getToken(code);
			if (!tokenData) throw new Error('expected response data');
			let access_token = tokenData.access_token;
			let refresh_token = tokenData.refresh_token;

			let refresh = await RefreshToken.find(refresh_token);
			expect(refresh.payload).toHaveProperty('expiresWithSession', true);

			let token = await AccessToken.find(access_token);
			expect(token.payload).toHaveProperty('expiresWithSession', true);

			const authed = await agent.userinfo.get({
				headers: { authorization: `Bearer ${access_token}` }
			});
			expect(authed.status).toBe(200);

			const { data: refreshed } = await agent.token.post({
				client_id: 'client-refresh',
				refresh_token,
				grant_type: 'refresh_token'
			});
			if (!refreshed) throw new Error('expected response data');
			access_token = refreshed.access_token;
			refresh_token = refreshed.refresh_token;

			refresh = await RefreshToken.find(refresh_token);
			expect(refresh.payload).toHaveProperty('expiresWithSession', true);

			token = await AccessToken.find(access_token);
			expect(token.payload).toHaveProperty('expiresWithSession', true);

			await TestAdapter.for('Session').destroy(setup.getSessionId());

			const denied = await agent.userinfo.get({
				headers: { authorization: `Bearer ${access_token}` }
			});
			expect(denied.status).toBe(401);

			const { response: rejected } = await agent.token.post({
				client_id: 'client-refresh',
				refresh_token,
				grant_type: 'refresh_token'
			});
			expect(rejected.status).toBe(400);
		});

		it('"code" with offline_access refresh token isnt affected', async () => {
			const cookie = await setup.login({ scope: 'openid offline_access' });
			const auth = new AuthorizationRequest({
				client_id: 'client-offline',
				scope: 'openid offline_access',
				prompt: 'consent'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(response.status).toBe(303);
			auth.validatePresence(response, ['code', 'state']);
			auth.validateState(response);
			auth.validateClientLocation(response);
			const code = codeFromResponse(response);

			const authorizationCode = await AuthorizationCode.find(code);
			expect(authorizationCode.payload).not.toHaveProperty(
				'expiresWithSession'
			);

			const { data: tokenData } = await auth.getToken(code);
			if (!tokenData) throw new Error('expected response data');
			let access_token = tokenData.access_token;
			let refresh_token = tokenData.refresh_token;

			let refresh = await RefreshToken.find(refresh_token);
			expect(refresh.payload).not.toHaveProperty('expiresWithSession');

			let token = await AccessToken.find(access_token);
			expect(token.payload).not.toHaveProperty('expiresWithSession');

			const authed = await agent.userinfo.get({
				headers: { authorization: `Bearer ${access_token}` }
			});
			expect(authed.status).toBe(200);

			const { data: refreshed } = await agent.token.post({
				client_id: 'client-offline',
				refresh_token,
				grant_type: 'refresh_token'
			});
			if (!refreshed) throw new Error('expected response data');
			access_token = refreshed.access_token;
			refresh_token = refreshed.refresh_token;

			token = await AccessToken.find(access_token);
			expect(token.payload).not.toHaveProperty('expiresWithSession');
			refresh = await RefreshToken.find(refresh_token);
			expect(refresh.payload).not.toHaveProperty('expiresWithSession');

			await TestAdapter.for('Session').destroy(setup.getSessionId());

			const stillAuthed = await agent.userinfo.get({
				headers: { authorization: `Bearer ${access_token}` }
			});
			expect(stillAuthed.status).toBe(200);

			const { data: refreshedAgain } = await agent.token.post({
				client_id: 'client-offline',
				refresh_token,
				grant_type: 'refresh_token'
			});
			if (!refreshedAgain) throw new Error('expected response data');
			access_token = refreshedAgain.access_token;
			refresh_token = refreshedAgain.refresh_token;

			token = await AccessToken.find(access_token);
			expect(token.payload).not.toHaveProperty('expiresWithSession');
			refresh = await RefreshToken.find(refresh_token);
			expect(refresh.payload).not.toHaveProperty('expiresWithSession');
		});
	});
});
