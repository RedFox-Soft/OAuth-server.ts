import * as url from 'node:url';
import {
	describe,
	it,
	beforeAll,
	spyOn,
	beforeEach,
	afterEach,
	mock,
	expect
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { IdToken } from 'lib/models/id_token.js';
import { Client } from 'lib/models/client.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { TestAdapter } from 'test/models.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { ttl } from 'lib/configs/liveTime.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';

describe('dynamic ttl', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	beforeEach(function () {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});
	afterEach(function () {
		mock.restore();
	});

	// return setup.login({ scope: 'openid offline_access' });

	it('client credentials', async function () {
		const clientSpy = spyOn(ttl, 'ClientCredentials').mockReturnValue(123);

		const { data, status } = await agent.token.post({
			client_id: 'client',
			grant_type: 'client_credentials'
		});
		expect(status).toBe(200);
		expect(data).toHaveProperty('expires_in', 123);

		expect(clientSpy).toBeCalledTimes(1);
		expect(clientSpy.mock.calls[0][1]).toBeInstanceOf(
			provider.ClientCredentials
		);
		expect(clientSpy.mock.calls[0][2]).toBeInstanceOf(Client);
	});

	it('device flow init', async function () {
		await setup.login({ scope: 'openid offline_access' });
		const deviceCodeSpy = spyOn(ttl, 'DeviceCode').mockReturnValue(123);
		const device = await agent.device.auth.post({
			client_id: 'client',
			scope: 'openid offline_access'
		});
		expect(device.response.status).toBe(200);
		expect(device.data.expires_in).toBe(123);
		const device_code = device.data.device_code;

		expect(deviceCodeSpy).toBeCalledTimes(1);
		expect(deviceCodeSpy.mock.calls[0][1]).toBeInstanceOf(DeviceCode);
		expect(deviceCodeSpy.mock.calls[0][2]).toBeInstanceOf(Client);

		TestAdapter.for('DeviceCode').syncUpdate(setup.getTokenJti(device_code), {
			scope: 'openid offline_access',
			accountId: setup.getAccountId(),
			grantId: setup.getGrantId('client')
		});

		const idTokenSpy = spyOn(ttl, 'IdToken').mockReturnValue(123);
		const accessTokenSpy = spyOn(ttl, 'AccessToken').mockReturnValue(1234);
		const refreshTokenSpy = spyOn(ttl, 'RefreshToken').mockReturnValue(12345);

		const { status } = await agent.token.post(
			{
				client_id: 'client',
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code
			},
			{ headers: {} }
		);
		expect(status).toBe(200);

		expect(idTokenSpy).toHaveBeenCalledTimes(1);
		expect(idTokenSpy.mock.calls[0][0]).toBeInstanceOf(IdToken);
		expect(idTokenSpy.mock.calls[0][1]).toBeInstanceOf(Client);

		expect(accessTokenSpy).toHaveBeenCalledTimes(1);
		expect(accessTokenSpy.mock.calls[0][1]).toBeInstanceOf(AccessToken);
		expect(accessTokenSpy.mock.calls[0][2]).toBeInstanceOf(Client);

		expect(refreshTokenSpy).toHaveBeenCalledTimes(1);
		expect(refreshTokenSpy.mock.calls[0][1]).toBeInstanceOf(RefreshToken);
		expect(refreshTokenSpy.mock.calls[0][2]).toBeInstanceOf(Client);
	});

	it('authorization flow returned tokens', async function () {
		const cookie = await setup.login({ scope: 'openid offline_access' });
		const spy = spyOn(ttl, 'AuthorizationCode').mockReturnValue(12);
		const auth = new AuthorizationRequest({ scope: 'openid' });

		const { status } = await agent.auth.get({
			query: auth.params,
			headers: {
				cookie
			}
		});
		expect(status).toBe(303);

		expect(spy).toHaveBeenCalledTimes(1);
		expect(spy.mock.calls[0][1]).toBeInstanceOf(AuthorizationCode);
		expect(spy.mock.calls[0][2]).toBeInstanceOf(Client);
	});

	it('authorization code', async function () {
		const cookie = await setup.login({ scope: 'openid offline_access' });
		const idTokenSpy = spyOn(ttl, 'IdToken').mockReturnValue(123);
		const accessTokenSpy = spyOn(ttl, 'AccessToken').mockReturnValue(1234);
		const refreshTokenSpy = spyOn(ttl, 'RefreshToken').mockReturnValue(12345);

		const auth = new AuthorizationRequest({
			scope: 'openid offline_access',
			prompt: 'consent'
		});

		const res = await agent.auth.get({
			query: auth.params,
			headers: {
				cookie
			}
		});
		expect(res.response.status).toBe(303);
		const {
			query: { code }
		} = url.parse(res.response.headers.get('location'), true);

		const { status } = await agent.token.post(
			{
				client_id: 'client',
				grant_type: 'authorization_code',
				code_verifier: auth.code_verifier,
				code,
				redirect_uri: 'https://rp.example.com/cb'
			},
			{ headers: {} }
		);
		expect(status).toBe(200);

		expect(idTokenSpy).toHaveBeenCalledTimes(1);
		expect(idTokenSpy.mock.calls[0][0]).toBeInstanceOf(IdToken);
		expect(idTokenSpy.mock.calls[0][1]).toBeInstanceOf(Client);

		expect(accessTokenSpy).toHaveBeenCalledTimes(1);
		expect(accessTokenSpy.mock.calls[0][1]).toBeInstanceOf(AccessToken);
		expect(accessTokenSpy.mock.calls[0][2]).toBeInstanceOf(Client);

		expect(refreshTokenSpy).toHaveBeenCalledTimes(1);
		expect(refreshTokenSpy.mock.calls[0][1]).toBeInstanceOf(RefreshToken);
		expect(refreshTokenSpy.mock.calls[0][2]).toBeInstanceOf(Client);
	});

	it('refreshed tokens', async function () {
		const cookie = await setup.login({ scope: 'openid offline_access' });
		const auth = new AuthorizationRequest({
			scope: 'openid offline_access',
			prompt: 'consent'
		});

		const res = await agent.auth.get({
			query: auth.params,
			headers: {
				cookie
			}
		});
		expect(res.response.status).toBe(303);
		const {
			query: { code }
		} = url.parse(res.response.headers.get('location'), true);

		const tokenRes = await agent.token.post({
			client_id: 'client',
			grant_type: 'authorization_code',
			code_verifier: auth.code_verifier,
			code,
			redirect_uri: 'https://rp.example.com/cb'
		});
		expect(tokenRes.status).toBe(200);
		const refresh_token = tokenRes.data.refresh_token;

		const idTokenSpy = spyOn(ttl, 'IdToken').mockReturnValue(123);
		const accessTokenSpy = spyOn(ttl, 'AccessToken').mockReturnValue(1234);
		const refreshTokenSpy = spyOn(ttl, 'RefreshToken').mockReturnValue(12345);

		const { status } = await agent.token.post({
			client_id: 'client',
			grant_type: 'refresh_token',
			refresh_token,
			redirect_uri: 'https://rp.example.com/cb'
		});
		expect(status).toBe(200);

		expect(idTokenSpy).toHaveBeenCalledTimes(1);
		expect(idTokenSpy.mock.calls[0][0]).toBeInstanceOf(IdToken);
		expect(idTokenSpy.mock.calls[0][1]).toBeInstanceOf(Client);

		expect(accessTokenSpy).toHaveBeenCalledTimes(1);
		expect(accessTokenSpy.mock.calls[0][1]).toBeInstanceOf(AccessToken);
		expect(accessTokenSpy.mock.calls[0][2]).toBeInstanceOf(Client);

		expect(refreshTokenSpy).toHaveBeenCalledTimes(1);
		expect(refreshTokenSpy.mock.calls[0][1]).toBeInstanceOf(RefreshToken);
		expect(refreshTokenSpy.mock.calls[0][2]).toBeInstanceOf(Client);
	});
});
