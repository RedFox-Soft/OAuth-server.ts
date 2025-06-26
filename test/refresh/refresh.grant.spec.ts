import { parse as parseUrl } from 'node:url';
import {
	describe,
	it,
	beforeAll,
	afterEach,
	beforeEach,
	spyOn,
	mock,
	expect
} from 'bun:test';

import base64url from 'base64url';
import timekeeper from 'timekeeper';

import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { ttl } from 'lib/configs/liveTime.js';

const route = '/token';

function errorDetail(spy) {
	return spy.mock.calls[0][0].error_detail;
}

describe('grant_type=refresh_token', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		spyOn(ttl, 'RefreshToken').mockReturnValue(5);
	});

	afterEach(() => {
		provider.removeAllListeners();
		timekeeper.reset();
		mock.restore();
	});

	let refreshToken = null;
	let rt = null;
	beforeEach(async function () {
		const authReq = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid email offline_access',
			prompt: 'consent',
			redirect_uri: 'https://client.example.com/cb',
			nonce: 'foobarnonce'
		});
		const cookie = await setup.login({ scope: 'openid email offline_access' });
		const auth = await agent.auth.get({
			query: authReq.params,
			headers: {
				cookie
			}
		});
		expect(auth.status).toBe(303);
		const {
			query: { code }
		} = parseUrl(auth.headers.get('location'), true);

		const { data } = await authReq.getToken(code);

		expect(data).toHaveProperty('refresh_token');
		const jti = setup.getTokenJti(data.refresh_token);
		refreshToken = TestAdapter.for('RefreshToken').syncFind(jti);
		expect(refreshToken).toHaveProperty('gty', 'authorization_code');
		rt = data.refresh_token;
	});

	it('returns the right stuff', async function () {
		const spy = mock();
		provider.on('grant.success', spy);

		const { data, status } = await agent.token.post(
			{
				refresh_token: rt,
				grant_type: 'refresh_token'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(status).toBe(200);
		expect(spy).toBeCalledTimes(1);
		expect(data).toContainKeys([
			'access_token',
			'id_token',
			'expires_in',
			'token_type',
			'refresh_token',
			'scope'
		]);
		const refreshIdToken = JSON.parse(
			base64url.decode(data.id_token.split('.')[1])
		);
		expect(refreshIdToken).toHaveProperty('nonce', 'foobarnonce');
		expect(data.refresh_token).toBeString();
	});

	it('populates ctx.oidc.entities', async function () {
		const spy = spyOn(OIDCContext.prototype, 'entity');

		await agent.token.post(
			{
				refresh_token: rt,
				grant_type: 'refresh_token'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);

		const entities = spy.mock.calls.map((call) => call[0]);
		expect([
			'Account',
			'Grant',
			'Client',
			'AccessToken',
			'RefreshToken'
		]).toEqual(expect.arrayContaining(entities));
		const refreshToken = spy.mock.calls.find(
			(call) => call[0] === 'RefreshToken'
		);
		expect(refreshToken[1]).toHaveProperty('gty', 'authorization_code');
		const accessToken = spy.mock.calls.find(
			(call) => call[0] === 'AccessToken'
		);
		expect(accessToken[1]).toHaveProperty(
			'gty',
			'authorization_code refresh_token'
		);
	});

	describe('validates', () => {
		it('validates the refresh token is not expired', async function () {
			timekeeper.travel(Date.now() + 10 * 1000);
			const spy = mock();
			provider.on('grant.error', spy);

			const { error } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(error.value).toEqual({
				error: 'invalid_grant',
				error_description: 'grant request is invalid'
			});
			expect(errorDetail(spy)).toBe('refresh token is expired');
		});

		it('validates that token belongs to client', async function () {
			const spy = mock();
			provider.on('grant.error', spy);

			const { error } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client2', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(errorDetail(spy)).toBe('client mismatch');
			expect(error.value).toEqual({
				error: 'invalid_grant',
				error_description: 'grant request is invalid'
			});
		});

		it('scopes are not getting extended (single)', async function () {
			const { error } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token',
					scope: 'openid profile'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_scope',
				error_description: 'refresh token missing requested scope'
			});
		});

		it('scopes are not getting extended (multiple)', async function () {
			const { error } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token',
					scope: 'openid profile address'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_scope',
				error_description: 'refresh token missing requested scopes'
			});
		});

		it('scopes can get slimmer (1/2) - no openid scope, ID Token is not issued', async function () {
			const spy = mock();
			provider.on('access_token.saved', spy);
			provider.on('access_token.issued', spy);

			const { data, status } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token',
					scope: 'email'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(spy.mock.calls[0][0]).toHaveProperty('kind', 'AccessToken');
			expect(spy.mock.calls[0][0]).toHaveProperty('scope', 'email');
			expect(data).toHaveProperty('scope', 'email');
			expect(data).not.toHaveProperty('id_token');
		});

		it('scopes can get slimmer (2/2) - openid scope is present, ID Token is issued', async function () {
			const spy = mock();
			provider.on('access_token.saved', spy);
			provider.on('access_token.issued', spy);

			const { data, status } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token',
					scope: 'openid email'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(spy.mock.calls[0][0]).toHaveProperty('kind', 'AccessToken');
			expect(spy.mock.calls[0][0]).toHaveProperty('scope', 'openid email');
			expect(data).toHaveProperty('scope', 'openid email');
			expect(data).toHaveProperty('id_token');
		});

		it('validates account is still there', async function () {
			spyOn(i(provider).configuration, 'findAccount').mockResolvedValue(null);

			const spy = mock();
			provider.on('grant.error', spy);

			const { error } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(errorDetail(spy)).toBe(
				'refresh token invalid (referenced account not found)'
			);
			expect(error.value).toEqual({
				error: 'invalid_grant',
				error_description: 'grant request is invalid'
			});
		});
	});

	it('refresh_token presence', async function () {
		const { error } = await agent.token.post(
			{
				grant_type: 'refresh_token'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(error.status).toBe(400);
		expect(error.value).toEqual({
			error: 'invalid_request',
			error_description: "missing required parameter 'refresh_token'"
		});
	});

	it('code being "found"', async function () {
		const spy = mock();
		provider.on('grant.error', spy);

		const { error } = await agent.token.post(
			{
				grant_type: 'refresh_token',
				refresh_token:
					'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiYzc4ZjdlYjMtZjdkYi00ZDNmLWFjNzUtYTY3MTA2NTUxOTYyIiwiaWF0IjoxNDYzNjY5Mjk1LCJleHAiOjE0NjM2NzEwOTUsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NjAxNDMifQ.KJxy5D3_lwAlBs6E0INhrjJm1Bk9BrPlRacoyYztt5s_yxWidNua_eSvMbmRqqIq6t2hGguW7ZkEJhVHGNxvaHctGjSIrAOjaZhh1noqP9keXnATf2N2Twdsz-Viim5F0A7vu9OlhNm75P-yfreOTmmbQ4goM5449Dvq_xli2gmgg1j4HnASAI3YuxAzCCSJPbJDE2UL0-_q7nIvH0Ak2RuNbTJLjYt36jymfLnJ2OOe1z9N2RuZrIQQy7ksAIJkJs_3SJ0RYKDBtUplPC2fK7qsNk4wUTgxLJE3Xp_sJZKwVG2ascsVdexVnUCxqDN3xt9MpI14M3Zw7UwGghdIfQ'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(error.status).toBe(400);
		expect(spy).toBeCalledTimes(1);
		expect(errorDetail(spy)).toBe('refresh token not found');
		expect(error.value).toEqual({
			error: 'invalid_grant',
			error_description: 'grant request is invalid'
		});
	});

	describe('rotateRefreshToken=true', () => {
		beforeEach(function () {
			i(provider).configuration.rotateRefreshToken = true;
		});

		afterEach(function () {
			i(provider).configuration.rotateRefreshToken = false;
		});

		it('populates ctx.oidc.entities', async function () {
			const spy = spyOn(OIDCContext.prototype, 'entity');

			await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			const entities = spy.mock.calls.map((call) => call[0]);
			expect([
				'Account',
				'Grant',
				'Client',
				'AccessToken',
				'RotatedRefreshToken',
				'RefreshToken'
			]).toEqual(expect.arrayContaining(entities));
			const rotatedRefreshToken = spy.mock.calls.find(
				(call) => call[0] === 'RotatedRefreshToken'
			);
			expect(rotatedRefreshToken[1]).toHaveProperty(
				'gty',
				'authorization_code'
			);
			const refreshToken = spy.mock.calls.findLast(
				(call) => call[0] === 'RefreshToken'
			);
			expect(refreshToken[1]).not.toEqual(rotatedRefreshToken[1]);
			expect(refreshToken[1]).toHaveProperty(
				'gty',
				'authorization_code refresh_token'
			);
			const accessToken = spy.mock.calls.find(
				(call) => call[0] === 'AccessToken'
			);
			expect(accessToken[1]).toHaveProperty(
				'gty',
				'authorization_code refresh_token'
			);
		});

		it('issues a new refresh token and consumes the old one', async function () {
			const consumeSpy = mock();
			const issueSpy = mock();
			provider.on('refresh_token.consumed', consumeSpy);
			provider.on('refresh_token.saved', issueSpy);

			const { data, status } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(consumeSpy).toBeCalledTimes(1);
			expect(issueSpy).toBeCalled();
			expect(data).toContainKeys([
				'access_token',
				'id_token',
				'expires_in',
				'token_type',
				'refresh_token',
				'scope'
			]);
			const refreshIdToken = JSON.parse(
				base64url.decode(data.id_token.split('.')[1])
			);
			expect(refreshIdToken).toHaveProperty('nonce', 'foobarnonce');
			expect(data.refresh_token).toBeString();
			expect(data.refresh_token).not.toEqual(rt);
		});

		it('the new refresh token has identical scope to the old one', async function () {
			const consumeSpy = mock();
			const issueSpy = mock();
			provider.on('refresh_token.consumed', consumeSpy);
			provider.on('refresh_token.saved', issueSpy);
			provider.on('access_token.saved', issueSpy);
			provider.on('access_token.issued', issueSpy);

			const { status } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(consumeSpy).toBeCalledTimes(1);
			expect(issueSpy).toBeCalledTimes(2);
			expect(consumeSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
			expect(issueSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
		});

		it('the new refresh token has identical scope to the old one even if the access token is requested with less scopes', async function () {
			const consumeSpy = mock();
			const issueSpy = mock();
			provider.on('refresh_token.consumed', consumeSpy);
			provider.on('refresh_token.saved', issueSpy);
			provider.on('access_token.saved', issueSpy);
			provider.on('access_token.issued', issueSpy);

			const { status } = await agent.token.post(
				{
					refresh_token: rt,
					scope: 'openid',
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(consumeSpy).toBeCalledTimes(1);
			expect(issueSpy).toBeCalledTimes(2);
			expect(consumeSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
			expect(issueSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
			expect(issueSpy.mock.calls[1][0]).toHaveProperty('scope', 'openid');
		});

		it('revokes the complete grant if the old token is used again', async function () {
			const grantRevokeSpy = mock();
			const tokenDestroySpy = mock();
			provider.on('grant.revoked', grantRevokeSpy);
			provider.on('refresh_token.destroyed', tokenDestroySpy);

			await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);

			const { error } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(grantRevokeSpy).toBeCalledTimes(1);
			expect(tokenDestroySpy).toBeCalledTimes(1);
		});
	});

	describe('rotateRefreshToken is a function (returns true)', () => {
		beforeEach(function () {
			const conf = i(provider).configuration;
			spyOn(conf, 'rotateRefreshToken').mockReturnValue(true);
		});

		it('populates ctx.oidc.entities', async function () {
			const spy = spyOn(OIDCContext.prototype, 'entity');

			await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			const entities = spy.mock.calls.map((call) => call[0]);
			expect([
				'Account',
				'Grant',
				'Client',
				'AccessToken',
				'RotatedRefreshToken',
				'RefreshToken'
			]).toEqual(expect.arrayContaining(entities));
			const rotatedRefreshToken = spy.mock.calls.find(
				(call) => call[0] === 'RotatedRefreshToken'
			);
			expect(rotatedRefreshToken[1]).toHaveProperty(
				'gty',
				'authorization_code'
			);
			const refreshToken = spy.mock.calls.findLast(
				(call) => call[0] === 'RefreshToken'
			);
			expect(refreshToken[1]).not.toEqual(rotatedRefreshToken[1]);
			expect(refreshToken[1]).toHaveProperty(
				'gty',
				'authorization_code refresh_token'
			);
			const accessToken = spy.mock.calls.find(
				(call) => call[0] === 'AccessToken'
			);
			expect(accessToken[1]).toHaveProperty(
				'gty',
				'authorization_code refresh_token'
			);
		});

		it('issues a new refresh token and consumes the old one', async function () {
			const consumeSpy = mock();
			const issueSpy = mock();
			provider.on('refresh_token.consumed', consumeSpy);
			provider.on('refresh_token.saved', issueSpy);

			const { data, status } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(consumeSpy).toBeCalledTimes(1);
			expect(issueSpy).toBeCalled();
			expect(data).toContainKeys([
				'access_token',
				'id_token',
				'expires_in',
				'token_type',
				'refresh_token',
				'scope'
			]);
			const refreshIdToken = JSON.parse(
				base64url.decode(data.id_token.split('.')[1])
			);
			expect(refreshIdToken).toHaveProperty('nonce', 'foobarnonce');
			expect(data.refresh_token).toBeString();
			expect(data.refresh_token).not.toEqual(rt);
		});

		it('the new refresh token has identical scope to the old one', async function () {
			const consumeSpy = mock();
			const issueSpy = mock();
			provider.on('refresh_token.consumed', consumeSpy);
			provider.on('refresh_token.saved', issueSpy);

			const { status } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(consumeSpy).toBeCalledTimes(1);
			expect(issueSpy).toBeCalled();
			expect(consumeSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
			expect(issueSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
		});

		it('the new refresh token has identical scope to the old one even if the access token is requested with less scopes', async function () {
			const consumeSpy = mock();
			const issueSpy = mock();
			provider.on('refresh_token.consumed', consumeSpy);
			provider.on('refresh_token.saved', issueSpy);
			provider.on('access_token.saved', issueSpy);
			provider.on('access_token.issued', issueSpy);

			const { status } = await agent.token.post(
				{
					refresh_token: rt,
					scope: 'openid',
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(consumeSpy).toBeCalledTimes(1);
			expect(issueSpy).toBeCalledTimes(2);
			expect(consumeSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
			expect(issueSpy.mock.calls[0][0]).toHaveProperty(
				'scope',
				'openid email offline_access'
			);
			expect(issueSpy.mock.calls[1][0]).toHaveProperty('scope', 'openid');
		});

		it('revokes the complete grant if the old token is used again', async function () {
			const grantRevokeSpy = mock();
			const tokenDestroySpy = mock();
			provider.on('grant.revoked', grantRevokeSpy);
			provider.on('refresh_token.destroyed', tokenDestroySpy);

			await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);

			const { error } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(grantRevokeSpy).toBeCalledTimes(1);
			expect(tokenDestroySpy).toBeCalledTimes(1);
		});
	});

	describe('rotateRefreshToken is a function (returns false)', () => {
		beforeEach(function () {
			const conf = i(provider).configuration;
			spyOn(conf, 'rotateRefreshToken').mockReturnValue(false);
		});

		it('does not rotate', async function () {
			const spy = spyOn(OIDCContext.prototype, 'entity');

			const { data, status } = await agent.token.post(
				{
					refresh_token: rt,
					grant_type: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys([
				'access_token',
				'id_token',
				'expires_in',
				'token_type',
				'refresh_token',
				'scope'
			]);
			const refreshIdToken = JSON.parse(
				base64url.decode(data.id_token.split('.')[1])
			);
			expect(refreshIdToken).toHaveProperty('nonce', 'foobarnonce');
			expect(data.refresh_token).toEqual(rt);

			const entities = spy.mock.calls.map((call) => call[0]);
			expect([
				'Account',
				'Grant',
				'Client',
				'AccessToken',
				'RefreshToken'
			]).toEqual(expect.arrayContaining(entities));
			const refreshToken = spy.mock.calls.find(
				(call) => call[0] === 'RefreshToken'
			);
			expect(refreshToken[1]).toHaveProperty('gty', 'authorization_code');
			const accessToken = spy.mock.calls.find(
				(call) => call[0] === 'AccessToken'
			);
			expect(accessToken[1]).toHaveProperty(
				'gty',
				'authorization_code refresh_token'
			);
		});
	});
});
