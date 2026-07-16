import {
	describe,
	it,
	beforeAll,
	expect,
	beforeEach,
	afterEach,
	mock,
	spyOn
} from 'bun:test';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as url from 'node:url';

import bootstrap, {
	agent,
	getHeader,
	jsonToFormUrlEncoded,
	type Setup
} from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { InvalidRequest } from 'lib/helpers/errors.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

const crt = new X509Certificate(
	readFileSync('./test/jwks/client.crt', { encoding: 'ascii' })
);
const expectedS256 = 'A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0';

describe('features.mTLS.certificateBoundAccessTokens', () => {
	let setup: Setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
		await setup.login();
	});
	afterEach(function () {
		mock.restore();
	});

	it('discovery extends discovery', async function () {
		const { data, status } =
			await agent['.well-known']['openid-configuration'].get();
		expect(status).toBe(200);
		expect(data).toHaveProperty(
			'tls_client_certificate_bound_access_tokens',
			true
		);
	});

	describe('userinfo', () => {
		it('acts like an RS checking the thumbprint now', async function () {
			const at = new AccessToken({
				grantId: setup.getGrantId('client'),
				accountId: setup.getAccountId(),
				client: await Client.find('client'),
				scope: 'openid'
			});
			at.setThumbprint('x5t', crt);

			expect(() => at.setThumbprint('jkt', 'foo')).toThrowError(
				new InvalidRequest(
					'multiple proof-of-posession mechanisms are not allowed'
				)
			);

			const bearer = await at.save();
			const tr = await agent.userinfo.get({
				headers: {
					authorization: `Bearer ${bearer}`
				}
			});
			expect(tr.status).toBe(401);

			const res = await agent.userinfo.get({
				headers: {
					authorization: `Bearer ${bearer}`,
					'x-client-cert': 'foobar'
				}
			});
			expect(res.status).toBe(401);

			const { status } = await agent.userinfo.get({
				headers: {
					authorization: `Bearer ${bearer}`,
					'x-client-cert': crt.raw.toString('base64')
				}
			});
			expect(status).toBe(200);
		});
	});

	describe('introspection', () => {
		it('exposes cnf now', async function () {
			const at = new AccessToken({
				grantId: setup.getGrantId('client'),
				accountId: setup.getAccountId(),
				client: await Client.find('client'),
				scope: 'openid'
			});
			at.setThumbprint('x5t', crt);

			const token = await at.save();

			const { status, data } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			if (!data) throw new Error('expected response data');
			expect(status).toBe(200);
			expect(data).toHaveProperty('cnf');
			expect(data).toHaveProperty('token_type', 'Bearer');
			expect(data.cnf).toHaveProperty('x5t#S256');
		});
	});

	describe('urn:ietf:params:oauth:grant-type:device_code', () => {
		let dc;
		beforeAll(async function () {
			await setup.login({ scope: 'openid offline_access' });
		});
		beforeEach(async function () {
			const { data } = await agent.device.auth.post(
				jsonToFormUrlEncoded({ scope: 'openid' }),
				{
					headers: {
						'content-type': 'application/x-www-form-urlencoded',
						...AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				}
			);
			if (!data) throw new Error('expected response data');
			dc = data.device_code;

			TestAdapter.for('DeviceCode').syncUpdate(setup.getTokenJti(dc), {
				grantId: setup.getGrantId('client'),
				scope: 'openid offline_access',
				accountId: setup.getAccountId()
			});
		});

		it('binds the access token to the certificate', async function () {
			const spy = mock();
			provider.once('grant.success', spy);

			const { status } = await agent.token.post(
				{
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					device_code: dc
				},
				{
					headers: {
						...AuthorizationRequest.basicAuthHeader('client', 'secret'),
						'x-client-cert': crt.raw.toString('base64')
					}
				}
			);
			expect(status).toBe(200);
			expect(spy).toBeCalledTimes(1);
			const {
				oidc: {
					entities: { AccessToken: accessToken, RefreshToken: refreshToken }
				}
			} = spy.mock.calls[0][0];
			expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
			expect(refreshToken.payload).not.toHaveProperty('x5t#S256');
		});

		it('verifies the request made with mutual-TLS', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const { error } = await agent.token.post(
				{
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					device_code: dc
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			if (!error) throw new Error('expected error response');
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_grant',
				error_description: 'grant request is invalid'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty(
				'error_detail',
				'mutual TLS client certificate not provided'
			);
		});

		it('binds the refresh token to the certificate for public clients', async function () {
			const spy = mock();
			provider.once('grant.success', spy);

			// changes the code to client-none
			TestAdapter.for('DeviceCode').syncUpdate(setup.getTokenJti(dc), {
				clientId: 'client-none',
				grantId: setup.getGrantId('client-none'),
				accountId: setup.getAccountId()
			});

			const { status } = await agent.token.post(
				{
					client_id: 'client-none',
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					device_code: dc
				},
				{
					headers: { 'x-client-cert': crt.raw.toString('base64') }
				}
			);
			expect(status).toBe(200);
			expect(spy).toBeCalledTimes(1);
			const {
				oidc: {
					entities: { AccessToken: accessToken, RefreshToken: refreshToken }
				}
			} = spy.mock.calls[0][0];
			expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
			expect(refreshToken.payload).toHaveProperty('x5t#S256', expectedS256);
		});
	});

	describe('urn:openid:params:grant-type:ciba', () => {
		let reqId;
		beforeEach(async function () {
			const { data } = await agent.backchannel.post(
				jsonToFormUrlEncoded({
					scope: 'openid offline_access',
					login_hint: 'accountId'
				}),
				{
					headers: {
						'content-type': 'application/x-www-form-urlencoded',
						...AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				}
			);
			if (!data) throw new Error('expected response data');
			reqId = data.auth_req_id;
		});

		it('binds the access token to the certificate', async function () {
			const spy = mock();
			provider.once('grant.success', spy);

			const { status } = await agent.token.post(
				{
					grant_type: 'urn:openid:params:grant-type:ciba',
					auth_req_id: reqId
				},
				{
					headers: {
						...AuthorizationRequest.basicAuthHeader('client', 'secret'),
						'x-client-cert': crt.raw.toString('base64')
					}
				}
			);
			expect(status).toBe(200);
			expect(spy).toBeCalledTimes(1);
			const {
				oidc: {
					entities: { AccessToken: accessToken, RefreshToken: refreshToken }
				}
			} = spy.mock.calls[0][0];
			expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
			expect(refreshToken.payload).not.toHaveProperty('x5t#S256');
		});

		it('verifies the request made with mutual-TLS', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const { error } = await agent.token.post(
				{
					grant_type: 'urn:openid:params:grant-type:ciba',
					auth_req_id: reqId
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			if (!error) throw new Error('expected error response');
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_grant',
				error_description: 'grant request is invalid'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty(
				'error_detail',
				'mutual TLS client certificate not provided'
			);
		});

		it('binds the refresh token to the certificate for public clients', async function () {
			const spy = mock();
			provider.once('grant.success', spy);

			// changes the code to client-none
			TestAdapter.for('BackchannelAuthenticationRequest').syncUpdate(
				setup.getTokenJti(reqId),
				{
					clientId: 'client-none'
				}
			);
			const { grantId } = TestAdapter.for(
				'BackchannelAuthenticationRequest'
			).syncFind(setup.getTokenJti(reqId));
			TestAdapter.for('Grant').syncUpdate(grantId, {
				clientId: 'client-none'
			});

			const { status } = await agent.token.post(
				{
					client_id: 'client-none',
					grant_type: 'urn:openid:params:grant-type:ciba',
					auth_req_id: reqId
				},
				{
					headers: { 'x-client-cert': crt.raw.toString('base64') }
				}
			);
			expect(status).toBe(200);
			expect(spy).toBeCalledTimes(1);
			const {
				oidc: {
					entities: { AccessToken: accessToken, RefreshToken: refreshToken }
				}
			} = spy.mock.calls[0][0];
			expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
			expect(refreshToken.payload).toHaveProperty('x5t#S256', expectedS256);
		});
	});

	describe('authorization flow', () => {
		let cookie: string;
		let auth;
		let code;
		beforeAll(async function () {
			cookie = await setup.login({ scope: 'openid offline_access' });
		});

		beforeEach(async function () {
			auth = new AuthorizationRequest({
				scope: 'openid offline_access',
				prompt: 'consent'
			});
			spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
			const res = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			const location = getHeader(res.response, 'location');
			({
				query: { code }
			} = url.parse(location, true));
		});

		describe('authorization_code', () => {
			it('binds the access token to the certificate', async function () {
				const spy = mock();
				provider.once('grant.success', spy);
				const { status } = await auth.getToken(code, {
					headers: { 'x-client-cert': crt.raw.toString('base64') }
				});
				expect(status).toBe(200);
				expect(spy).toBeCalledTimes(1);
				const {
					oidc: {
						entities: { AccessToken: accessToken, RefreshToken: refreshToken }
					}
				} = spy.mock.calls[0][0];
				expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
				expect(refreshToken.payload).not.toHaveProperty('x5t#S256');
			});

			it('verifies the request made with mutual-TLS', async function () {
				const spy = mock();
				provider.once('grant.error', spy);

				const { error } = await auth.getToken(code);
				expect(error.status).toBe(400);
				expect(error.value).toEqual({
					error: 'invalid_grant',
					error_description: 'grant request is invalid'
				});

				expect(spy).toBeCalledTimes(1);
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_detail',
					'mutual TLS client certificate not provided'
				);
			});
		});

		describe('refresh_token', () => {
			let refresh_token;
			beforeEach(async function () {
				const { data } = await auth.getToken(code, {
					headers: { 'x-client-cert': crt.raw.toString('base64') }
				});
				refresh_token = data.refresh_token;
			});

			it('binds the access token to the certificate', async function () {
				const spy = mock();
				provider.once('grant.success', spy);

				const { status } = await agent.token.post(
					{
						grant_type: 'refresh_token',
						refresh_token
					},
					{
						headers: {
							'x-client-cert': crt.raw.toString('base64'),
							...auth.basicAuthHeader
						}
					}
				);
				expect(status).toBe(200);

				expect(spy).toBeCalledTimes(1);
				const {
					oidc: {
						entities: { AccessToken: accessToken, RefreshToken: refreshToken }
					}
				} = spy.mock.calls[0][0];
				expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
				expect(refreshToken.payload['x5t#S256']).toBeUndefined();
			});

			it('verifies the request made with mutual-TLS', async function () {
				const spy = mock();
				provider.once('grant.error', spy);

				const { error } = await agent.token.post(
					{
						grant_type: 'refresh_token',
						refresh_token
					},
					{
						headers: {
							...auth.basicAuthHeader
						}
					}
				);
				if (!error) throw new Error('expected error response');
				expect(error.status).toBe(400);
				expect(error.value).toEqual({
					error: 'invalid_grant',
					error_description: 'grant request is invalid'
				});

				expect(spy).toBeCalledTimes(1);
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_detail',
					'mutual TLS client certificate not provided'
				);
			});
		});
	});

	describe('authorization flow (public client)', () => {
		let cookie: string;
		let auth;
		let code;
		beforeAll(async function () {
			cookie = await setup.login({ scope: 'openid offline_access' });
		});

		beforeEach(async function () {
			auth = new AuthorizationRequest({
				client_id: 'client-none',
				scope: 'openid offline_access',
				prompt: 'consent'
			});
			spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);

			const res = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			const location = getHeader(res.response, 'location');
			({
				query: { code }
			} = url.parse(location, true));
		});

		describe('authorization_code', () => {
			it('binds the access token to the certificate', async function () {
				const spy = mock();
				provider.once('grant.success', spy);

				const { status } = await auth.getToken(code, {
					headers: { 'x-client-cert': crt.raw.toString('base64') }
				});
				expect(status).toBe(200);
				expect(spy).toBeCalledTimes(1);
				const {
					oidc: {
						entities: { AccessToken: accessToken, RefreshToken: refreshToken }
					}
				} = spy.mock.calls[0][0];
				expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
				expect(refreshToken.payload).toHaveProperty('x5t#S256', expectedS256);
			});

			it('verifies the request made with mutual-TLS', async function () {
				const spy = mock();
				provider.once('grant.error', spy);

				const { error } = await auth.getToken(code);
				expect(error.status).toBe(400);
				expect(error.value).toEqual({
					error: 'invalid_grant',
					error_description: 'grant request is invalid'
				});

				expect(spy).toBeCalledTimes(1);
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_detail',
					'mutual TLS client certificate not provided'
				);
			});
		});

		describe('refresh_token', () => {
			let refresh_token;
			beforeEach(async function () {
				const { data } = await auth.getToken(code, {
					headers: { 'x-client-cert': crt.raw.toString('base64') }
				});
				refresh_token = data.refresh_token;
			});

			it('binds the access token to the certificate', async function () {
				const spy = mock();
				provider.once('grant.success', spy);

				const { status } = await agent.token.post(
					{
						client_id: 'client-none',
						grant_type: 'refresh_token',
						refresh_token
					},
					{
						headers: {
							'x-client-cert': crt.raw.toString('base64')
						}
					}
				);
				expect(status).toBe(200);

				expect(spy).toBeCalledTimes(1);
				const {
					oidc: {
						entities: { AccessToken: accessToken, RefreshToken: refreshToken }
					}
				} = spy.mock.calls[0][0];
				expect(accessToken.payload).toHaveProperty('x5t#S256', expectedS256);
				expect(refreshToken.payload).toHaveProperty('x5t#S256', expectedS256);
			});

			it('verifies the request made with mutual-TLS', async function () {
				const spy = mock();
				provider.once('grant.error', spy);

				const { error } = await agent.token.post({
					client_id: 'client-none',
					grant_type: 'refresh_token',
					refresh_token
				});
				if (!error) throw new Error('expected error response');
				expect(error.status).toBe(400);
				expect(error.value).toEqual({
					error: 'invalid_grant',
					error_description: 'grant request is invalid'
				});

				expect(spy).toBeCalledTimes(1);
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_detail',
					'mutual TLS client certificate not provided'
				);
			});

			it('verifies the request made with mutual-TLS using the same cert', async function () {
				const spy = mock();
				provider.once('grant.error', spy);

				const { error } = await agent.token.post(
					{
						client_id: 'client-none',
						grant_type: 'refresh_token',
						refresh_token
					},
					{
						headers: {
							'x-client-cert': new X509Certificate(
								readFileSync('./test/jwks/rsa.crt', { encoding: 'ascii' })
							).raw.toString('base64')
						}
					}
				);
				if (!error) throw new Error('expected error response');
				expect(error.status).toBe(400);
				expect(error.value).toEqual({
					error: 'invalid_grant',
					error_description: 'grant request is invalid'
				});

				expect(spy).toBeCalledTimes(1);
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_detail',
					'failed x5t#S256 verification'
				);
			});
		});
	});

	describe('client_credentials', () => {
		it('binds the access token to the certificate', async function () {
			const spy = mock();
			provider.once('grant.success', spy);

			const { status } = await agent.token.post(
				{
					grant_type: 'client_credentials'
				},
				{
					headers: {
						...AuthorizationRequest.basicAuthHeader('client', 'secret'),
						'x-client-cert': crt.raw.toString('base64')
					}
				}
			);
			expect(status).toBe(200);

			expect(spy).toBeCalledTimes(1);
			const {
				oidc: {
					entities: { ClientCredentials }
				}
			} = spy.mock.calls[0][0];
			expect(ClientCredentials.payload).toHaveProperty(
				'x5t#S256',
				expectedS256
			);
		});

		it('verifies the request was made with mutual-TLS', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const { error } = await agent.token.post(
				{
					grant_type: 'client_credentials'
				},
				{
					headers: {
						...AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				}
			);
			if (!error) throw new Error('expected error response');
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_grant',
				error_description: 'grant request is invalid'
			});

			expect(spy).toBeCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty(
				'error_detail',
				'mutual TLS client certificate not provided'
			);
		});
	});
});
