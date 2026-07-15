import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';
import { once } from 'node:events';

import { generateKeyPair, SignJWT, exportJWK } from 'jose';

import { AccessDenied } from '../../lib/helpers/errors.ts';
import bootstrap, { agent, jsonToFormUrlEncoded } from '../test_helper.js';

import { emitter } from './ciba.config.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import { Grant } from 'lib/models/grant.js';

const form = { 'content-type': 'application/x-www-form-urlencoded' };

function post(body, headers = {}) {
	return agent.backchannel.post(jsonToFormUrlEncoded(body), {
		headers: { ...form, ...headers }
	});
}

describe('features.ciba', () => {
	describe('w/o request objects', () => {
		beforeAll(async () => {
			await bootstrap(import.meta.url);
		});

		afterEach(() => {
			mock.restore();
			provider.removeAllListeners('backchannel_authentication.error');
		});

		it('extends discovery', async () => {
			const { status, data } =
				await agent['.well-known']['openid-configuration'].get();
			if (!data) throw new Error('expected response data');
			expect(status).toBe(200);
			expect(data).toHaveProperty('backchannel_authentication_endpoint');
			expect(data.backchannel_authentication_endpoint).toMatch(
				/\/backchannel$/
			);
			expect(data).not.toHaveProperty(
				'backchannel_authentication_request_signing_alg_values_supported'
			);
			expect(data.backchannel_token_delivery_modes_supported).toEqual([
				'poll',
				'ping'
			]);
			expect(data).toHaveProperty(
				'backchannel_user_code_parameter_supported',
				true
			);
		});

		describe('Provider.prototype.backchannelResult', () => {
			it('"request" can be a string (BackchannelAuthenticationRequest jti)', async () => {
				const result = new AccessDenied();
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client'
				});
				await request.save();
				await provider.backchannelResult(request.jti, result);
				await expect(
					provider.backchannelResult('notfound', result)
				).rejects.toThrow('BackchannelAuthenticationRequest not found');
			});

			it('"request" can be a BackchannelAuthenticationRequest instance', async () => {
				const result = new Grant({
					clientId: 'client',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client',
					accountId: 'accountId'
				});
				await request.save();
				await provider.backchannelResult(request, result);
			});

			it('"request" must be a supported type', async () => {
				const result = new AccessDenied();

				for (const request of [
					{},
					[],
					0,
					1,
					true,
					false,
					new Set(),
					new Error()
				]) {
					await expect(
						provider.backchannelResult(request, result)
					).rejects.toThrow('invalid "request" argument');
				}
			});

			it('"result" can be a string (Grant jti)', async () => {
				const result = new Grant({
					clientId: 'client',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client',
					accountId: 'accountId'
				});
				await result.save();
				await provider.backchannelResult(request, result.jti);
				await expect(
					provider.backchannelResult(request, 'notfound')
				).rejects.toThrow('Grant not found');
			});

			it('"result" must be a supported type', async () => {
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client'
				});

				for (const result of [
					{},
					[],
					0,
					1,
					true,
					false,
					new Set(),
					new Error()
				]) {
					await expect(
						provider.backchannelResult(request, result)
					).rejects.toThrow('invalid "result" argument');
				}
			});

			it('request.clientId must be a valid client', async () => {
				const result = new AccessDenied();
				const request = new BackchannelAuthenticationRequest({
					clientId: 'notfound'
				});
				await expect(
					provider.backchannelResult(request, result)
				).rejects.toThrow('Client not found');
			});

			it('request.clientId must match result.clientId', async () => {
				const result = new Grant({
					clientId: 'client',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client-ping',
					accountId: 'accountId'
				});
				await expect(
					provider.backchannelResult(request, result)
				).rejects.toThrow('client mismatch');
			});

			it('request.accountId must match result.accountId', async () => {
				const result = new Grant({
					clientId: 'client',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client',
					accountId: 'accountId-2'
				});
				await expect(
					provider.backchannelResult(request, result)
				).rejects.toThrow('accountId mismatch');
			});

			it('saves the "request"', async () => {
				const result = new Grant({
					clientId: 'client',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client',
					accountId: 'accountId'
				});
				expect(request.jti).toBeFalsy();
				await provider.backchannelResult(request, result);
				expect(request.jti).toBeTruthy();
			});

			it('pings the client (204)', async () => {
				const fetchSpy = spyOn(globalThis, 'fetch').mockResolvedValue(
					new Response(null, { status: 204 })
				);
				const result = new Grant({
					clientId: 'client-ping',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client-ping',
					accountId: 'accountId',
					params: { client_notification_token: 'foo' }
				});
				await provider.backchannelResult(request, result);
				expect(fetchSpy).toHaveBeenCalledTimes(1);
			});

			it('pings the client (200)', async () => {
				const fetchSpy = spyOn(globalThis, 'fetch').mockResolvedValue(
					new Response(null, { status: 200 })
				);
				const result = new Grant({
					clientId: 'client-ping',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client-ping',
					accountId: 'accountId',
					params: { client_notification_token: 'foo' }
				});
				await provider.backchannelResult(request, result);
				expect(fetchSpy).toHaveBeenCalledTimes(1);
			});

			it('pings the client (400)', async () => {
				spyOn(globalThis, 'fetch').mockResolvedValue(
					new Response(null, { status: 400 })
				);
				const result = new Grant({
					clientId: 'client-ping',
					accountId: 'accountId'
				});
				const request = new BackchannelAuthenticationRequest({
					clientId: 'client-ping',
					accountId: 'accountId',
					params: { client_notification_token: 'foo' }
				});
				await expect(
					provider.backchannelResult(request, result)
				).rejects.toThrow(
					'expected 204 No Content from https://rp.example.com/ping, got: 400 Bad Request'
				);
			});
		});

		describe('backchannel_authentication_endpoint', () => {
			it('minimal w/ login_hint', async () => {
				const [res, [, request, account, client]] = await Promise.all([
					post({
						scope: 'openid',
						login_hint: 'accountId',
						client_id: 'client'
					}),
					once(emitter, 'triggerAuthenticationDevice'),
					once(emitter, 'processLoginHint'),
					once(emitter, 'validateBindingMessage'),
					once(emitter, 'validateRequestContext'),
					once(emitter, 'verifyUserCode')
				]);

				expect(res.status).toBe(200);
				expect(res.response.headers.get('content-type')).toMatch(
					/application\/json/
				);
				if (!res.data) throw new Error('expected response data');
				expect(Object.keys(res.data).sort()).toEqual(
					['auth_req_id', 'expires_in'].sort()
				);
				expect(typeof res.data.expires_in).toBe('number');
				expect(res.data.expires_in).toBeLessThanOrEqual(600);
				expect(typeof res.data.auth_req_id).toBe('string');

				expect(request.payload.accountId).toEqual(account.accountId);
				expect(request.payload.clientId).toEqual(client.clientId);
				expect(request.payload.resource).toBeUndefined();
				expect(request.payload.claims).toEqual({});
				expect(request.payload.nonce).toBeUndefined();
				expect(request.payload.scope).toBe('openid');
				expect(request.payload.params).toMatchObject({
					client_id: 'client',
					login_hint: 'accountId',
					scope: 'openid'
				});
			});

			it('requested_expiry', async () => {
				const { data } = await post({
					scope: 'openid',
					login_hint: 'accountId',
					client_id: 'client',
					requested_expiry: 300
				});
				if (!data) throw new Error('expected response data');
				expect(typeof data.expires_in).toBe('number');
				expect(data.expires_in).toBeLessThanOrEqual(300);
			});

			it('minimal w/ login_hint_token', async () => {
				const [res, [, request, account, client]] = await Promise.all([
					post({
						scope: 'openid',
						login_hint_token: 'accountId',
						client_id: 'client'
					}),
					once(emitter, 'triggerAuthenticationDevice'),
					once(emitter, 'processLoginHintToken'),
					once(emitter, 'validateBindingMessage'),
					once(emitter, 'validateRequestContext'),
					once(emitter, 'verifyUserCode')
				]);

				expect(res.status).toBe(200);
				expect(res.response.headers.get('content-type')).toMatch(
					/application\/json/
				);
				if (!res.data) throw new Error('expected response data');
				expect(Object.keys(res.data).sort()).toEqual(
					['auth_req_id', 'expires_in'].sort()
				);
				expect(typeof res.data.expires_in).toBe('number');
				expect(typeof res.data.auth_req_id).toBe('string');

				expect(request.payload.accountId).toEqual(account.accountId);
				expect(request.payload.clientId).toEqual(client.clientId);
				expect(request.payload.resource).toBeUndefined();
				expect(request.payload.claims).toEqual({});
				expect(request.payload.nonce).toBeUndefined();
				expect(request.payload.scope).toBe('openid');
				expect(request.payload.params).toMatchObject({
					client_id: 'client',
					login_hint_token: 'accountId',
					scope: 'openid'
				});
			});

			it('minimal w/ id_token_hint', async () => {
				const [, [, request]] = await Promise.all([
					post({
						scope: 'openid',
						login_hint_token: 'accountId',
						client_id: 'client'
					}),
					once(emitter, 'triggerAuthenticationDevice')
				]);
				const grant = new Grant({
					accountId: 'accountId',
					clientId: 'client'
				});
				grant.addOIDCScope('openid');
				await grant.save();
				await provider.backchannelResult(request, grant);

				const { data: tokenData } = await agent.token.post(
					jsonToFormUrlEncoded({
						client_id: 'client',
						grant_type: 'urn:openid:params:grant-type:ciba',
						auth_req_id: request.jti
					}),
					{ headers: form }
				);
				const { id_token } = tokenData;

				const [res2, [, request2, account, client]] = await Promise.all([
					post({
						scope: 'openid',
						id_token_hint: id_token,
						client_id: 'client'
					}),
					once(emitter, 'triggerAuthenticationDevice'),
					once(emitter, 'validateBindingMessage'),
					once(emitter, 'validateRequestContext'),
					once(emitter, 'verifyUserCode')
				]);

				expect(res2.status).toBe(200);
				expect(Object.keys(res2.data).sort()).toEqual(
					['auth_req_id', 'expires_in'].sort()
				);

				expect(request2.payload.accountId).toEqual(account.accountId);
				expect(request2.payload.clientId).toEqual(client.clientId);
				expect(request2.payload.resource).toBeUndefined();
				expect(request2.payload.claims).toEqual({});
				expect(request2.payload.nonce).toBeUndefined();
				expect(request2.payload.scope).toBe('openid');
				expect(request2.payload.params).toMatchObject({
					client_id: 'client',
					id_token_hint: id_token,
					scope: 'openid'
				});
			});

			describe('client validation', () => {
				it('only responds to clients with urn:openid:params:grant-type:ciba enabled', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client-not-allowed'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description:
							'urn:openid:params:grant-type:ciba is not allowed for this client'
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('rejects invalid clients', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'not-found-client'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(401);
					expect(error.value).toEqual({
						error: 'invalid_client',
						error_description: 'client authentication failed'
					});
					expect(spy).toBeCalledTimes(1);
				});
			});

			it('rejects other than application/x-www-form-urlencoded', async () => {
				const spy = mock();
				provider.once('backchannel_authentication.error', spy);

				const { error } = await agent.backchannel.post({
					client_id: 'client'
				});
				if (!error) throw new Error('expected error response');

				expect(error.status).toBe(400);
				expect(error.value).toEqual({
					error: 'invalid_request',
					error_description:
						'only application/x-www-form-urlencoded content-type bodies are supported on POST /backchannel'
				});
				expect(spy).toBeCalledTimes(1);
			});

			describe('param validation', () => {
				['request', 'request_uri', 'registration'].forEach((param) => {
					it(`check for not supported parameter ${param}`, async () => {
						const spy = mock();
						provider.once('backchannel_authentication.error', spy);

						const { error } = await post({
							client_id: 'client',
							scope: 'openid',
							[param]: 'some'
						});
						if (!error) throw new Error('expected error response');

						expect(error.status).toBe(400);
						expect(error.value).toEqual({
							error: `${param}_not_supported`
						});
						expect(spy).toBeCalledTimes(1);
					});
				});

				it('could not resolve Account', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						scope: 'openid',
						login_hint: 'notfound',
						client_id: 'client'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'unknown_user_id',
						error_description: 'could not identify end-user'
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('could not resolve account identifier', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						scope: 'openid',
						login_hint_token: 'notfound',
						client_id: 'client'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'unknown_user_id',
						error_description: 'could not identify end-user'
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('requires the scope param', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: "missing required parameter 'scope'"
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('requires the client_notification_token param when using ping', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client-ping',
						scope: 'openid'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description:
							"missing required parameter 'client_notification_token'"
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('requires the scope param with openid', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client',
						scope: 'foo'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: 'openid scope must be requested for this request'
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('validates requested_expiry', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client',
						scope: 'openid',
						requested_expiry: 0
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: 'invalid requested_expiry parameter value'
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('validates one of the hints is provided', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client',
						scope: 'openid'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description:
							'missing one of required parameters login_hint_token, id_token_hint, or login_hint'
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('validates exactly one of the hints is provided', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client',
						scope: 'openid',
						login_hint_token: 'foo',
						login_hint: 'foo'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description:
							'only one of required parameters login_hint_token, id_token_hint, or login_hint must be provided'
					});
					expect(spy).toBeCalledTimes(1);
				});
			});
		});
	});

	describe('with request objects', () => {
		beforeAll(async () => {
			await bootstrap(import.meta.url, { config: 'ciba_jar' });
		});

		afterEach(() => {
			mock.restore();
			provider.removeAllListeners('backchannel_authentication.error');
		});

		it('extends discovery', async () => {
			const { data } = await agent['.well-known']['openid-configuration'].get();
			if (!data) throw new Error('expected response data');
			expect(
				data.backchannel_authentication_request_signing_alg_values_supported
			).toBeDefined();
			expect(
				data.backchannel_authentication_request_signing_alg_values_supported
			).not.toContain('HS256');
		});

		describe('backchannel_authentication_endpoint', () => {
			describe('param validation', () => {
				['request_uri', 'registration'].forEach((param) => {
					it(`check for not supported parameter ${param}`, async () => {
						const spy = mock();
						provider.once('backchannel_authentication.error', spy);

						const { error } = await post({
							client_id: 'client',
							scope: 'openid',
							[param]: 'some'
						});
						if (!error) throw new Error('expected error response');

						expect(error.status).toBe(400);
						expect(error.value).toEqual({
							error: `${param}_not_supported`
						});
						expect(spy).toBeCalledTimes(1);
					});
				});

				it('validates request object is used', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client-signed',
						scope: 'openid'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: 'Request Object must be used by this client'
					});
					expect(spy).toBeCalledTimes(1);

					const { privateKey, publicKey } = await generateKeyPair('ES256');

					spyOn(globalThis, 'fetch').mockResolvedValue(
						new Response(
							JSON.stringify({ keys: [await exportJWK(publicKey)] }),
							{
								status: 200,
								headers: { 'content-type': 'application/json' }
							}
						)
					);

					const { status } = await post({
						client_id: 'client-signed',
						request: await new SignJWT({
							client_id: 'client-signed',
							scope: 'openid',
							login_hint: 'accountId'
						})
							.setProtectedHeader({ alg: 'ES256' })
							.setJti('foo')
							.setExpirationTime('5m')
							.setNotBefore('0s')
							.setIssuer('client-signed')
							.setIssuedAt()
							.setAudience(ISSUER)
							.sign(privateKey)
					});

					expect(status).toBe(200);
				});

				it('validates request object claims are present (exp)', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { privateKey } = await generateKeyPair('ES256');

					const { error } = await post({
						client_id: 'client-signed',
						request: await new SignJWT({
							client_id: 'client-signed',
							scope: 'openid',
							login_hint: 'accountId'
						})
							.setProtectedHeader({ alg: 'ES256' })
							.setJti('foo')
							.setNotBefore('0s')
							.setIssuer('client-signed')
							.setIssuedAt()
							.setAudience(ISSUER)
							.sign(privateKey)
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: "Request Object is missing the 'exp' claim"
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('validates request object claims are present (nbf)', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { privateKey } = await generateKeyPair('ES256');

					const { error } = await post({
						client_id: 'client-signed',
						request: await new SignJWT({
							client_id: 'client-signed',
							scope: 'openid',
							login_hint: 'accountId'
						})
							.setProtectedHeader({ alg: 'ES256' })
							.setJti('foo')
							.setExpirationTime('5m')
							.setIssuer('client-signed')
							.setIssuedAt()
							.setAudience(ISSUER)
							.sign(privateKey)
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: "Request Object is missing the 'nbf' claim"
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('validates request object claims are present (jti)', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { privateKey } = await generateKeyPair('ES256');

					const { error } = await post({
						client_id: 'client-signed',
						request: await new SignJWT({
							client_id: 'client-signed',
							scope: 'openid',
							login_hint: 'accountId'
						})
							.setProtectedHeader({ alg: 'ES256' })
							.setExpirationTime('5m')
							.setNotBefore('0s')
							.setIssuer('client-signed')
							.setIssuedAt()
							.setAudience(ISSUER)
							.sign(privateKey)
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: "Request Object is missing the 'jti' claim"
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('validates request object claims are present (iat)', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { privateKey } = await generateKeyPair('ES256');

					const { error } = await post({
						client_id: 'client-signed',
						request: await new SignJWT({
							client_id: 'client-signed',
							scope: 'openid',
							login_hint: 'accountId'
						})
							.setProtectedHeader({ alg: 'ES256' })
							.setJti('foo')
							.setExpirationTime('5m')
							.setNotBefore('0s')
							.setIssuer('client-signed')
							.setAudience(ISSUER)
							.sign(privateKey)
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: "Request Object is missing the 'iat' claim"
					});
					expect(spy).toBeCalledTimes(1);
				});

				it('validates Encrypted Request Objects are not used', async () => {
					const spy = mock();
					provider.once('backchannel_authentication.error', spy);

					const { error } = await post({
						client_id: 'client-signed',
						scope: 'openid',
						request: '....'
					});
					if (!error) throw new Error('expected error response');

					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description:
							'Encrypted Request Objects are not supported by CIBA'
					});
					expect(spy).toBeCalledTimes(1);
				});
			});
		});
	});
});
