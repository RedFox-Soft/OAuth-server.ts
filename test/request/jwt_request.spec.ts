import * as crypto from 'node:crypto';

import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';
import { importJWK } from 'jose';

import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, {
	agent,
	formAgent,
	getHeader,
	type Setup
} from '../test_helper.js';
import { eventBus } from 'lib/event_bus.js';
import { Client, clientKeys } from 'lib/models/client.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ISSUER } from 'lib/configs/env.js';
import { ValidationError } from 'elysia';

/**
 * @proves A signed request object is the request: a query parameter cannot modify it, the
 * algorithm and client cannot differ from what was registered, and inception is refused.
 */
describe('request parameter features', () => {
	let setup: Setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(function () {
		mock.restore();
	});

	describe('configuration features.request', () => {
		it('discovery advertises request object support and its signing algorithms', async function () {
			const { data } = await agent['.well-known']['openid-configuration'].get();
			expect(data).toHaveProperty('request_parameter_supported', true);
			expect(data).not.toHaveProperty('require_signed_request_object');

			ApplicationConfig['requestObjects.requireSignedRequestObject'] = true;

			const { data: newData } =
				await agent['.well-known']['openid-configuration'].get();

			expect(newData).toHaveProperty('request_parameter_supported', true);
			expect(newData).toHaveProperty('require_signed_request_object', true);
		});

		afterEach(function () {
			ApplicationConfig['requestObjects.requireSignedRequestObject'] = false;
		});
	});

	// How a case sends its request object: what it signs, what travels beside it, and with which key.
	type RequestCase = {
		jwtPayload?: Record<string, unknown>;
		payload?: Record<string, unknown>;
		verb?: string;
		isError?: boolean;
		jwtKey?: crypto.KeyObject | CryptoKey | Uint8Array;
		alg?: string;
	};

	async function authorization(
		client_id: string,
		{
			jwtPayload = {},
			payload = {},
			verb = 'get',
			isError = false,
			jwtKey,
			alg = 'HS256'
		}: RequestCase = {}
	) {
		const code_verifier = crypto.randomBytes(32).toString('base64url');
		const code_challenge = crypto.hash('sha256', code_verifier, 'base64url');
		const request = await JWT.sign(
			{
				jti: crypto.randomBytes(16).toString('base64url'),
				client_id,
				redirect_uri: 'https://client.example.com/cb',
				response_type: 'code',
				code_challenge_method: 'S256',
				code_challenge,
				...jwtPayload
			},
			jwtKey ?? Buffer.from('secret'),
			alg,
			{ issuer: client_id, audience: ISSUER, expiresIn: 30 }
		);

		const cookie = await setup.login({
			claims: { id_token: { email: null } }
		});
		let authResp = null;
		if (verb === 'get') {
			authResp = await agent.auth.get({
				query: {
					client_id,
					request,
					...payload
				},
				headers: {
					cookie
				}
			});
		} else {
			authResp = await formAgent.auth.post(
				{
					client_id,
					request,
					...payload
				},
				{
					headers: {
						cookie
					}
				}
			);
		}

		if (isError) {
			expect(authResp.status).toBe(303);
			return authResp;
		}

		if (jwtPayload.response_mode === 'form_post') {
			expect(authResp.status).toBe(200);
			expect(authResp.response.headers.get('content-type')).toBe(
				'text/html; charset=utf-8'
			);
			return authResp;
		}
		expect(authResp.status).toBe(303);
		const location = getHeader(authResp.response, 'location');
		expect(location.startsWith('https://client.example.com/cb')).toBeTrue();
		const params = new URL(location).searchParams;
		expect(params.get('code')).not.toBeNull();

		return authResp;
	}

	async function authorizationDevice(
		client_id: string,
		{
			jwtPayload = {},
			payload = {},
			isError = false,
			jwtKey,
			alg = 'HS256'
		}: RequestCase = {}
	) {
		const request = await JWT.sign(
			{
				jti: crypto.randomBytes(16).toString('base64url'),
				client_id,
				...jwtPayload
			},
			jwtKey ?? Buffer.from('secret'),
			alg,
			{ issuer: client_id, audience: ISSUER, expiresIn: 30 }
		);

		// No sign-in: the device authorization request comes from the device, which holds no session.
		const authResp = await formAgent.device.auth.post({
			client_id,
			request,
			...payload
		});

		if (isError) {
			expect([400, 422]).toContain(authResp.status);
			return authResp;
		}

		expect(authResp.response.status).toBe(200);
		expect(authResp.data).toHaveProperty('device_code');
		return authResp;
	}

	// Each endpoint that takes a request object: its route, verb, how to call it, and its two events.
	const endpoints: [
		route: string,
		verb: string,
		authorizationRequest: typeof authorization | typeof authorizationDevice,
		errorEvt: string,
		successEvt: string
	][] = [
		[
			'auth',
			'get',
			authorization,
			'authorization.error',
			'authorization.success'
		],
		[
			'/auth',
			'post',
			authorization,
			'authorization.error',
			'authorization.success'
		],
		[
			'/device/auth',
			'post',
			authorizationDevice,
			'device_authorization.error',
			'device_authorization.success'
		]
	];
	endpoints.forEach(
		([route, verb, authorizationRequest, errorEvt, successEvt]) => {
			describe(`${route} ${verb} passing request parameters as JWTs`, () => {
				it('does not use anything from the OAuth 2.0 parameters', async function () {
					const spy = mock();
					eventBus.once('authorization.success', spy);

					if (route === '/device/auth') {
						eventBus.once('device_authorization.success', (oidc) => {
							eventBus.emit('authorization.success', {
								params: oidc.entities.DeviceCode.payload.params
							});
						});
					}

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid'
						},
						payload: {
							ui_locales: 'foo'
						},
						verb
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0].params.ui_locales).toBeUndefined();
				});

				it('can contain max_age parameter as a number and it (and other params too) will be forced as string', async function () {
					const spy = mock();
					eventBus.once(successEvt, spy);

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							max_age: 300
						},
						payload: {
							scope: 'openid'
						},
						verb
					});

					expect(spy.mock.calls[0][0]).toMatchObject({
						params: { max_age: expect.any(Number) }
					});
				});

				it('can contain params as array and have them handled as dupes', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						jwtPayload: {
							scope: ['openid', 'profile']
						},
						payload: {
							scope: 'openid'
						},
						verb,
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toBeInstanceOf(ValidationError);
				});

				it('can contain claims parameter as JSON', async function () {
					const spy = mock();
					eventBus.once(successEvt, spy);
					const claims = JSON.stringify({ id_token: { email: null } });

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							claims
						},
						payload: {
							scope: 'openid'
						},
						verb
					});

					expect(spy.mock.calls[0][0]).toMatchObject({ params: { claims } });
				});

				it('can contain claims parameter as object', async function () {
					const spy = mock();
					eventBus.once(successEvt, spy);
					const claims = { id_token: { email: null } };

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							claims
						},
						payload: {
							scope: 'openid'
						},
						verb
					});

					expect(spy.mock.calls[0][0]).toMatchObject({ params: { claims } });
				});

				it('can accept Request Objects issued within acceptable system clock skew', async function () {
					const client = await Client.find('client-with-HS-sig');
					const [jwk] = clientKeys(client).symmetric.selectForSign({
						alg: 'HS256'
					});
					const key = await importJWK(jwk);

					await authorizationRequest('client-with-HS-sig', {
						jwtPayload: {
							scope: 'openid',
							iat: Math.ceil(Date.now() / 1000) + 5
						},
						payload: {
							scope: 'openid'
						},
						verb,
						jwtKey: key
					});
				});

				it('a request object signed with an asymmetric key is accepted', async function () {
					const client = await Client.find('client-with-HS-sig');
					const [jwk] = clientKeys(client).symmetric.selectForSign({
						alg: 'HS256'
					});
					const key = await importJWK(jwk);

					await authorizationRequest('client-with-HS-sig', {
						jwtPayload: {
							scope: 'openid'
						},
						payload: {
							scope: 'openid'
						},
						verb,
						jwtKey: key
					});
				});

				it('rejects HMAC based requests when signed with an expired secret', async function () {
					const client = await Client.find('client-with-HS-sig-expired');
					const [jwk] = clientKeys(client).symmetric.selectForSign({
						alg: 'HS256'
					});
					const key = await importJWK(jwk);

					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client-with-HS-sig-expired', {
						jwtPayload: {
							scope: 'openid'
						},
						payload: {
							scope: 'openid'
						},
						verb,
						jwtKey: key,
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_request_object'
					);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'error_description',
						'could not validate the Request Object - the client secret used for its signature is expired'
					);
				});

				it('doesnt allow request inception', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							request: 'request inception'
						},
						payload: {
							scope: 'openid'
						},
						verb,
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toBeInstanceOf(ValidationError);
				});

				it('doesnt allow requestUri inception', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							request_uri: 'request uri inception'
						},
						payload: {
							scope: 'openid'
						},
						verb,
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toBeInstanceOf(ValidationError);
				});

				if (route !== '/device/auth') {
					it('may contain a response_mode and it will be honoured', async function () {
						await authorizationRequest('client', {
							jwtPayload: {
								scope: 'openid',
								response_mode: 'form_post'
							},
							payload: {
								scope: 'openid'
							},
							verb
						});
					});

					/*
					 * Refused before the pipeline read the request object at all — a parameter beside it
					 * fails validation — and still delivered where the request object asked. The request
					 * carries no response_mode of its own, so the fallback would be a query redirect.
					 */
					it('delivers a refusal by the response mode the request object asked for', async function () {
						const request = await JWT.sign(
							{
								jti: crypto.randomBytes(16).toString('base64url'),
								client_id: 'client',
								redirect_uri: 'https://client.example.com/cb',
								response_type: 'code',
								scope: 'openid',
								response_mode: 'form_post'
							},
							Buffer.from('secret'),
							'HS256',
							{ issuer: 'client', audience: ISSUER, expiresIn: 30 }
						);
						const params = { client_id: 'client', request, max_age: -1 };
						const { response, error } =
							verb === 'get'
								? await agent.auth.get({ query: params })
								: await formAgent.auth.post(params);

						expect(response.headers.get('location')).toBeNull();
						// A 4xx body is Eden's error value; this one is the auto-submitting page.
						const page = String(error?.value);
						expect(page).toContain('action="https://client.example.com/cb"');
						expect(page).toContain('name="error" value="invalid_request"');
					});

					it('a response mode the client may not use is refused', async function () {
						const spy = mock();
						eventBus.once(errorEvt, spy);

						await authorizationRequest('client', {
							jwtPayload: {
								scope: 'openid',
								response_mode: 'foo'
							},
							payload: {
								scope: 'openid',
								response_mode: 'query'
							},
							verb,
							isError: true
						});

						expect(spy).toHaveBeenCalledTimes(1);
						expect(spy.mock.calls[0][0]).toHaveProperty(
							'message',
							'unsupported_response_mode'
						);
						expect(spy.mock.calls[0][0]).toHaveProperty(
							'error_description',
							'unsupported response_mode requested'
						);
					});

					it('doesnt allow response_type to differ', async function () {
						const spy = mock();
						eventBus.once(errorEvt, spy);

						await authorizationRequest('client', {
							jwtPayload: {
								scope: 'openid',
								response_type: 'code'
							},
							payload: {
								scope: 'openid',
								response_type: 'none'
							},
							verb,
							isError: true
						});

						expect(spy).toHaveBeenCalledTimes(1);
						expect(spy.mock.calls[0][0]).toHaveProperty(
							'message',
							'invalid_request_object'
						);
						expect(spy.mock.calls[0][0]).toHaveProperty(
							'error_description',
							'request response_type must equal the one in request parameters'
						);
					});

					it('uses the state from the request even if its validations will fail', async function () {
						const spy = mock();
						eventBus.once(errorEvt, spy);

						const { response } = await authorizationRequest('client', {
							jwtPayload: {
								scope: 'openid',
								state: 'foobar',
								client_id: 'client2'
							},
							payload: {
								scope: 'openid'
							},
							verb,
							isError: true
						});
						const params = new URL(getHeader(response, 'location'))
							.searchParams;
						expect(params.get('state')).toBe('foobar');

						expect(spy).toHaveBeenCalledTimes(1);
						expect(spy.mock.calls[0][0]).toHaveProperty(
							'message',
							'invalid_request_object'
						);
						expect(spy.mock.calls[0][0]).toHaveProperty(
							'error_description',
							'request client_id must equal the one in request parameters'
						);
					});
				}

				it('doesnt allow client_id to differ', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							client_id: 'client2',
							iss: 'client2'
						},
						payload: {
							scope: 'openid'
						},
						verb,
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_request_object'
					);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'error_description',
						'request client_id must equal the one in request parameters'
					);
				});

				it('a value that resembles a JWT but is not one is refused', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						payload: {
							scope: 'openid',
							request: 'definitely.notsigned.jwt'
						},
						verb,
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_request_object'
					);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'error_description',
						'could not parse Request Object'
					);
				});

				it('doesnt allow clients with predefined alg to bypass this alg', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client-with-HS-sig', {
						payload: {
							scope: 'openid'
						},
						verb,
						alg: 'HS384',
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_request_object'
					);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'error_description',
						'the preregistered alg must be used in request or request_uri'
					);
				});

				it('unsupported algs must not be used', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						payload: {
							scope: 'openid'
						},
						verb,
						jwtKey: crypto.createSecretKey(crypto.randomBytes(48)),
						alg: 'HS512',
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_request_object'
					);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'error_description',
						'unsupported signed request alg'
					);
				});

				it('bad signatures will be rejected', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						payload: {
							scope: 'openid'
						},
						verb,
						jwtKey: Buffer.from('not THE secret'),
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_request_object'
					);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'error_description',
						'could not validate Request Object'
					);
				});

				it('rejects "registration" parameter part of the Request Object', async function () {
					const spy = mock();
					eventBus.once(errorEvt, spy);

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							registration: 'foo'
						},
						payload: {
							scope: 'openid'
						},
						verb,
						isError: true
					});

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0]).toBeInstanceOf(ValidationError);
				});

				it('an unknown member of the request object is ignored rather than refused', async function () {
					const spy = mock();
					eventBus.once(successEvt, spy);

					await authorizationRequest('client', {
						jwtPayload: {
							scope: 'openid',
							unrecognized: true
						},
						payload: {
							scope: 'openid'
						},
						verb
					});

					expect(spy).toHaveBeenCalledTimes(1);
				});
			});
		}
	);
});
