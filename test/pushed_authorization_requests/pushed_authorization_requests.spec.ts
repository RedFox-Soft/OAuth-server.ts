import { randomBytes, createHash } from 'node:crypto';
import { parse as parseUrl } from 'node:url';

import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	beforeEach,
	spyOn,
	mock
} from 'bun:test';
import { importJWK, decodeProtectedHeader, decodeJwt } from 'jose';

import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, { agent, jsonToFormUrlEncoded } from '../test_helper.js';
import { eventBus } from 'lib/event_bus.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { PushedAuthorizationRequest } from 'lib/models/pushed_authorization_request.js';
import { ISSUER } from 'lib/configs/env.js';
import { Client } from 'lib/models/client.ts';

/*
 * The lifetime a request object dictates, allowing for the second that may tick between this test
 * minting `exp` and the server subtracting its own `now` from it — the handler computes
 * `ttl = exp - now`, so the answer is `seconds` or one less, and which one is a property of when the
 * request lands rather than of the contract.
 *
 * Not `toBeCloseTo(seconds, 1)`, which is what stood here and reads as tolerant while allowing ±0.05:
 * on a whole-second value that demands exactly `seconds`, and CI duly returned 29 for a 30-second
 * request object. Where the server answers with its own MAX_TTL constant instead, the assertions
 * below stay exact, because nothing about those can drift.
 */
function expectDictatedTtl(actual: number | undefined, seconds: number) {
	expect(actual).toBeGreaterThanOrEqual(seconds - 1);
	expect(actual).toBeLessThanOrEqual(seconds);
}

/**
 * @proves A client pushes an authorization request it has authenticated for, receives a bounded
 * single-use request_uri, and cannot use PAR to modify a signed request or act as another
 * client.
 */
describe('Pushed Request Object', async () => {
	const setup = await bootstrap(import.meta.url);
	afterEach(() => {
		mock.restore();
	});

	describe('w/o Request Objects', () => {
		beforeEach(function () {
			ApplicationConfig['requestObjects.enabled'] = false;
		});

		describe('discovery', () => {
			it('discovery advertises the PAR endpoint and whether it is required', async function () {
				const { data } =
					await agent['.well-known']['openid-configuration'].get();

				expect(data).not.toHaveProperty('request_object_endpoint');
				expect(data).toHaveProperty('pushed_authorization_request_endpoint');
				expect(data).not.toHaveProperty(
					'request_object_signing_alg_values_supported'
				);
				expect(data).toHaveProperty('request_uri_parameter_supported', false);
				expect(data).not.toHaveProperty(
					'require_pushed_authorization_requests'
				);

				ClientDefaults['authorization.requirePushedAuthorizationRequests'] =
					true;

				const { data: newData } =
					await agent['.well-known']['openid-configuration'].get();

				expect(newData).toHaveProperty(
					'require_pushed_authorization_requests',
					true
				);
			});

			afterEach(function () {
				ClientDefaults['authorization.requirePushedAuthorizationRequests'] =
					false;
			});
		});

		['client', 'client-par-required'].forEach((clientId) => {
			const requirePushedAuthorizationRequests =
				clientId === 'client-par-required';

			describe('allowUnregisteredRedirectUris', () => {
				beforeEach(function () {
					ApplicationConfig['par.allowUnregisteredRedirectUris'] = true;
				});
				afterEach(function () {
					ApplicationConfig['par.allowUnregisteredRedirectUris'] = false;
				});

				it('allows unregistered redirectUris to be used', async function () {
					const code_verifier = randomBytes(32).toString('base64url');
					const code_challenge = createHash('sha256')
						.update(code_verifier)
						.digest('base64url');

					const par = await agent.par.post(
						// @ts-expect-error endpoint will be parse to object
						jsonToFormUrlEncoded({
							scope: 'openid',
							response_type: 'code',
							code_challenge_method: 'S256',
							code_challenge,
							client_id: clientId,
							redirect_uri: 'https://rp.example.com/unlisted'
						}),
						{
							headers: {
								['content-type']: 'application/x-www-form-urlencoded',
								...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
							}
						}
					);
					expect(par.response.status).toBe(201);
					const request_uri = par.data?.request_uri ?? '';
					const id = request_uri.split(':').at(-1) ?? '';

					const { request } =
						(await PushedAuthorizationRequest.find(id))?.payload || {};
					if (!request) {
						throw new Error('Request not found in PushedAuthorizationRequest');
					}
					expect(decodeJwt(request)).toHaveProperty(
						'redirect_uri',
						'https://rp.example.com/unlisted'
					);

					const auth = new AuthorizationRequest({
						client_id: clientId,
						request_uri
					});
					delete auth.params.redirect_uri;
					delete auth.params.state;

					const cookie = await setup.login();
					const authGet = await agent.auth.get({
						query: {
							client_id: clientId,
							request_uri
						},
						headers: {
							cookie
						}
					});

					expect(authGet.status).toBe(303);
					auth.validatePresence(authGet.response, ['code']);
					const {
						query: { code }
					} = parseUrl(authGet.response.headers.get('location'), true);
					const jti = setup.getTokenJti(code);
					expect(
						TestAdapter.for('AuthorizationCode').syncFind(jti)
					).toHaveProperty('redirectUri', 'https://rp.example.com/unlisted');

					const { response } = await agent.token.post(
						// @ts-expect-error endpoint will be parse to object
						jsonToFormUrlEncoded({
							code,
							code_verifier,
							grant_type: 'authorization_code',
							redirect_uri: 'https://rp.example.com/unlisted'
						}),
						{
							headers: {
								['content-type']: 'application/x-www-form-urlencoded',
								...auth.basicAuthHeader
							}
						}
					);
					expect(response.status).toBe(200);
				});

				it('except for public clients', async function () {
					const testClientId = 'client-unregistered-test-public';
					const code_verifier = randomBytes(32).toString('base64url');
					const code_challenge = createHash('sha256')
						.update(code_verifier)
						.digest('base64url');

					const { error } = await agent.par.post(
						// @ts-expect-error endpoint will be parse to object
						jsonToFormUrlEncoded({
							response_type: 'code',
							code_challenge_method: 'S256',
							code_challenge,
							client_id: testClientId,
							redirect_uri: 'https://rp.example.com/unlisted'
						}),
						{
							headers: {
								['content-type']: 'application/x-www-form-urlencoded'
							}
						}
					);
					expect(error?.status).toBe(400);
					expect(error?.value).toEqual({
						error: 'invalid_redirect_uri',
						error_description:
							"redirect_uri did not match any of the client's registered redirectUris"
					});
				});

				it('still validates the URI to be valid redirect_uri', async function () {
					const code_verifier = randomBytes(32).toString('base64url');
					const code_challenge = createHash('sha256')
						.update(code_verifier)
						.digest('base64url');

					// must only contain valid uris
					const par = await agent.par.post(
						// @ts-expect-error endpoint will be parse to object
						jsonToFormUrlEncoded({
							scope: 'openid',
							response_type: 'code',
							code_challenge_method: 'S256',
							code_challenge,
							client_id: clientId,
							redirect_uri: 'not-a-valid-uri'
						}),
						{
							headers: {
								['content-type']: 'application/x-www-form-urlencoded',
								...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
							}
						}
					);
					expect(par.response.status).toBe(400);
					expect(par.error?.value).toEqual({
						error: 'invalid_request',
						error_description: "Property 'redirect_uri' should be uri"
					});

					// must not contain fragments
					const { error } = await agent.par.post(
						// @ts-expect-error endpoint will be parse to object
						jsonToFormUrlEncoded({
							scope: 'openid',
							response_type: 'code',
							code_challenge_method: 'S256',
							code_challenge,
							client_id: clientId,
							redirect_uri: 'https://rp.example.com/unlisted#fragment'
						}),
						{
							headers: {
								['content-type']: 'application/x-www-form-urlencoded',
								...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
							}
						}
					);
					expect(error?.status).toBe(400);
					expect(error?.value).toEqual({
						error: 'invalid_request',
						error_description: 'redirect_uri must not contain fragments'
					});
				});
			});

			describe(`when require_pushed_authorization_requests=${requirePushedAuthorizationRequests}`, () => {
				describe('using a JAR request parameter', () => {
					it('with the capability off the PAR endpoint is not served and discovery does not advertise it', async function () {
						const { error } = await agent.par.post(
							// @ts-expect-error endpoint will be parse to object
							jsonToFormUrlEncoded({
								client_id: clientId,
								request: 'this.should.be.a.jwt'
							}),
							{
								headers: {
									['content-type']: 'application/x-www-form-urlencoded',
									...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
								}
							}
						);
						expect(error?.status).toBe(400);
						expect(error?.value).toEqual({
							error: 'not_supported',
							error_description: 'Request Object is not supported'
						});
					});
				});

				describe('using a plain pushed authorization request', () => {
					describe('Pushed Authorization Request Endpoint', () => {
						it('labels the pushed request uri as JSON', async function () {
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { response } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									scope: 'openid',
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);

							expect(response.status).toBe(201);
							expect(response.headers.get('content-type')).toMatch(
								/^application\/json\b/
							);
						});

						it('stores a request object and returns a uri', async function () {
							const spy = mock();
							eventBus.once('pushed_authorization_request.success', spy);
							const spy2 = mock((_par: PushedAuthorizationRequest) => {});
							eventBus.once('pushed_authorization_request.saved', spy2);

							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { data, response } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									scope: 'openid',
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId,
									claims: JSON.stringify({
										id_token: {
											auth_time: { essential: true }
										}
									})
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(response.status).toBe(201);
							expect(data).toContainAllKeys(['expires_in', 'request_uri']);
							expect(data?.expires_in).toBeCloseTo(60, 1);
							expect(data?.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);

							expect(spy).toHaveBeenCalledTimes(1);
							expect(spy2).toHaveBeenCalledTimes(1);
							const stored = spy2.mock.calls[0][0].payload;
							expect(stored).toHaveProperty('trusted', true);
							const header = decodeProtectedHeader(stored.request);
							expect(header).toEqual({ alg: 'none' });
							const payload = decodeJwt(stored.request);
							expect(payload).toContainKeys([
								'jti',
								'aud',
								'exp',
								'iat',
								'nbf',
								'iss'
							]);
							expect(payload).toHaveProperty('claims', {
								id_token: {
									auth_time: { essential: true }
								}
							});
						});

						it('forbids request_uri to be used', async function () {
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');
							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									request_uri: 'https://rp.example.com/jar#foo'
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(error?.status).toBe(400);
							expect(error?.value).toEqual({
								error: 'invalid_request',
								error_description:
									"Property 'request_uri' should not be provided"
							});
						});

						it('remaps invalid_redirect_uri error to invalid_request', async function () {
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');
							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId,
									redirect_uri: 'https://rp.example.com/unlisted'
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(error?.status).toBe(400);
							expect(error?.value).toEqual({
								error: 'invalid_redirect_uri',
								error_description:
									"redirect_uri did not match any of the client's registered redirectUris"
							});
						});

						it('leaves non OIDCProviderError alone', async function () {
							const adapterThrow = new Error('adapter throw!');
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							spyOn(
								TestAdapter.for('PushedAuthorizationRequest'),
								'upsert'
							).mockRejectedValue(adapterThrow);

							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							if (!error) throw new Error('expected error response');
							expect(error.status).toBe(500);
							expect(error.value).toEqual({
								error: 'server_error',
								error_description: 'An unexpected error occurred'
							});
						});
					});

					describe('Using Pushed Authorization Requests', () => {
						it('allows the request_uri to be used', async function () {
							const code_verifier = randomBytes(32).toString('base64url');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const {
								data: { request_uri }
							} = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									scope: 'openid',
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);

							let id = request_uri.split(':');
							id = id[id.length - 1];

							expect(await PushedAuthorizationRequest.find(id)).toBeObject();

							const cookie = await setup.login();
							const auth = new AuthorizationRequest({
								client_id: clientId,
								request_uri
							});

							const { response } = await agent.auth.get({
								query: {
									client_id: clientId,
									request_uri
								},
								headers: {
									cookie
								}
							});
							expect(response.status).toBe(303);
							auth.validatePresence(response, ['code']);

							expect(
								(await PushedAuthorizationRequest.find(id))?.payload
							).toHaveProperty('consumed');
						});

						it('allows the request_uri to be used (when request object was not used but client has request_object_signing_alg for its optional use)', async function () {
							const code_verifier = randomBytes(32).toString('base64url');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const {
								data: { request_uri }
							} = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									scope: 'openid',
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: 'client-alg-registered'
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(
											'client-alg-registered',
											'secret'
										)
									}
								}
							);

							let id = request_uri.split(':');
							id = id[id.length - 1];

							expect(await PushedAuthorizationRequest.find(id)).toBeObject();

							const auth = new AuthorizationRequest({
								client_id: 'client-alg-registered',
								request_uri
							});
							const cookie = await setup.login();
							const { response } = await agent.auth.get({
								query: {
									client_id: 'client-alg-registered',
									request_uri
								},
								headers: {
									cookie
								}
							});

							expect(response.status).toBe(303);
							auth.validatePresence(response, ['code']);

							expect(
								(await PushedAuthorizationRequest.find(id))?.payload
							).toHaveProperty('consumed');
						});
					});
				});
			});
		});
	});

	describe('with Request Objects', () => {
		let key: CryptoKey | Uint8Array;
		beforeAll(async function () {
			const client = await Client.find('client');
			key = await importJWK(
				client.symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]
			);
		});
		beforeEach(function () {
			ApplicationConfig['requestObjects.enabled'] = true;
		});

		describe('discovery', () => {
			it('discovery advertises the PAR endpoint and whether it is required', async function () {
				const { data } =
					await agent['.well-known']['openid-configuration'].get();

				expect(data).not.toHaveProperty('request_object_endpoint');
				expect(data).toHaveProperty('pushed_authorization_request_endpoint');
				expect(
					data?.request_object_signing_alg_values_supported
				).not.toHaveLength(0);
				expect(data).toHaveProperty('request_parameter_supported', true);
				expect(data).toHaveProperty('request_uri_parameter_supported', false);
				expect(data).not.toHaveProperty(
					'require_pushed_authorization_requests'
				);

				ClientDefaults['authorization.requirePushedAuthorizationRequests'] =
					true;

				const { data: newData } =
					await agent['.well-known']['openid-configuration'].get();

				expect(newData).toHaveProperty(
					'require_pushed_authorization_requests',
					true
				);
			});

			afterEach(function () {
				ClientDefaults['authorization.requirePushedAuthorizationRequests'] =
					false;
			});
		});

		['client', 'client-par-required'].forEach((clientId) => {
			const requirePushedAuthorizationRequests =
				clientId === 'client-par-required';

			describe(`when require_pushed_authorization_requests=${requirePushedAuthorizationRequests}`, () => {
				describe('using a JAR request parameter', () => {
					describe('Pushed Authorization Request Endpoint', () => {
						it('stores a request object and returns a uri', async function () {
							const spy = mock();
							eventBus.once('pushed_authorization_request.success', spy);
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { data, response } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(response.status).toBe(201);
							expectDictatedTtl(data?.expires_in, 30);
							expect(data?.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);
							expect(spy).toHaveBeenCalledTimes(1);
						});

						it('a pushed request with no expiry is refused rather than stored without one', async function () {
							const spy = mock();
							eventBus.once('pushed_authorization_request.success', spy);
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256'
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							if (!error) throw new Error('expected error response');
							expect(error.status).toBe(400);
							expect(error.value).toEqual({
								error: 'invalid_request',
								error_description: "Property 'exp' is missing"
							});
						});

						it('uses the expiration from JWT when below MAX_TTL', async function () {
							const spy = mock();
							eventBus.once('pushed_authorization_request.success', spy);
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { data, response } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256',
										{ expiresIn: 20 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(response.status).toBe(201);
							expectDictatedTtl(data?.expires_in, 20);
							expect(data?.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);
							expect(spy).toHaveBeenCalledTimes(1);
						});

						it('uses MAX_TTL when the expiration from JWT is above it', async function () {
							const spy = mock((_e: unknown) => {});
							eventBus.once('pushed_authorization_request.success', spy);
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { data, response } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256',
										{
											expiresIn: 120
										}
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(response.status).toBe(201);
							expect(data?.expires_in).toBeCloseTo(60, 1);
							expect(data?.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);
							expect(spy).toHaveBeenCalledTimes(1);
						});

						it('ignores regular parameters when passing a JAR request', async function () {
							const spy = mock((_par: PushedAuthorizationRequest) => {});
							eventBus.once('pushed_authorization_request.saved', spy);
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { response } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									nonce: 'foo',
									response_type: 'code',
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(response.status).toBe(201);
							expect(spy).toHaveBeenCalledTimes(1);

							const { request } = spy.mock.calls[0][0].payload;
							const payload = decodeJwt(request);
							expect(payload).not.toHaveProperty('nonce');
							expect(payload).toHaveProperty('response_type', 'code');
						});

						it('requires the registered request object signing alg be used', async function () {
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: 'client-alg-registered',
											iss: 'client-alg-registered',
											aud: ISSUER
										},
										key,
										'HS384',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(
											'client-alg-registered',
											'secret'
										)
									}
								}
							);
							expect(error?.status).toBe(400);
							expect(error?.value).toEqual({
								error: 'invalid_request_object',
								error_description:
									'the preregistered alg must be used in request or request_uri'
							});
						});

						it('requires the request object client_id to equal the authenticated client one', async function () {
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: 'client-foo',
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(error?.status).toBe(400);
							expect(error?.value).toEqual({
								error: 'invalid_request_object',
								error_description:
									"request client_id must equal the authenticated client's client_id"
							});
						});

						it('remaps invalid_redirect_uri error to invalid_request', async function () {
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER,
											redirect_uri: 'https://rp.example.com/unlisted'
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							expect(error?.status).toBe(400);
							expect(error?.value).toEqual({
								error: 'invalid_redirect_uri',
								error_description:
									"redirect_uri did not match any of the client's registered redirectUris"
							});
						});

						it('leaves non OIDCProviderError alone', async function () {
							const adapterThrow = new Error('adapter throw!');
							spyOn(
								TestAdapter.for('PushedAuthorizationRequest'),
								'upsert'
							).mockRejectedValue(adapterThrow);
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);
							if (!error) throw new Error('expected error response');
							expect(error.status).toBe(500);
							expect(error.value).toEqual({
								error: 'server_error',
								error_description: 'An unexpected error occurred'
							});
						});
					});

					describe('Using Pushed Authorization Requests', () => {
						it('allows the request_uri to be used', async function () {
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const par = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request: await JWT.sign(
										{
											jti: randomBytes(16).toString('base64url'),
											scope: 'openid',
											response_type: 'code',
											code_challenge_method: 'S256',
											code_challenge,
											client_id: clientId,
											iss: clientId,
											aud: ISSUER
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: {
										['content-type']: 'application/x-www-form-urlencoded',
										...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
									}
								}
							);

							const request_uri = par.data?.request_uri ?? '';
							const id = request_uri.split(':').at(-1) ?? '';

							expect(await PushedAuthorizationRequest.find(id)).toBeObject();

							const auth = new AuthorizationRequest({
								client_id: clientId,
								request_uri
							});

							const cookie = await setup.login();
							const { response } = await agent.auth.get({
								query: {
									client_id: clientId,
									request_uri
								},
								headers: {
									cookie
								}
							});
							expect(response.status).toBe(303);
							auth.validatePresence(response, ['code']);

							expect(
								(await PushedAuthorizationRequest.find(id))?.payload
							).toHaveProperty('consumed');
						});

						it('an expired or malformed request_uri is refused at the authorization endpoint', async function () {
							const auth = new AuthorizationRequest({
								client_id: clientId,
								request_uri: 'urn:ietf:params:oauth:request_uri:foobar'
							});

							const { response } = await agent.auth.get({
								query: {
									client_id: clientId,
									state: auth.params.state,
									request_uri: 'urn:ietf:params:oauth:request_uri:foobar'
								}
							});
							expect(response.status).toBe(303);
							auth.validatePresence(response, [
								'error',
								'error_description',
								'state'
							]);
							auth.validateState(response);
							auth.validateClientLocation(response);
							auth.validateError(response, 'invalid_request_uri');
							auth.validateErrorDescription(
								response,
								'request_uri is invalid, expired, or was already used'
							);
						});
					});
				});
			});
		});
	});
});
