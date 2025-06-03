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
import sinon from 'sinon';
import { importJWK, decodeProtectedHeader, decodeJwt } from 'jose';

import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, { agent, jsonToFormUrlEncoded } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';

describe('Pushed Request Object', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});
	afterEach(() => {
		sinon.restore();
		mock.restore();
	});

	describe('w/o Request Objects', () => {
		beforeEach(function () {
			i(provider).features.requestObjects.enabled = false;
		});

		describe('discovery', () => {
			it('extends the well known config', async function () {
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

				it('allows unregistered redirect_uris to be used', async function () {
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
							headers: AuthorizationRequest.basicAuthHeader(clientId, 'secret')
						}
					);
					expect(par.response.status).toBe(201);
					const { request_uri } = par.data;

					let id = request_uri.split(':');
					id = id[id.length - 1];

					const { request } =
						await provider.PushedAuthorizationRequest.find(id);
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

					expect(authGet.response.status).toBe(303);
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
							headers: auth.basicAuthHeader
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
						})
					);
					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_redirect_uri',
						error_description:
							"redirect_uri did not match any of the client's registered redirect_uris"
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
							headers: AuthorizationRequest.basicAuthHeader(clientId, 'secret')
						}
					);
					expect(par.response.status).toBe(422);
					expect(par.error.value).toEqual({
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
							headers: AuthorizationRequest.basicAuthHeader(clientId, 'secret')
						}
					);
					expect(error.status).toBe(400);
					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: 'redirect_uri must not contain fragments'
					});
				});
			});

			describe(`when require_pushed_authorization_requests=${requirePushedAuthorizationRequests}`, () => {
				describe('using a JAR request parameter', () => {
					it('is not enabled', async function () {
						const { error } = await agent.par.post(
							// @ts-expect-error endpoint will be parse to object
							jsonToFormUrlEncoded({
								client_id: clientId,
								request: 'this.should.be.a.jwt'
							}),
							{
								headers: AuthorizationRequest.basicAuthHeader(
									clientId,
									'secret'
								)
							}
						);
						expect(error.status).toBe(400);
						expect(error.value).toEqual({
							error: 'not_supported',
							error_description: 'Request Object is not supported'
						});
					});
				});

				describe('using a plain pushed authorization request', () => {
					describe('Pushed Authorization Request Endpoint', () => {
						it('populates ctx.oidc.entities', async function () {
							const spy = spyOn(provider.OIDCContext.prototype, 'entity');
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							const entities = spy.mock.calls.map((call) => call[0]);
							expect(entities).toEqual(
								expect.arrayContaining(['PushedAuthorizationRequest', 'Client'])
							);
						});

						it('stores a request object and returns a uri', async function () {
							const spy = sinon.spy();
							provider.once('pushed_authorization_request.success', spy);
							const spy2 = sinon.spy();
							provider.once('pushed_authorization_request.saved', spy2);

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
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(response.status).toBe(201);
							expect(data).toContainAllKeys(['expires_in', 'request_uri']);
							expect(data.expires_in).toBeCloseTo(60, 1);
							expect(data.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);

							expect(spy.calledOnce).toBeTrue();
							expect(spy2.calledOnce).toBeTrue();
							const stored = spy2.args[0][0];
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
							const { response, error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									request_uri: 'https://rp.example.com/jar#foo'
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(error.status).toBe(422);
							expect(error.value).toEqual({
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
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(error.status).toBe(400);
							expect(error.value).toEqual({
								error: 'invalid_redirect_uri',
								error_description:
									"redirect_uri did not match any of the client's registered redirect_uris"
							});
						});

						it('leaves non OIDCProviderError alone', async function () {
							const adapterThrow = new Error('adapter throw!');
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							sinon
								.stub(TestAdapter.for('PushedAuthorizationRequest'), 'upsert')
								.callsFake(async () => {
									throw adapterThrow;
								});

							const { error } = await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							TestAdapter.for('PushedAuthorizationRequest').upsert.restore();
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
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);

							let id = request_uri.split(':');
							id = id[id.length - 1];

							expect(
								await provider.PushedAuthorizationRequest.find(id)
							).toBeObject();

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
								await provider.PushedAuthorizationRequest.find(id)
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
									headers: AuthorizationRequest.basicAuthHeader(
										'client-alg-registered',
										'secret'
									)
								}
							);

							let id = request_uri.split(':');
							id = id[id.length - 1];

							expect(
								await provider.PushedAuthorizationRequest.find(id)
							).toBeObject();

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
								await provider.PushedAuthorizationRequest.find(id)
							).toHaveProperty('consumed');
						});
					});
				});
			});
		});
	});

	describe('with Request Objects', () => {
		let key = null;
		beforeAll(async function () {
			const client = await provider.Client.find('client');
			key = await importJWK(
				client.symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]
			);
		});
		beforeEach(function () {
			i(provider).features.requestObjects.enabled = true;
		});

		describe('discovery', () => {
			it('extends the well known config', async function () {
				const { data } =
					await agent['.well-known']['openid-configuration'].get();

				expect(data).not.toHaveProperty('request_object_endpoint');
				expect(data).toHaveProperty('pushed_authorization_request_endpoint');
				expect(
					data.request_object_signing_alg_values_supported
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
						it('populates ctx.oidc.entities', async function () {
							const spy = spyOn(provider.OIDCContext.prototype, 'entity');
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const request = await JWT.sign(
								{
									jti: randomBytes(16).toString('base64url'),
									response_type: 'code',
									code_challenge_method: 'S256',
									code_challenge,
									client_id: clientId,
									iss: clientId,
									aud: 'http://e.ly'
								},
								key,
								'HS256',
								{ expiresIn: 30 }
							);

							await agent.par.post(
								// @ts-expect-error endpoint will be parse to object
								jsonToFormUrlEncoded({
									request
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							const entities = spy.mock.calls.map((call) => call[0]);
							expect(entities).toEqual(
								expect.arrayContaining(['PushedAuthorizationRequest', 'Client'])
							);
						});

						it('stores a request object and returns a uri', async function () {
							const spy = sinon.spy();
							provider.once('pushed_authorization_request.success', spy);
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
											aud: 'http://e.ly'
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(response.status).toBe(201);
							expect(data.expires_in).toBeCloseTo(30, 1);
							expect(data.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);
							expect(spy.calledOnce).toBeTrue();
						});

						it('Error when no expires_in is present', async function () {
							const spy = sinon.spy();
							provider.once('pushed_authorization_request.success', spy);
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
											aud: 'http://e.ly'
										},
										key,
										'HS256'
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(error.status).toBe(422);
							expect(error.value).toEqual({
								error: 'invalid_request',
								error_description: "Property 'exp' is missing"
							});
						});

						it('uses the expiration from JWT when below MAX_TTL', async function () {
							const spy = sinon.spy();
							provider.once('pushed_authorization_request.success', spy);
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
											aud: 'http://e.ly'
										},
										key,
										'HS256',
										{ expiresIn: 20 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(response.status).toBe(201);
							expect(data.expires_in).toBeCloseTo(20, 1);
							expect(data.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);
							expect(spy.calledOnce).toBeTrue();
						});

						it('uses MAX_TTL when the expiration from JWT is above it', async function () {
							const spy = sinon.spy();
							provider.once('pushed_authorization_request.success', spy);
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
											aud: 'http://e.ly'
										},
										key,
										'HS256',
										{
											expiresIn: 120
										}
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(response.status).toBe(201);
							expect(data.expires_in).toBeCloseTo(60, 1);
							expect(data.request_uri).toMatch(
								/^urn:ietf:params:oauth:request_uri:(.+)$/
							);
							expect(spy.calledOnce).toBeTrue();
						});

						it('ignores regular parameters when passing a JAR request', async function () {
							const spy = sinon.spy();
							provider.once('pushed_authorization_request.saved', spy);
							const code_verifier = randomBytes(32).toString('base64');
							const code_challenge = createHash('sha256')
								.update(code_verifier)
								.digest('base64url');

							const { error, response } = await agent.par.post(
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
											aud: 'http://e.ly'
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(response.status).toBe(201);
							expect(spy.calledOnce).toBeTrue();

							const { request } = spy.args[0][0];
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
											aud: 'http://e.ly'
										},
										key,
										'HS384',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										'client-alg-registered',
										'secret'
									)
								}
							);
							expect(error.status).toBe(400);
							expect(error.value).toEqual({
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
											aud: 'http://e.ly'
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(error.status).toBe(400);
							expect(error.value).toEqual({
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
											aud: 'http://e.ly',
											redirect_uri: 'https://rp.example.com/unlisted'
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
							expect(error.status).toBe(400);
							expect(error.value).toEqual({
								error: 'invalid_redirect_uri',
								error_description:
									"redirect_uri did not match any of the client's registered redirect_uris"
							});
						});

						it('leaves non OIDCProviderError alone', async function () {
							const adapterThrow = new Error('adapter throw!');
							sinon
								.stub(TestAdapter.for('PushedAuthorizationRequest'), 'upsert')
								.callsFake(async () => {
									throw adapterThrow;
								});
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
											aud: 'http://e.ly'
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);
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
											aud: 'http://e.ly'
										},
										key,
										'HS256',
										{ expiresIn: 30 }
									)
								}),
								{
									headers: AuthorizationRequest.basicAuthHeader(
										clientId,
										'secret'
									)
								}
							);

							const { request_uri } = par.data;
							let id = request_uri.split(':');
							id = id[id.length - 1];

							expect(
								await provider.PushedAuthorizationRequest.find(id)
							).toBeObject();

							const auth = new AuthorizationRequest({
								client_id: clientId,
								iss: clientId,
								aud: 'http://e.ly',
								request_uri
							});

							const cookie = await setup.login();
							const { response } = await agent.auth.get({
								query: {
									client_id: clientId,
									iss: clientId,
									aud: 'http://e.ly',
									request_uri
								},
								headers: {
									cookie
								}
							});
							expect(response.status).toBe(303);
							auth.validatePresence(response, ['code']);

							expect(
								await provider.PushedAuthorizationRequest.find(id)
							).toHaveProperty('consumed');
						});

						it('handles expired or invalid pushed authorization request object', async function () {
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
