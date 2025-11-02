import { createPrivateKey, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';

import { importJWK } from 'jose';
import {
	beforeAll,
	describe,
	it,
	expect,
	mock,
	beforeEach,
	afterEach
} from 'bun:test';

import nanoid from '../../lib/helpers/nanoid.ts';
import provider from '../../lib/index.ts';
import bootstrap, { agent } from '../test_helper.js';
import clientKey from '../client.sig.key.js';
import * as JWT from '../../lib/helpers/jwt.ts';
import { ISSUER } from 'lib/configs/env.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Client } from 'lib/models/client.js';

const mtlsKeys = JSON.parse(
	readFileSync('test/jwks/jwks.json', {
		encoding: 'utf-8'
	})
);

const rsacrt = new X509Certificate(
	readFileSync('test/jwks/rsa.crt', { encoding: 'ascii' })
);
const eccrt = new X509Certificate(
	readFileSync('test/jwks/ec.crt', { encoding: 'ascii' })
);

const route = '/token';

const tokenAuthSucceeded = { success: true };

const introspectionAuthSucceeded = {
	active: false
};

const tokenAuthRejected = {
	error: 'invalid_client',
	error_description: 'client authentication failed'
};

function errorDetail(spy) {
	return spy.mock.calls[0][0].error_detail;
}

describe('client authentication options', () => {
	beforeAll(async function () {
		await bootstrap(import.meta.url)();
	});

	it('expects auth to be provided', async function () {
		const { error } = await agent.token.post({
			grant_type: 'foo'
		});
		expect(error?.status).toBe(400);
		expect(error?.value).toEqual({
			error: 'invalid_request',
			error_description: 'no client authentication mechanism provided'
		});
	});

	it('rejects when no client is found', async function () {
		const { error } = await agent.token.post({
			grant_type: 'foo',
			client_id: 'client-not-found'
		});
		expect(error?.status).toBe(401);
		expect(error?.value).toEqual({
			error: 'invalid_client',
			error_description: 'client authentication failed'
		});
	});

	describe('none "auth"', () => {
		it('accepts the "auth"', async function () {
			const res = await agent.token.post({
				grant_type: 'foo',
				client_id: 'client-none'
			});
			expect(res.status).toBe(200);
			expect(res.data).toEqual(tokenAuthSucceeded);
		});

		it('rejects the "auth" if secret was also provided', async function () {
			const spy = mock();
			provider.once('grant.error', spy);
			const { status, error } = await agent.token.post({
				grant_type: 'foo',
				client_id: 'client-none',
				client_secret: 'foobar'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'the provided authentication mechanism does not match the registered client authentication method'
				})
			);
			expect(status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});
	});

	describe('client_secret_basic auth', () => {
		it('accepts the auth', async function () {
			const { status, data } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-basic',
						'secret'
					)
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('accepts the auth (but client configured with post)', async function () {
			const { status, data } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client-post', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('accepts the auth even with id in the body', async function () {
			const { status, data } = await agent.token.post(
				{
					grant_type: 'foo',
					client_id: 'client-basic'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-basic',
						'secret'
					)
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('rejects the auth when body id differs', async function () {
			const { status, error } = await agent.token.post(
				{
					grant_type: 'foo',
					client_id: 'client-basic-other'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-basic',
						'secret'
					)
				}
			);
			expect(status).toBe(400);
			expect(error?.value).toEqual({
				error: 'invalid_request',
				error_description: 'mismatch in body and authorization client ids'
			});
		});

		it('accepts the auth (https://tools.ietf.org/html/rfc6749#appendix-B)', async function () {
			const { status, data } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(' %&+', ' %&+')
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('accepts the auth (https://tools.ietf.org/html/rfc6749#appendix-B again)', async function () {
			const { status, data } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'an:identifier',
						'some secure & non-standard secret'
					)
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('rejects improperly encoded headers', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: {
						authorization: `Basic ${btoa('foo with %:foo with $')}`
					}
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'client_id and client_secret in the authorization header are not properly encoded'
			});
		});

		it('validates the Basic scheme format (parts)', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: {
						authorization: 'Basic'
					}
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'invalid authorization header value format'
			});
		});

		it('validates the Basic scheme format (Basic)', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: {
						authorization: 'Bearer foo'
					}
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'invalid authorization header value format'
			});
		});

		it('validates the Basic scheme format (no :)', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: {
						authorization: 'Basic Zm9v'
					}
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'invalid authorization header value format'
			});
		});

		it('rejects invalid secrets', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const { error } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-basic',
						'invalid secret'
					)
				}
			);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'invalid secret provided'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('rejects double auth', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo',
					client_id: 'client-basic',
					client_secret: 'secret'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-basic',
						'invalid secret'
					)
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'client authentication must only be provided using one mechanism'
			});
		});

		it('rejects double auth (no client_id in body)', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo',
					client_secret: 'secret'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-basic',
						'invalid secret'
					)
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'client authentication must only be provided using one mechanism'
			});
		});

		it('requires the client_secret to be sent', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client-basic', '')
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'client_secret must be provided in the Authorization header'
			});
		});

		it('rejects expired secrets', async function () {
			const { error } = await agent.token.post(
				{
					grant_type: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'secret-expired-basic',
						'secret'
					)
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_client',
				error_description:
					'could not authenticate the client - its client secret is expired'
			});
		});
	});

	describe('client_secret_post auth', () => {
		it('accepts the auth', async function () {
			const { status, data } = await agent.token.post({
				grant_type: 'foo',
				client_id: 'client-post',
				client_secret: 'secret'
			});
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('accepts the auth (but client configured with basic)', async function () {
			const { status, data } = await agent.token.post({
				grant_type: 'foo',
				client_id: 'client-basic',
				client_secret: 'secret'
			});
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('rejects invalid secrets', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const { error } = await agent.token.post({
				grant_type: 'foo',
				client_id: 'client-post',
				client_secret: 'invalid'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'invalid secret provided'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('requires the client_secret to be sent', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const { error } = await agent.token.post({
				grant_type: 'foo',
				client_id: 'client-post',
				client_secret: ''
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'the provided authentication mechanism does not match the registered client authentication method'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('rejects expired secrets', async function () {
			const { error } = await agent.token.post({
				grant_type: 'foo',
				client_id: 'secret-expired-basic',
				client_secret: 'secret'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_client',
				error_description:
					'could not authenticate the client - its client secret is expired'
			});
		});
	});

	describe('client_secret_jwt auth', () => {
		let key;

		beforeEach(async function () {
			key = await importJWK(
				(
					await Client.find('client-jwt-secret')
				).symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]
			);
		});

		it('accepts the auth', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{ expiresIn: 60 }
			);

			const { status, data } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		describe('additional audience values', () => {
			it('accepts the auth when aud is an array', async function () {
				const assertion = await JWT.sign(
					{
						jti: nanoid(),
						aud: [ISSUER],
						sub: 'client-jwt-secret',
						iss: 'client-jwt-secret'
					},
					key,
					'HS256',
					{ expiresIn: 60 }
				);

				const { status, data } = await agent.token.post({
					client_assertion: assertion,
					grant_type: 'foo',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				});
				expect(status).toBe(200);
				expect(data).toEqual(tokenAuthSucceeded);
			});

			it('accepts the auth when aud is the token endpoint', async function () {
				for (const aud of [ISSUER + '/token', [ISSUER + '/token']]) {
					const assertion = await JWT.sign(
						{
							jti: nanoid(),
							aud,
							sub: 'client-jwt-secret',
							iss: 'client-jwt-secret'
						},
						key,
						'HS256',
						{ expiresIn: 60 }
					);

					const { status, data } = await agent.token.post({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					});
					expect(status).toBe(200);
					expect(data).toEqual(tokenAuthSucceeded);
				}
			});

			it('accepts the auth when aud is the token endpoint at another endpoint', async function () {
				for (const aud of [ISSUER + '/token', [ISSUER + '/token']]) {
					const assertion = await JWT.sign(
						{
							jti: nanoid(),
							aud,
							sub: 'client-jwt-secret',
							iss: 'client-jwt-secret'
						},
						key,
						'HS256',
						{ expiresIn: 60 }
					);

					const { status, data } = await agent.token.introspect.post({
						client_assertion: assertion,
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
						token: 'foo'
					});
					expect(status).toBe(200);
					expect(data).toEqual(introspectionAuthSucceeded);
				}
			});

			it('accepts the auth when aud is the url of another endpoint it is used at', async function () {
				for (const aud of [
					ISSUER + '/token/introspect',
					[ISSUER + '/token/introspect']
				]) {
					const assertion = await JWT.sign(
						{
							jti: nanoid(),
							aud,
							sub: 'client-jwt-secret',
							iss: 'client-jwt-secret'
						},
						key,
						'HS256',
						{ expiresIn: 60 }
					);

					const { status, data } = await agent.token.introspect.post({
						client_assertion: assertion,
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
						token: 'foo'
					});
					expect(status).toBe(200);
					expect(data).toEqual(introspectionAuthSucceeded);
				}
			});
		});

		it('rejects the auth if this is actually a none-client', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-none',
					iss: 'client-none'
				},
				key,
				'HS256',
				{ expiresIn: 60 }
			);

			await agent.token.post({
				client_id: 'client-none',
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'the provided authentication mechanism does not match the registered client authentication method'
				})
			);
		});

		it('rejects the auth if authorization header is also present', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{ expiresIn: 60 }
			);

			const { error } = await agent.token.post(
				{
					client_assertion: assertion,
					grant_type: 'foo',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-basic',
						'secret'
					)
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'client authentication must only be provided using one mechanism'
			});
		});

		it('rejects the auth if client secret is also present', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{ expiresIn: 60 }
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
				client_secret: 'foo'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'client authentication must only be provided using one mechanism'
			});
		});

		it('rejects malformed assertions', async function () {
			const { error } = await agent.token.post({
				client_id: 'client-jwt-secret',
				client_assertion:
					'.eyJzdWIiOiJjbGllbnQtand0LXNlY3JldCIsImFsZyI6IkhTMjU2In0.',
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'invalid client_assertion format'
			});
		});

		it('exp must be set', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret',
					exp: ''
				},
				key,
				'HS256',
				{
					// expiresIn: 60
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'expiration must be specified in the client_assertion JWT'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('aud must be set', async function () {
			const spy = mock();
			provider.once('grant.error', spy);
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{
					expiresIn: 60
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'aud (JWT audience) must be provided in the client_assertion JWT'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('jti must be set', async function () {
			const spy = mock();
			provider.once('grant.error', spy);
			const assertion = await JWT.sign(
				{
					// jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{
					expiresIn: 60
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'unique jti (JWT ID) must be provided in the client_assertion JWT'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('iss must be set', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret'
					// iss: 'client-jwt-secret',
				},
				key,
				'HS256',
				{
					expiresIn: 60
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'iss (JWT issuer) must be provided in the client_assertion JWT'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('sub must be set', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					// sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{
					expiresIn: 60
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'sub (JWT subject) must be provided in the client_assertion JWT'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('iss must be the client id', async function () {
			const spy = mock();
			provider.once('grant.error', spy);

			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'not equal to clientid'
				},
				key,
				'HS256',
				{
					expiresIn: 60
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'iss (JWT issuer) must be the client_id'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('checks for mismatch in client_assertion client_id and body client_id', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{ expiresIn: 60 }
			);
			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_id: 'mismatching-client-id',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'subject of client_assertion must be the same as client_id provided in the body'
			});
		});

		it('requires client_assertion_type', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{
					expiresIn: 60
				}
			);
			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo'
				// client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'client_assertion_type must be provided'
			});
		});

		it('requires client_assertion_type of specific value', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{
					expiresIn: 60
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type: 'urn:ietf:mycustom'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'client_assertion_type must have value urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
		});

		it('rejects invalid assertions', async function () {
			const { error } = await agent.token.post({
				client_assertion: 'this.notatall.valid',
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'invalid client_assertion format'
			});
		});

		it('rejects valid format and signature but expired/invalid jwts', async function () {
			const spy = mock();
			provider.once('grant.error', spy);
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				key,
				'HS256',
				{
					expiresIn: -300
				}
			);
			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'jwt expired'
				})
			);
			expect(error.status).toBe(401);
			expect(error.value).toEqual(tokenAuthRejected);
		});

		it('rejects assertions when the secret is expired', async function () {
			const key = await importJWK(
				(
					await provider.Client.find('secret-expired-jwt')
				).symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]
			);
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'secret-expired-jwt',
					iss: 'secret-expired-jwt'
				},
				key,
				'HS256',
				{
					expiresIn: -1
				}
			);

			const { error } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_client',
				error_description:
					'could not authenticate the client - its client secret used for the client_assertion is expired'
			});
		});

		describe('JTI uniqueness', () => {
			it('reused jtis must be rejected', async function () {
				const spy = mock();
				provider.once('grant.error', spy);
				const assertion = await JWT.sign(
					{
						jti: nanoid(),
						aud: ISSUER,
						sub: 'client-jwt-secret',
						iss: 'client-jwt-secret'
					},
					key,
					'HS256',
					{
						expiresIn: 60
					}
				);

				const { status, data } = await agent.token.post({
					client_assertion: assertion,
					grant_type: 'foo',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				});
				expect(status).toBe(200);
				expect(data).toEqual(tokenAuthSucceeded);

				const { error } = await agent.token.post({
					client_assertion: assertion,
					grant_type: 'foo',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				});
				expect(spy).toBeCalledTimes(1);
				expect(spy).toBeCalledWith(
					expect.objectContaining({
						error_detail: 'client assertion tokens must only be used once'
					})
				);
				expect(error.status).toBe(401);
				expect(error.value).toEqual(tokenAuthRejected);
			});
		});

		describe('when token_endpoint_auth_signing_alg is set on the client', () => {
			beforeEach(async function () {
				(await Client.find('client-jwt-secret')).tokenEndpointAuthSigningAlg =
					'HS384';
			});
			afterEach(async function () {
				delete (await Client.find('client-jwt-secret'))
					.tokenEndpointAuthSigningAlg;
			});

			it('rejects signatures with different algorithm', async function () {
				const spy = mock();
				provider.once('grant.error', spy);

				const assertion = await JWT.sign(
					{
						jti: nanoid(),
						aud: ISSUER,
						sub: 'client-jwt-secret',
						iss: 'client-jwt-secret'
					},
					key,
					'HS256',
					{
						expiresIn: 60
					}
				);

				const { error } = await agent.token.post({
					client_assertion: assertion,
					grant_type: 'foo',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				});
				expect(spy).toBeCalledTimes(1);
				expect(spy).toBeCalledWith(
					expect.objectContaining({
						error_detail: 'alg mismatch'
					})
				);
				expect(error.status).toBe(401);
				expect(error.value).toEqual(tokenAuthRejected);
			});
		});
	});

	describe('private_key_jwt auth', () => {
		const privateKey = createPrivateKey({ format: 'jwk', key: clientKey });

		it('accepts the auth', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-key',
					iss: 'client-jwt-key'
				},
				privateKey,
				'RS256',
				{
					expiresIn: 60
				}
			);

			const { status, data } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('accepts client assertions issued within acceptable system clock skew', async function () {
			const assertion = await JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-key',
					iss: 'client-jwt-key',
					iat: Math.ceil(Date.now() / 1000) + 5
				},
				privateKey,
				'RS256',
				{
					expiresIn: 60
				}
			);

			const { status, data } = await agent.token.post({
				client_assertion: assertion,
				grant_type: 'foo',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});
	});

	describe.skip('tls_client_auth auth', () => {
		it('accepts the auth', async function () {
			const { status, data } = await agent.token.post(
				{
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				},
				{
					headers: {
						'x-ssl-client-cert': rsacrt.raw.toString('base64'),
						'x-ssl-client-verify': 'SUCCESS',
						'x-ssl-client-san-dns': 'rp.example.com'
					}
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual(tokenAuthSucceeded);
		});

		it('fails the auth when getCertificate() does not return a cert', function () {
			return this.agent
				.post(route)
				.send({
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('fails the auth when certificateAuthorized() fails', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.set('x-ssl-client-verify', 'FAILED: self signed certificate')
				.set('x-ssl-client-san-dns', 'rp.example.com')
				.send({
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('fails the auth when certificateSubjectMatches() return false', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.set('x-ssl-client-verify', 'SUCCESS')
				.set('x-ssl-client-san-dns', 'foobarbaz')
				.send({
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});
	});

	describe.skip('self_signed_tls_client_auth auth', () => {
		it('accepts the auth [1/2]', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('accepts the auth [2/2]', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', eccrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('fails the auth when x-ssl-client-cert is not passed by the proxy', function () {
			return this.agent
				.post(route)
				.send({
					client_id: 'client-self-signed-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('fails the auth when x-ssl-client-cert does not match the registered ones', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', eccrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls-rsa',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('handles rotation of stale jwks', function () {
			mock('https://client.example.com')
				.intercept({
					path: '/jwks'
				})
				.reply(200, JSON.stringify(mtlsKeys));

			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls-jwks_uri',
					grant_type: 'foo'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});
	});
});
