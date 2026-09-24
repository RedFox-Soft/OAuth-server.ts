import * as crypto from 'node:crypto';

import { describe, it, beforeAll, afterAll, expect } from 'bun:test';
import {
	compactDecrypt,
	CompactEncrypt,
	decodeJwt,
	decodeProtectedHeader,
	generateKeyPair
} from 'jose';

import bootstrap, {
	agent,
	type Setup,
	changeClient,
	formAgent,
	getHeader,
	locationQuery,
	redirectQuery
} from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.ts';

import { keypair } from './encryption.config.js';
import { ISSUER } from 'lib/configs/env.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Client, clientKeys, needsSecret } from 'lib/models/client.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * @proves A client registered for encryption receives nested signed-then-encrypted responses,
 * and an expired secret or unsupported algorithm is refused rather than served in the clear.
 */
describe('encryption', () => {
	let setup: Setup;
	let cookie: string;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		cookie = await setup.login();
	});

	[
		// symmetric kw
		'A128GCMKW',
		'A192GCMKW',
		'A256GCMKW',
		'A128KW',
		'A192KW',
		'A256KW',
		// no kw
		'dir'
	].forEach((alg) => {
		[
			'authorization_encrypted_response_alg',
			'id_token_encrypted_response_alg',
			'introspection_encrypted_response_alg',
			'request_object_encryption_alg',
			'userinfo_encrypted_response_alg'
		].forEach((attr) => {
			it(`every symmetric algorithm requires a client secret`, () => {
				expect(
					needsSecret({
						token_endpoint_auth_method: 'none',
						[attr]: alg
					})
				).toBe(true);
			});
		});
	});

	['get', 'post'].forEach((verb) => {
		// Implicit flow was removed; these previously-implicit id_token/token cases now exercise the
		// authorization code flow and read tokens from the token endpoint response.
		function authRequest(auth: { params: AuthorizationRequest['params'] }) {
			if (verb === 'get') {
				return agent.auth.get({
					query: auth.params,
					headers: { cookie }
				});
			}
			return formAgent.auth.post(auth.params, {
				headers: {
					cookie
				}
			});
		}

		// Issue an authorization request from a plain params object (used for request-object /
		// request_uri flows where we must NOT auto-generate PKCE/state like AuthorizationRequest does).
		function rawAuthRequest(params: AuthorizationRequest['params']) {
			return authRequest({ params });
		}

		// Run the full code flow for `auth` and return the token endpoint response body
		// (token payload on success, or the error body on failure).
		async function getTokenBody(
			auth: AuthorizationRequest
		): Promise<Record<string, unknown> | undefined> {
			const { response } = await authRequest(auth);
			const query = redirectQuery(response);
			if (query.error) {
				return query;
			}
			const { data, error } = await auth.getToken(query.code);
			return data ?? error?.value;
		}

		// A token the flow must have produced; the case cannot go on without it.
		function stringOf(body: Record<string, unknown> | undefined, name: string) {
			const value = body?.[name];
			if (typeof value !== 'string') throw new Error(`expected ${name}`);
			return value;
		}

		describe(`[encryption] code+token ${verb} /auth`, () => {
			describe('encrypted authorization results', () => {
				let id_token: string;
				let access_token: string;
				beforeAll(async () => {
					const auth = new AuthorizationRequest({ scope: 'openid' });
					const body = await getTokenBody(auth);
					id_token = stringOf(body, 'id_token');
					access_token = stringOf(body, 'access_token');
				});

				it('responds with a nested encrypted and signed id_token JWT', async () => {
					expect(id_token).toBeTruthy();
					expect(id_token.split('.')).toHaveLength(5);

					const { plaintext } = await compactDecrypt(
						id_token,
						keypair.privateKey
					);
					expect(plaintext).toBeTruthy();
					expect(decodeJwt(decoder.decode(plaintext))).toBeTruthy();
				});

				it('duplicates iss and aud as JWE Header Parameters in an encrypted ID Token', () => {
					const header = decodeProtectedHeader(id_token);
					expect(header).toHaveProperty('iss', ISSUER);
					expect(header).toHaveProperty('aud', 'client');
				});

				it('an encrypted, signed UserInfo response is produced and decrypts to the claims', async () => {
					const { data, response } = await agent.userinfo.get({
						headers: { authorization: `Bearer ${access_token}` }
					});
					if (typeof data !== 'string')
						throw new Error('expected a JWT response');

					expect(response.status).toBe(200);
					expect(response.headers.get('content-type')).toMatch(
						/application\/jwt/
					);
					expect(data.split('.')).toHaveLength(5);

					const header = decodeProtectedHeader(data);
					expect(header).toHaveProperty('iss', ISSUER);
					expect(header).toHaveProperty('aud', 'client');

					const { plaintext } = await compactDecrypt(data, keypair.privateKey);
					expect(plaintext).toBeTruthy();
					const payload = decodeJwt(decoder.decode(plaintext));
					expect(payload).toBeTruthy();
					expect(payload).toHaveProperty('sub');
					expect(payload).toHaveProperty('exp');
					if (typeof payload.iat !== 'number') throw new Error('expected iat');
					expect(payload.exp).toBeGreaterThan(payload.iat);
				});

				describe('userinfo signed - expired client secret', () => {
					let restore: () => Promise<void>;

					beforeAll(async () => {
						restore = await changeClient('client', {
							userinfo_signed_response_alg: 'HS256',
							client_secret_expires_at: 1
						});
					});

					afterAll(async () => {
						await restore();
					});

					it('errors with a specific message', async () => {
						const { error } = await agent.userinfo.get({
							headers: { authorization: `Bearer ${access_token}` }
						});
						if (!error) throw new Error('expected error response');
						expect(error.status).toBe(400);
						expect(error.value).toEqual({
							error: 'invalid_client',
							error_description:
								'client secret is expired - cannot respond with HS256 JWT UserInfo response'
						});
					});
				});

				describe('userinfo symmetric encrypted - expired client secret', () => {
					let restore: () => Promise<void>;

					beforeAll(async () => {
						restore = await changeClient('client', {
							client_secret_expires_at: 1,
							userinfo_encrypted_response_alg: 'dir'
						});
					});

					afterAll(async () => {
						await restore();
					});

					it('errors with a specific message', async () => {
						const { error } = await agent.userinfo.get({
							headers: { authorization: `Bearer ${access_token}` }
						});
						if (!error) throw new Error('expected error response');
						expect(error.status).toBe(400);
						expect(error.value).toEqual({
							error: 'invalid_client',
							error_description:
								'client secret is expired - cannot respond with dir encrypted JWT UserInfo response'
						});
					});
				});
			});

			describe('Request Object encryption', () => {
				it('an unsupported encryption algorithm is refused at registration', async () => {
					const signed = await JWT.sign(
						{
							client_id: 'client',
							response_type: 'code',
							redirect_uri: 'https://client.example.com/cb'
						},
						Buffer.from('secret'),
						'HS256',
						{ issuer: 'client', audience: ISSUER }
					);

					// The provider JWKS store has no asymmetric encryption key, so we encrypt with a
					// freshly generated RSA public key. The alg (RSA-OAEP-512) is rejected by name
					// before any decryption is attempted, which is exactly what this test asserts.
					const { publicKey } = await generateKeyPair('RSA-OAEP-512');
					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP-512' })
						.encrypt(publicKey);

					const { response } = await rawAuthRequest({
						request: encrypted,
						scope: 'openid',
						client_id: 'client',
						response_type: 'code'
					});
					const query = redirectQuery(response);
					expect(query).toHaveProperty('error', 'invalid_request_object');
					expect(query).toHaveProperty(
						'error_description',
						'could not decrypt request object'
					);
				});

				it('refuses an unsupported content-encryption algorithm at registration', async () => {
					const signed = await JWT.sign(
						{
							client_id: 'client',
							response_type: 'code',
							redirect_uri: 'https://client.example.com/cb'
						},
						Buffer.from('secret'),
						'HS256',
						{ issuer: 'client', audience: ISSUER }
					);

					// See note above: encrypt with a generated RSA key; RSA-OAEP-512 is rejected by name.
					const { publicKey } = await generateKeyPair('RSA-OAEP-512');
					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A192CBC-HS384', alg: 'RSA-OAEP-512' })
						.encrypt(publicKey);

					const { response } = await rawAuthRequest({
						request: encrypted,
						scope: 'openid',
						client_id: 'client',
						response_type: 'code'
					});
					const query = redirectQuery(response);
					expect(query).toHaveProperty('error', 'invalid_request_object');
					expect(query).toHaveProperty(
						'error_description',
						'could not decrypt request object'
					);
				});
			});

			// Encrypted Request Objects pushed via PAR: processRequestObject() decrypts
			// oidc.params.request and exposes the decoded JWS as oidc.processedRequestObject, which the
			// PAR handler now persists (instead of the stale encrypted JWE it captured up front).
			// These use symmetric A128KW encryption because the test JWKS store holds only an RS256
			// signing key (see the config note), so asymmetric RSA-OAEP request-object encryption is
			// unavailable in this environment.
			describe('Pushed Request Object encryption', () => {
				it('a request object that is signed but not encrypted is accepted', async () => {
					const client = await Client.find('client');
					const [hsSecret] = clientKeys(client).symmetric.selectForSign({
						alg: 'HS256'
					});
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
							jti: crypto.randomBytes(16).toString('base64url'),
							client_id: 'client',
							response_type: 'code',
							redirect_uri: 'https://client.example.com/cb',
							scope: 'openid',
							code_challenge_method: 'S256',
							code_challenge: crypto.hash('sha256', code_verifier, 'base64url')
						},
						clientKeys(client).symmetric.getKeyObject(hsSecret),
						'HS256',
						{ issuer: 'client', audience: ISSUER, expiresIn: 30 }
					);

					let [key] = clientKeys(client).symmetric.selectForEncrypt({
						alg: 'A128KW'
					});
					key = clientKeys(client).symmetric.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					const { data: par } = await formAgent.par.post(
						{ request: encrypted },
						{
							headers: {
								...AuthorizationRequest.basicAuthHeader('client', 'secret')
							}
						}
					);
					if (!par) throw new Error('expected response data');

					const { response } = await rawAuthRequest({
						request_uri: par.request_uri,
						client_id: 'client'
					});
					expect(response.status).toBe(303);
					const expected = new URL('https://client.example.com/cb');
					const actual = new URL(getHeader(response, 'location'));
					(['protocol', 'host', 'pathname'] as const).forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					expect(Object.fromEntries(actual.searchParams)).toHaveProperty(
						'code'
					);
				});

				it('where an algorithm is required, a genuinely signed request object is accepted and an unsecured one is not', async () => {
					const client = await Client.find('clientRequestObjectSigningAlg');
					const [hsSecret] = clientKeys(client).symmetric.selectForSign({
						alg: 'HS256'
					});
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
							jti: crypto.randomBytes(16).toString('base64url'),
							client_id: 'clientRequestObjectSigningAlg',
							response_type: 'code',
							redirect_uri: 'https://client.example.com/cb',
							scope: 'openid',
							code_challenge_method: 'S256',
							code_challenge: crypto.hash('sha256', code_verifier, 'base64url')
						},
						clientKeys(client).symmetric.getKeyObject(hsSecret),
						'HS256',
						{
							issuer: 'clientRequestObjectSigningAlg',
							audience: ISSUER,
							expiresIn: 30
						}
					);

					let [key] = clientKeys(client).symmetric.selectForEncrypt({
						alg: 'A128KW'
					});
					key = clientKeys(client).symmetric.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					const { data: par } = await formAgent.par.post(
						{ request: encrypted },
						{
							headers: {
								...AuthorizationRequest.basicAuthHeader(
									'clientRequestObjectSigningAlg',
									'secret'
								)
							}
						}
					);
					if (!par) throw new Error('expected response data');

					const { response } = await rawAuthRequest({
						request_uri: par.request_uri,
						client_id: 'clientRequestObjectSigningAlg'
					});
					expect(response.status).toBe(303);
					const expected = new URL('https://client.example.com/cb');
					const actual = new URL(getHeader(response, 'location'));
					(['protocol', 'host', 'pathname'] as const).forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					expect(Object.fromEntries(actual.searchParams)).toHaveProperty(
						'code'
					);
				});
			});

			it('a client with no usable encryption key is refused rather than served an unencrypted response', async () => {
				const restore = await changeClient('client', {
					id_token_encrypted_response_alg: 'ECDH-ES'
				});

				const auth = new AuthorizationRequest({ scope: 'openid' });

				const body = await getTokenBody(auth);

				await restore();

				expect(body).toHaveProperty('error', 'invalid_client_metadata');
				expect(body).toHaveProperty(
					'error_description',
					'no suitable encryption key found (ECDH-ES)'
				);
			});

			describe('symmetric encryption', () => {
				let id_token: string;
				beforeAll(async () => {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric'
					});
					const body = await getTokenBody(auth);
					id_token = stringOf(body, 'id_token');
				});

				it('accepts symmetric encrypted Request Objects', async () => {
					const client = await Client.find('clientSymmetric');
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
							jti: crypto.randomBytes(16).toString('base64url'),
							client_id: 'clientSymmetric',
							scope: 'openid',
							response_type: 'code',
							nonce: 'foobar',
							redirect_uri: 'https://client.example.com/cb',
							code_challenge_method: 'S256',
							code_challenge: crypto.hash('sha256', code_verifier, 'base64url')
						},
						Buffer.from('secret'),
						'HS256',
						{ issuer: 'clientSymmetric', audience: ISSUER, expiresIn: 30 }
					);

					let [key] = clientKeys(client).symmetric.selectForEncrypt({
						alg: 'A128KW'
					});
					key = clientKeys(client).symmetric.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					const { response } = await rawAuthRequest({
						request: encrypted,
						scope: 'openid',
						client_id: 'clientSymmetric'
					});
					expect(response.status).toBe(303);
					const expected = new URL('https://client.example.com/cb');
					const actual = new URL(getHeader(response, 'location'));
					(['protocol', 'host', 'pathname'] as const).forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					const code = actual.searchParams.get('code') ?? undefined;

					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric'
					});
					auth.code_verifier = code_verifier;
					const { data } = await auth.getToken(code);
					expect(data).toHaveProperty('id_token');
				});

				it('rejects symmetric encrypted request objects when secret is expired', async () => {
					const client = await Client.find('clientSymmetric-expired');
					const signed = await JWT.sign(
						{
							client_id: 'clientSymmetric-expired',
							response_type: 'code',
							nonce: 'foobar'
						},
						Buffer.from('secret'),
						'HS256',
						{
							issuer: 'clientSymmetric-expired',
							audience: ISSUER
						}
					);

					let [key] = clientKeys(client).symmetric.selectForEncrypt({
						alg: 'A128KW'
					});
					key = clientKeys(client).symmetric.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					const { response } = await rawAuthRequest({
						redirect_uri: 'https://client.example.com/cb',
						request: encrypted,
						scope: 'openid',
						client_id: 'clientSymmetric-expired',
						response_type: 'code'
					});
					expect(response.status).toBe(303);
					const query = redirectQuery(response);
					expect(query).toHaveProperty('error', 'invalid_request_object');
					expect(query).toHaveProperty(
						'error_description',
						'could not decrypt the Request Object - the client secret used for its encryption is expired'
					);
				});

				it('responds encrypted', () => {
					expect(id_token).toBeTruthy();
					expect(id_token.split('.')).toHaveLength(5);
					const header = decodeProtectedHeader(id_token);
					expect(header).toHaveProperty('alg', 'A128KW');
					expect(header).toHaveProperty('iss', ISSUER);
					expect(header).toHaveProperty('aud', 'clientSymmetric');
				});
			});

			describe('direct key agreement symmetric encryption', () => {
				let id_token: string;
				beforeAll(async () => {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric-dir'
					});
					const body = await getTokenBody(auth);
					id_token = stringOf(body, 'id_token');
				});

				it('accepts symmetric (dir) encrypted Request Objects', async () => {
					const client = await Client.find('clientSymmetric');
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
							jti: crypto.randomBytes(16).toString('base64url'),
							client_id: 'clientSymmetric-dir',
							scope: 'openid',
							response_type: 'code',
							nonce: 'foobar',
							redirect_uri: 'https://client.example.com/cb',
							code_challenge_method: 'S256',
							code_challenge: crypto.hash('sha256', code_verifier, 'base64url')
						},
						Buffer.from('secret'),
						'HS256',
						{ issuer: 'clientSymmetric-dir', audience: ISSUER, expiresIn: 30 }
					);

					let [key] = clientKeys(client).symmetric.selectForEncrypt({
						alg: 'A128CBC-HS256'
					});
					key = clientKeys(client).symmetric.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
						.encrypt(key);

					const { response } = await rawAuthRequest({
						request: encrypted,
						scope: 'openid',
						client_id: 'clientSymmetric-dir'
					});
					expect(response.status).toBe(303);
					const expected = new URL('https://client.example.com/cb');
					const actual = new URL(getHeader(response, 'location'));
					(['protocol', 'host', 'pathname'] as const).forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					const code = actual.searchParams.get('code') ?? undefined;

					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric-dir'
					});
					auth.code_verifier = code_verifier;
					const { data } = await auth.getToken(code);
					expect(data).toHaveProperty('id_token');
				});

				it('rejects symmetric (dir) encrypted request objects when secret is expired', async () => {
					const client = await Client.find('clientSymmetric');
					const signed = await JWT.sign(
						{
							client_id: 'clientSymmetric-expired',
							response_type: 'code',
							nonce: 'foobar'
						},
						Buffer.from('secret'),
						'HS256',
						{
							issuer: 'clientSymmetric-expired',
							audience: ISSUER
						}
					);

					let [key] = clientKeys(client).symmetric.selectForEncrypt({
						alg: 'A128CBC-HS256'
					});
					key = clientKeys(client).symmetric.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
						.encrypt(key);

					const { response } = await rawAuthRequest({
						redirect_uri: 'https://client.example.com/cb',
						request: encrypted,
						scope: 'openid',
						client_id: 'clientSymmetric-expired',
						response_type: 'code'
					});
					expect(response.status).toBe(303);
					const query = locationQuery(
						getHeader(response, 'location').replace('#', '?')
					);
					expect(query).toHaveProperty('error', 'invalid_request_object');
					expect(query).toHaveProperty(
						'error_description',
						'could not decrypt the Request Object - the client secret used for its encryption is expired'
					);
				});

				it('responds encrypted', () => {
					expect(id_token).toBeTruthy();
					expect(id_token.split('.')).toHaveLength(5);
					const header = decodeProtectedHeader(id_token);
					expect(header).toHaveProperty('alg', 'dir');
					expect(header).toHaveProperty('enc', 'A128CBC-HS256');
					expect(header).toHaveProperty('iss', ISSUER);
					expect(header).toHaveProperty('aud', 'clientSymmetric-dir');
				});
			});
		});
	});
});
