import * as url from 'node:url';
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
	jsonToFormUrlEncoded,
	type Setup
} from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.ts';

import { keypair } from './encryption.config.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Client } from 'lib/models/client.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
			it(`symmetric ${attr} makes client secret mandatory (${alg})`, () => {
				expect(
					Client.needsSecret({
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
		function authRequest(auth) {
			if (verb === 'get') {
				return agent.auth.get({
					query: auth.params,
					headers: { cookie }
				});
			}
			return agent.auth.post(jsonToFormUrlEncoded(auth.params), {
				headers: {
					cookie,
					['content-type']: 'application/x-www-form-urlencoded'
				}
			});
		}

		// Issue an authorization request from a plain params object (used for request-object /
		// request_uri flows where we must NOT auto-generate PKCE/state like AuthorizationRequest does).
		function rawAuthRequest(params) {
			return authRequest({ params });
		}

		// Run the full code flow for `auth` and return the token endpoint response body
		// (token payload on success, or the error body on failure).
		async function getTokenBody(auth) {
			const { response } = await authRequest(auth);
			const location = response.headers.get('location');
			const { query } = url.parse(location, true);
			if (query.error) {
				return query;
			}
			const { data, error } = await auth.getToken(query.code);
			return data ?? error?.value;
		}

		describe(`[encryption] code+token ${verb} /auth`, () => {
			describe('encrypted authorization results', () => {
				let id_token;
				let access_token;
				beforeAll(async () => {
					const auth = new AuthorizationRequest({ scope: 'openid' });
					const body = await getTokenBody(auth);
					id_token = body.id_token;
					access_token = body.access_token;
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

				it('handles nested encrypted and signed userinfo JWT', async () => {
					const { data, response } = await agent.userinfo.get({
						headers: { authorization: `Bearer ${access_token}` }
					});
					if (!data) throw new Error('expected response data');

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
					expect(payload.exp).toBeGreaterThan(payload.iat);
				});

				describe('userinfo signed - expired client secret', () => {
					beforeAll(async () => {
						const client = await Client.find('client');
						client.userinfoSignedResponseAlg = 'HS256';
						client.clientSecretExpiresAt = 1;
					});

					afterAll(async () => {
						const client = await Client.find('client');
						client.userinfoSignedResponseAlg = 'RS256';
						client.clientSecretExpiresAt = 0;
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
					beforeAll(async () => {
						const client = await Client.find('client');
						client.clientSecretExpiresAt = 1;
						client.userinfoEncryptedResponseAlg = 'dir';
					});

					afterAll(async () => {
						const client = await Client.find('client');
						client.clientSecretExpiresAt = 0;
						client.userinfoEncryptedResponseAlg = 'RSA-OAEP';
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
				it('handles enc unsupported algs', async () => {
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
					const { query } = url.parse(response.headers.get('location'), true);
					expect(query).toHaveProperty('error', 'invalid_request_object');
					expect(query).toHaveProperty(
						'error_description',
						'could not decrypt request object'
					);
				});

				it('handles enc unsupported encs', async () => {
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
					const { query } = url.parse(response.headers.get('location'), true);
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
				it('works signed', async () => {
					const client = await Client.find('client');
					const [hsSecret] = client.symmetricKeyStore.selectForSign({
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
						client.symmetricKeyStore.getKeyObject(hsSecret),
						'HS256',
						{ issuer: 'client', audience: ISSUER, expiresIn: 30 }
					);

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128KW'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					const { data: par } = await agent.par.post(
						jsonToFormUrlEncoded({ request: encrypted }),
						{
							headers: {
								['content-type']: 'application/x-www-form-urlencoded',
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
					const expected = url.parse('https://client.example.com/cb', true);
					const actual = url.parse(response.headers.get('location'), true);
					['protocol', 'host', 'pathname'].forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					expect(actual.query).toHaveProperty('code');
				});

				it('works with signed by other than none when an alg is required', async () => {
					const client = await Client.find('clientRequestObjectSigningAlg');
					const [hsSecret] = client.symmetricKeyStore.selectForSign({
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
						client.symmetricKeyStore.getKeyObject(hsSecret),
						'HS256',
						{
							issuer: 'clientRequestObjectSigningAlg',
							audience: ISSUER,
							expiresIn: 30
						}
					);

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128KW'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					const { data: par } = await agent.par.post(
						jsonToFormUrlEncoded({ request: encrypted }),
						{
							headers: {
								['content-type']: 'application/x-www-form-urlencoded',
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
					const expected = url.parse('https://client.example.com/cb', true);
					const actual = url.parse(response.headers.get('location'), true);
					['protocol', 'host', 'pathname'].forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					expect(actual.query).toHaveProperty('code');
				});
			});

			it('handles when no suitable encryption key is found', async () => {
				const client = await Client.find('client');

				client.idTokenEncryptedResponseAlg = 'ECDH-ES';

				const auth = new AuthorizationRequest({ scope: 'openid' });

				const body = await getTokenBody(auth);

				client.idTokenEncryptedResponseAlg = 'RSA-OAEP';

				expect(body).toHaveProperty('error', 'invalid_client_metadata');
				expect(body).toHaveProperty(
					'error_description',
					'no suitable encryption key found (ECDH-ES)'
				);
			});

			describe('symmetric encryption', () => {
				let id_token;
				beforeAll(async () => {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric'
					});
					const body = await getTokenBody(auth);
					id_token = body.id_token;
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

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128KW'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					const { response } = await rawAuthRequest({
						request: encrypted,
						scope: 'openid',
						client_id: 'clientSymmetric'
					});
					expect(response.status).toBe(303);
					const expected = url.parse('https://client.example.com/cb', true);
					const actual = url.parse(response.headers.get('location'), true);
					['protocol', 'host', 'pathname'].forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					const code = actual.query.code;

					const auth = new AuthorizationRequest({
						code_verifier,
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

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128KW'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

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
					const { query } = url.parse(response.headers.get('location'), true);
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
				let id_token;
				beforeAll(async () => {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric-dir'
					});
					const body = await getTokenBody(auth);
					id_token = body.id_token;
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

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128CBC-HS256'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
						.encrypt(key);

					const { response } = await rawAuthRequest({
						request: encrypted,
						scope: 'openid',
						client_id: 'clientSymmetric-dir'
					});
					expect(response.status).toBe(303);
					const expected = url.parse('https://client.example.com/cb', true);
					const actual = url.parse(response.headers.get('location'), true);
					['protocol', 'host', 'pathname'].forEach((attr) => {
						expect(actual[attr]).toBe(expected[attr]);
					});
					const code = actual.query.code;

					const auth = new AuthorizationRequest({
						code_verifier,
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

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128CBC-HS256'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

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
					const { query } = url.parse(
						response.headers.get('location').replace('#', '?'),
						true
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
