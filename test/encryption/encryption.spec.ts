import * as url from 'node:url';
import * as crypto from 'node:crypto';

import { expect } from 'chai';
import {
	compactDecrypt,
	CompactEncrypt,
	decodeJwt,
	decodeProtectedHeader
} from 'jose';

import bootstrap from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.ts';

import { keypair } from './encryption.config.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const route = '/auth';

const decoder = new TextDecoder();
const encoder = new TextEncoder();

describe('encryption', () => {
	before(bootstrap(import.meta.url));

	before(function () {
		return this.login();
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
			it(`symmetric ${attr} makes client secret mandatory (${alg})`, function () {
				expect(
					provider.Client.needsSecret({
						token_endpoint_auth_method: 'none',
						[attr]: alg
					})
				).to.be.true;
			});
		});
	});

	['get', 'post'].forEach((verb) => {
		describe(`[encryption] IMPLICIT id_token+token ${verb} ${route}`, () => {
			describe('encrypted authorization results', () => {
				before(async function () {
					const auth = new AuthorizationRequest({ scope: 'openid' });

					const response = await this.getToken(auth, { verb });
					this.id_token = response.body.id_token;
					this.access_token = response.body.access_token;
				});

				it('responds with a nested encrypted and signed id_token JWT', async function () {
					expect(this.id_token).to.be.ok;
					expect(this.id_token.split('.')).to.have.lengthOf(5);

					const { plaintext } = await compactDecrypt(
						this.id_token,
						keypair.privateKey
					);
					expect(plaintext).to.be.ok;
					expect(decodeJwt(decoder.decode(plaintext))).to.be.ok;
				});

				it('duplicates iss and aud as JWE Header Parameters in an encrypted ID Token', function () {
					const header = decodeProtectedHeader(this.id_token);
					expect(header).to.have.property('iss').eql(ISSUER);
					expect(header).to.have.property('aud').eql('client');
				});

				it('handles nested encrypted and signed userinfo JWT', function (done) {
					this.agent
						.get('/me')
						.auth(this.access_token, { type: 'bearer' })
						.expect(200)
						.expect('content-type', /application\/jwt/)
						.expect((response) => {
							expect(response.text.split('.')).to.have.lengthOf(5);
						})
						.end(async (err, response) => {
							if (err) throw err;

							const header = decodeProtectedHeader(response.text);
							expect(header).to.have.property('iss').eql(ISSUER);
							expect(header).to.have.property('aud').eql('client');

							const { plaintext } = await compactDecrypt(
								response.text,
								keypair.privateKey
							);
							expect(plaintext).to.be.ok;
							const payload = decodeJwt(decoder.decode(plaintext));
							expect(payload).to.be.ok;
							expect(payload)
								.to.have.property('exp')
								.above(Date.now() / 1000);
							done();
						});
				});

				describe('userinfo signed - expired client secret', () => {
					before(async function () {
						const client = await provider.Client.find('client');
						client.userinfoSignedResponseAlg = 'HS256';
						client.clientSecretExpiresAt = 1;
					});

					after(async function () {
						const client = await provider.Client.find('client');
						client.userinfoSignedResponseAlg = 'RS256';
						client.clientSecretExpiresAt = 0;
					});

					it('errors with a specific message', function () {
						return this.agent
							.get('/me')
							.auth(this.access_token, { type: 'bearer' })
							.expect(400)
							.expect({
								error: 'invalid_client',
								error_description:
									'client secret is expired - cannot respond with HS256 JWT UserInfo response'
							});
					});
				});

				describe('userinfo symmetric encrypted - expired client secret', () => {
					before(async function () {
						const client = await provider.Client.find('client');
						client.clientSecretExpiresAt = 1;
						client.userinfoEncryptedResponseAlg = 'dir';
					});

					after(async function () {
						const client = await provider.Client.find('client');
						client.clientSecretExpiresAt = 0;
						client.userinfoEncryptedResponseAlg = 'RSA-OAEP';
					});

					it('errors with a specific message', function () {
						return this.agent
							.get('/me')
							.auth(this.access_token, { type: 'bearer' })
							.expect(400)
							.expect({
								error: 'invalid_client',
								error_description:
									'client secret is expired - cannot respond with dir encrypted JWT UserInfo response'
							});
					});
				});
			});

			describe('Request Object encryption', () => {
				it('handles enc unsupported algs', async function () {
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

					let [key] = i(provider).keystore.selectForEncrypt({
						kty: 'RSA',
						alg: 'RSA-OAEP-512'
					});
					key = i(provider).keystore.getKeyObject(key, true);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP-512' })
						.encrypt(key);

					return this.wrap({
						route,
						verb,
						auth: {
							request: encrypted,
							scope: 'openid',
							client_id: 'client',
							response_type: 'code'
						}
					}).expect((response) => {
						const { query } = url.parse(response.headers.location, true);
						expect(query).to.have.property('error', 'invalid_request_object');
						expect(query).to.have.property(
							'error_description',
							'could not decrypt request object'
						);
					});
				});

				it('handles enc unsupported encs', async function () {
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

					let [key] = i(provider).keystore.selectForEncrypt({
						kty: 'RSA',
						alg: 'RSA-OAEP-512'
					});
					key = i(provider).keystore.getKeyObject(key, true);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A192CBC-HS384', alg: 'RSA-OAEP-512' })
						.encrypt(key);

					return this.wrap({
						route,
						verb,
						auth: {
							request: encrypted,
							scope: 'openid',
							client_id: 'client',
							response_type: 'code'
						}
					}).expect((response) => {
						const { query } = url.parse(response.headers.location, true);
						expect(query).to.have.property('error', 'invalid_request_object');
						expect(query).to.have.property(
							'error_description',
							'could not decrypt request object'
						);
					});
				});
			});

			describe('Pushed Request Object encryption', () => {
				it('works signed', async function () {
					const client = await provider.Client.find('client');
					const [hsSecret] = client.symmetricKeyStore.selectForSign({
						alg: 'HS256'
					});
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
							client_id: 'client',
							response_type: 'code',
							redirect_uri: 'https://client.example.com/cb',
							scope: 'openid',
							code_challenge_method: 'S256',
							code_challenge: crypto.hash('sha256', code_verifier, 'base64url')
						},
						client.symmetricKeyStore.getKeyObject(hsSecret),
						'HS256',
						{ issuer: 'client', audience: ISSUER }
					);

					let [key] = i(provider).keystore.selectForEncrypt({
						kty: 'RSA',
						alg: 'RSA-OAEP'
					});
					key = i(provider).keystore.getKeyObject(key, true);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })
						.encrypt(key);

					const { body } = await this.agent
						.post('/request')
						.auth('client', 'secret')
						.type('form')
						.send({ request: encrypted });

					return this.wrap({
						route,
						verb,
						auth: {
							request_uri: body.request_uri,
							client_id: 'client'
						}
					})
						.expect(303)
						.expect((response) => {
							const expected = url.parse('https://client.example.com/cb', true);
							const actual = url.parse(response.headers.location, true);
							['protocol', 'host', 'pathname'].forEach((attr) => {
								expect(actual[attr]).to.equal(expected[attr]);
							});
							expect(actual.query).to.have.property('code');
						});
				});

				it('works with signed by other than none when an alg is required', async function () {
					const client = await provider.Client.find(
						'clientRequestObjectSigningAlg'
					);
					const [hsSecret] = client.symmetricKeyStore.selectForSign({
						alg: 'HS256'
					});
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
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
							audience: ISSUER
						}
					);

					let [key] = i(provider).keystore.selectForEncrypt({
						kty: 'RSA',
						alg: 'RSA-OAEP'
					});
					key = i(provider).keystore.getKeyObject(key, true);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })
						.encrypt(key);

					const { body } = await this.agent
						.post('/request')
						.auth('clientRequestObjectSigningAlg', 'secret')
						.type('form')
						.send({ request: encrypted });

					return this.wrap({
						route,
						verb,
						auth: {
							request_uri: body.request_uri,
							client_id: 'clientRequestObjectSigningAlg'
						}
					})
						.expect(303)
						.expect((response) => {
							const expected = url.parse('https://client.example.com/cb', true);
							const actual = url.parse(response.headers.location, true);
							['protocol', 'host', 'pathname'].forEach((attr) => {
								expect(actual[attr]).to.equal(expected[attr]);
							});
							expect(actual.query).to.have.property('code');
						});
				});
			});

			it('handles when no suitable encryption key is found', async function () {
				const client = await provider.Client.find('client');

				client.idTokenEncryptedResponseAlg = 'ECDH-ES';

				const auth = new AuthorizationRequest({ scope: 'openid' });

				const response = await this.getToken(auth, { verb });

				client.idTokenEncryptedResponseAlg = 'RSA-OAEP';

				expect(response.body).to.have.property(
					'error',
					'invalid_client_metadata'
				);
				expect(response.body).to.have.property(
					'error_description',
					'no suitable encryption key found (ECDH-ES)'
				);
			});

			describe('symmetric encryption', () => {
				before(async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric'
					});

					const response = await this.getToken(auth, { verb });
					this.id_token = response.body.id_token;
				});

				it('accepts symmetric encrypted Request Objects', async function () {
					const client = await provider.Client.find('clientSymmetric');
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
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
						{ issuer: 'clientSymmetric', audience: ISSUER }
					);

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128KW'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
						.encrypt(key);

					let code;
					await this.wrap({
						route,
						verb,
						auth: {
							request: encrypted,
							scope: 'openid',
							client_id: 'clientSymmetric'
						}
					})
						.expect(303)
						.expect((response) => {
							const { query } = url.parse(response.headers.location, true);
							code = query.code;
							const expected = url.parse('https://client.example.com/cb', true);
							const actual = url.parse(response.headers.location, true);
							['protocol', 'host', 'pathname'].forEach((attr) => {
								expect(actual[attr]).to.equal(expected[attr]);
							});
						});

					const auth = new AuthorizationRequest({
						code_verifier,
						scope: 'openid',
						client_id: 'clientSymmetric'
					});
					return auth.getToken(code).expect((response) => {
						expect(response.body).to.have.property('id_token');
					});
				});

				it('rejects symmetric encrypted request objects when secret is expired', async function () {
					const client = await provider.Client.find('clientSymmetric-expired');
					const signed = await JWT.sign(
						{
							client_id: 'clientSymmetric-expired',
							response_type: 'id_token',
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

					return this.wrap({
						route,
						verb,
						auth: {
							redirect_uri: 'https://client.example.com/cb',
							request: encrypted,
							scope: 'openid',
							client_id: 'clientSymmetric-expired',
							response_type: 'id_token'
						}
					})
						.expect(303)
						.expect((response) => {
							const { query } = url.parse(response.headers.location, true);
							expect(query).to.have.property('error', 'invalid_request_object');
							expect(query).to.have.property(
								'error_description',
								'could not decrypt the Request Object - the client secret used for its encryption is expired'
							);
						});
				});

				it('responds encrypted', function () {
					expect(this.id_token).to.be.ok;
					expect(this.id_token.split('.')).to.have.lengthOf(5);
					const header = decodeProtectedHeader(this.id_token);
					expect(header).to.have.property('alg', 'A128KW');
					expect(header).to.have.property('iss').eql(ISSUER);
					expect(header).to.have.property('aud').eql('clientSymmetric');
				});
			});

			describe('direct key agreement symmetric encryption', () => {
				before(async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						client_id: 'clientSymmetric-dir'
					});

					const response = await this.getToken(auth, { verb });
					this.id_token = response.body.id_token;
				});

				it('accepts symmetric (dir) encrypted Request Objects', async function () {
					const client = await provider.Client.find('clientSymmetric');
					const code_verifier = crypto.randomBytes(32).toString('base64url');
					const signed = await JWT.sign(
						{
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
						{ issuer: 'clientSymmetric-dir', audience: ISSUER }
					);

					let [key] = client.symmetricKeyStore.selectForEncrypt({
						alg: 'A128CBC-HS256'
					});
					key = client.symmetricKeyStore.getKeyObject(key);

					const encrypted = await new CompactEncrypt(encoder.encode(signed))
						.setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
						.encrypt(key);

					let code;
					await this.wrap({
						route,
						verb,
						auth: {
							request: encrypted,
							scope: 'openid',
							client_id: 'clientSymmetric-dir'
						}
					})
						.expect(303)
						.expect((response) => {
							const expected = url.parse('https://client.example.com/cb', true);
							const actual = url.parse(response.headers.location, true);
							['protocol', 'host', 'pathname'].forEach((attr) => {
								expect(actual[attr]).to.equal(expected[attr]);
							});
							code = actual.query.code;
						});
					const auth = new AuthorizationRequest({
						code_verifier,
						scope: 'openid',
						client_id: 'clientSymmetric-dir'
					});
					return auth.getToken(code).expect((response) => {
						expect(response.body).to.have.property('id_token');
					});
				});

				it('rejects symmetric (dir) encrypted request objects when secret is expired', async function () {
					const client = await provider.Client.find('clientSymmetric');
					const signed = await JWT.sign(
						{
							client_id: 'clientSymmetric-expired',
							response_type: 'id_token',
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

					return this.wrap({
						route,
						verb,
						auth: {
							redirect_uri: 'https://client.example.com/cb',
							request: encrypted,
							scope: 'openid',
							client_id: 'clientSymmetric-expired',
							response_type: 'id_token'
						}
					})
						.expect(303)
						.expect((response) => {
							const { query } = url.parse(
								response.headers.location.replace('#', '?'),
								true
							);
							expect(query).to.have.property('error', 'invalid_request_object');
							expect(query).to.have.property(
								'error_description',
								'could not decrypt the Request Object - the client secret used for its encryption is expired'
							);
						});
				});

				it('responds encrypted', function () {
					expect(this.id_token).to.be.ok;
					expect(this.id_token.split('.')).to.have.lengthOf(5);
					const header = decodeProtectedHeader(this.id_token);
					expect(header).to.have.property('alg', 'dir');
					expect(header).to.have.property('enc', 'A128CBC-HS256');
					expect(header).to.have.property('iss').eql(ISSUER);
					expect(header).to.have.property('aud').eql('clientSymmetric-dir');
				});
			});
		});
	});
});
