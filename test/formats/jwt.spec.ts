import * as crypto from 'node:crypto';
import * as util from 'node:util';

import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	spyOn,
	mock
} from 'bun:test';
import base64url from 'base64url';

import i from 'lib/helpers/weak_cache.js';

import ResourceServer from '../../lib/helpers/resource_server.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';
import bootstrap from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { TestAdapter } from 'test/models.js';
import { Client } from 'lib/models/client.js';
import { AccessToken } from 'lib/models/access_token.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';

const generateKeyPair = util.promisify(crypto.generateKeyPair);
function decode(b64urljson) {
	return JSON.parse(base64url.decode(b64urljson));
}

describe('jwt format', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(function () {
		provider.removeAllListeners();
		mock.restore();
	});

	const accountId = 'account';
	const claims = {};
	const clientId = 'client';
	const grantId = 'grantid';
	const scope = 'openid';
	const sid = 'sid';
	const consumed = true;
	const acr = 'acr';
	const amr = ['amr'];
	const authTime = epochTime();
	const nonce = 'nonce';
	const redirectUri = 'https://rp.example.com/cb';
	const codeChallenge = 'codeChallenge';
	const codeChallengeMethod = 'codeChallengeMethod';
	const aud = 'foo';
	const gty = 'foo';
	const error = 'access_denied';
	const errorDescription = 'resource owner denied access';
	const params = { foo: 'bar' };
	const userCode = '1384-3217';
	const deviceInfo = { foo: 'bar' };
	const inFlight = true;
	const s256 = '_gPMqAT8BELhXwBa2nIT0OvdWtQCiF_g09nAyHhgCe0';
	const resource = 'urn:foo:bar';
	const policies = ['foo'];
	const sessionUid = 'foo';
	const expiresWithSession = false;
	const iiat = epochTime();
	const rotations = 1;
	const extra = { foo: 'bar' };
	const resourceServer = new ResourceServer(resource, {
		accessTokenFormat: 'jwt',
		audience: 'foo'
	});

	const fullPayload = {
		accountId,
		claims,
		clientId,
		grantId,
		scope,
		sid,
		consumed,
		acr,
		amr,
		authTime,
		nonce,
		redirectUri,
		codeChallenge,
		codeChallengeMethod,
		error,
		errorDescription,
		params,
		userCode,
		deviceInfo,
		gty,
		resource,
		policies,
		sessionUid,
		expiresWithSession,
		'x5t#S256': s256,
		inFlight,
		iiat,
		rotations,
		extra,
		jkt: s256,
		resourceServer
	};

	describe('Resource Server Configuration', () => {
		it('can be used to specify the signing algorithm', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: { alg: 'PS256' }
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'PS256');
		});

		it('uses the default idtokensigningalg by default (no jwt)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo'
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'RS256');
			expect(header).toHaveProperty(
				'kid',
				i(provider).keystore.selectForSign({ alg: 'RS256' })[0].kid
			);
		});

		it('uses the default idtokensigningalg by default (jwt)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'RS256');
			expect(header).toHaveProperty(
				'kid',
				i(provider).keystore.selectForSign({ alg: 'RS256' })[0].kid
			);
		});

		it('can be used to specify the signing algorithm to be HMAC (buffer)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: { alg: 'HS256', key: crypto.randomBytes(32) }
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'HS256');
			expect(header).not.toHaveProperty('kid');
		});

		it('can be used to specify the signing algorithm to be HMAC (CryptoKey)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'HS256',
						key: await crypto.subtle.generateKey(
							{ name: 'HMAC', hash: 'SHA-256' },
							false,
							['sign']
						)
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'HS256');
			expect(header).not.toHaveProperty('kid');
		});

		it('kid must be a string (sign)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: { alg: 'HS256', key: crypto.randomBytes(32), kid: 200 }
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'jwt.sign.kid must be a string when provided'
			);
		});

		it('kid must be a string (encrypt)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					encrypt: {
						alg: 'dir',
						enc: 'A128GCM',
						key: crypto.randomBytes(16),
						kid: 200
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'jwt.encrypt.kid must be a string when provided'
			);
		});

		it('can be used to specify the signing algorithm to be HMAC (buffer w/ kid)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: { alg: 'HS256', key: crypto.randomBytes(32), kid: 'feb-2020' }
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('kid', 'feb-2020');
		});

		it('can be used to specify the signing algorithm to be HMAC (KeyObject)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'HS256',
						key: crypto.createSecretKey(crypto.randomBytes(32))
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'HS256');
			expect(header).not.toHaveProperty('kid');
		});

		it('can be an encrypted JWT (Buffer)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: false,
					encrypt: {
						alg: 'dir',
						enc: 'A128GCM',
						key: crypto.randomBytes(16)
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'dir');
			expect(header).toHaveProperty('enc', 'A128GCM');
			expect(header).not.toHaveProperty('kid');
			expect(header).toHaveProperty('typ', 'at+jwt');
			expect(header).toHaveProperty('iss', ISSUER);
			expect(header).toHaveProperty('aud', 'foo');
		});

		it('can be an encrypted JWT (KeyObject)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: false,
					encrypt: {
						alg: 'dir',
						enc: 'A128GCM',
						key: crypto.generateKeySync('aes', { length: 128 })
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'dir');
			expect(header).toHaveProperty('enc', 'A128GCM');
			expect(header).not.toHaveProperty('kid');
			expect(header).toHaveProperty('typ', 'at+jwt');
			expect(header).toHaveProperty('iss', ISSUER);
			expect(header).toHaveProperty('aud', 'foo');
		});

		it('can be an encrypted JWT (CryptoKey)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: false,
					encrypt: {
						alg: 'dir',
						enc: 'A128GCM',
						key: await crypto.subtle.generateKey(
							{ name: 'AES-GCM', length: 128 },
							false,
							['encrypt']
						)
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'dir');
			expect(header).toHaveProperty('enc', 'A128GCM');
			expect(header).not.toHaveProperty('kid');
			expect(header).toHaveProperty('typ', 'at+jwt');
			expect(header).toHaveProperty('iss', ISSUER);
			expect(header).toHaveProperty('aud', 'foo');
		});

		it('can be an encrypted JWT w/ kid', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: false,
					encrypt: {
						alg: 'dir',
						enc: 'A128GCM',
						key: crypto.randomBytes(16),
						kid: 'feb-2020'
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('kid', 'feb-2020');
		});

		it('can be a nested JWT (explicit)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'PS256'
					},
					encrypt: {
						alg: 'ECDH-ES',
						enc: 'A128GCM',
						key: (await generateKeyPair('ec', { namedCurve: 'P-256' }))
							.publicKey
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'ECDH-ES');
			expect(header).toHaveProperty('enc', 'A128GCM');
			expect(header).toHaveProperty('cty', 'at+jwt');
			expect(header).toHaveProperty('iss', ISSUER);
			expect(header).toHaveProperty('aud', 'foo');
			expect(header).not.toHaveProperty('kid');
		});

		it('can be a nested JWT w/ kid', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'PS256'
					},
					encrypt: {
						alg: 'ECDH-ES',
						enc: 'A128GCM',
						key: (await generateKeyPair('ec', { namedCurve: 'P-256' }))
							.publicKey,
						kid: 'feb-2020'
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('kid', 'feb-2020');
		});

		it('can be a nested JWT (implicit signing alg)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {},
					encrypt: {
						alg: 'ECDH-ES',
						enc: 'A128GCM',
						key: (await generateKeyPair('ec', { namedCurve: 'P-256' }))
							.publicKey
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			const jwt = await token.save();

			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('alg', 'ECDH-ES');
			expect(header).toHaveProperty('enc', 'A128GCM');
			expect(header).toHaveProperty('cty', 'at+jwt');
			expect(header).toHaveProperty('iss', ISSUER);
			expect(header).toHaveProperty('aud', 'foo');
		});

		it('ensures "none" JWS algorithm cannot be used', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'none'
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'JWT Access Tokens may not use JWS algorithm "none"'
			);
		});

		it('ensures HMAC JWS algorithms get a key', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'HS256'
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'missing jwt.sign.key Resource Server configuration'
			);
		});

		it('ensures HMAC JWS algorithms get a secret key (1/2)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'HS256',
						key: (await generateKeyPair('ec', { namedCurve: 'P-256' }))
							.publicKey
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'jwt.sign.key Resource Server configuration must be a secret (symmetric) key'
			);
		});

		it('ensures HMAC JWS algorithms get a secret key (2/2)', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'HS256',
						key: (await generateKeyPair('ec', { namedCurve: 'P-256' }))
							.privateKey
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'jwt.sign.key Resource Server configuration must be a secret (symmetric) key'
			);
		});

		it('ensures Asymmetric JWS algorithms have a key in the provider keystore', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					sign: {
						alg: 'ES512'
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				"resolved Resource Server jwt configuration has no corresponding key in the provider's keystore"
			);
		});

		it('ensures JWE key is public or secret', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					encrypt: {
						alg: 'dir',
						enc: 'A128GCM',
						key: (await generateKeyPair('ec', { namedCurve: 'P-256' }))
							.privateKey
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'jwt.encrypt.key Resource Server configuration must be a secret (symmetric) or a public key'
			);
		});

		it('ensures Nested JWT when JWE encryption is a public one', async () => {
			const resourceServer = new ResourceServer(resource, {
				accessTokenFormat: 'jwt',
				audience: 'foo',
				jwt: {
					encrypt: {
						alg: 'ECDH-ES',
						enc: 'A128GCM',
						key: (await generateKeyPair('ec', { namedCurve: 'P-256' }))
							.publicKey
					}
				}
			});

			const client = await Client.find(clientId);
			const token = new AccessToken({
				client,
				...fullPayload,
				resourceServer
			});
			await expect(token.save()).rejects.toThrow(
				'missing jwt.sign Resource Server configuration'
			);
		});

		for (const prop of ['alg', 'enc', 'key']) {
			it(`ensures JWE Configuration has ${prop}`, async () => {
				const resourceServer = new ResourceServer(resource, {
					accessTokenFormat: 'jwt',
					audience: 'foo',
					jwt: {
						encrypt: {
							alg: 'dir',
							enc: 'A128GCM',
							key: crypto.randomBytes(16)
						}
					}
				});

				delete resourceServer.jwt.encrypt[prop];

				const client = await Client.find(clientId);
				const token = new AccessToken({
					client,
					...fullPayload,
					resourceServer
				});
				await expect(token.save()).rejects.toThrow(
					`missing jwt.encrypt.${prop} Resource Server configuration`
				);
			});
		}
	});

	it('for AccessToken', async () => {
		const upsert = spyOn(TestAdapter.for('AccessToken'), 'upsert');
		const client = await Client.find(clientId);
		const token = new AccessToken({ client, ...fullPayload });
		const issued = mock();
		provider.on('access_token.issued', issued);
		const jwt = await token.save();

		expect(upsert).not.toHaveBeenCalled();

		const { jti } = issued.mock.calls[0][0];
		const header = decode(jwt.split('.')[0]);
		expect(header).toHaveProperty('typ', 'at+jwt');
		const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
		expect(iat).toBeTypeOf('number');
		expect(exp).toBeTypeOf('number');
		expect(payload).toEqual({
			...extra,
			aud,
			client_id: clientId,
			iss: ISSUER,
			jti,
			scope,
			sub: accountId,
			cnf: {
				'x5t#S256': s256,
				jkt: s256
			}
		});
	});

	it('for pairwise AccessToken', async () => {
		const upsert = spyOn(TestAdapter.for('AccessToken'), 'upsert');
		const client = await Client.find('pairwise');
		const token = new AccessToken({ client, ...fullPayload });
		const issued = mock();
		provider.on('access_token.issued', issued);
		const jwt = await token.save();

		expect(upsert).not.toHaveBeenCalled();

		const { jti } = issued.mock.calls[0][0];
		const header = decode(jwt.split('.')[0]);
		expect(header).toHaveProperty('typ', 'at+jwt');
		const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
		expect(iat).toBeTypeOf('number');
		expect(exp).toBeTypeOf('number');
		expect(payload).toEqual({
			...extra,
			aud,
			client_id: 'pairwise',
			iss: ISSUER,
			jti,
			scope,
			sub: 'pairwise-sub',
			cnf: {
				'x5t#S256': s256,
				jkt: s256
			}
		});
	});

	it('for ClientCredentials', async () => {
		const upsert = spyOn(TestAdapter.for('ClientCredentials'), 'upsert');
		const client = await Client.find(clientId);
		const token = new ClientCredentials({
			client,
			...fullPayload
		});
		const issued = mock();
		provider.on('client_credentials.issued', issued);
		const jwt = await token.save();

		expect(upsert).not.toHaveBeenCalled();

		const { jti } = issued.mock.calls[0][0];
		const header = decode(jwt.split('.')[0]);
		expect(header).toHaveProperty('typ', 'at+jwt');
		const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
		expect(iat).toBeTypeOf('number');
		expect(exp).toBeTypeOf('number');
		expect(payload).toEqual({
			...extra,
			aud,
			client_id: clientId,
			sub: clientId,
			iss: ISSUER,
			jti,
			scope,
			cnf: {
				'x5t#S256': s256,
				jkt: s256
			}
		});
	});

	describe('customizers', () => {
		afterEach(function () {
			i(provider).configuration.formats.customizers.jwt = undefined;
		});

		it('allows the payload to be extended', async () => {
			const client = await Client.find(clientId);
			const accessToken = new AccessToken({
				client,
				...fullPayload
			});
			accessToken.resourceServer = resourceServer;
			i(provider).configuration.formats.customizers.jwt = (ctx, token, jwt) => {
				expect(token).toBe(accessToken);
				expect(jwt).toHaveProperty('payload');
				expect(jwt).toHaveProperty('header', undefined);
				jwt.header = { customized: true, typ: 'foo' };
				jwt.payload.customized = true;
				jwt.payload.iss = 'foobar';
			};

			const jwt = await accessToken.save();
			const header = decode(jwt.split('.')[0]);
			expect(header).toHaveProperty('customized', true);
			expect(header).toHaveProperty('typ', 'foo');
			const payload = decode(jwt.split('.')[1]);
			expect(payload).toHaveProperty('customized', true);
			expect(payload).toHaveProperty('iss', 'foobar');
		});
	});
});
