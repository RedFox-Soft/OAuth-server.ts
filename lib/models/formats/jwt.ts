import * as crypto from 'node:crypto';

import * as JWT from '../../helpers/jwt.ts';
import nanoid from '../../helpers/nanoid.js';
import { keystore } from 'lib/configs/keystore.js';
import { ISSUER } from 'lib/configs/env.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { pairwiseIdentifier } from '../../addon/index.js';

async function getResourceServerConfig(token) {
	const defaultAlg = ClientDefaults.idTokenSignedResponseAlg;

	let sign;
	let encrypt;

	{
		let alg;
		let key;
		let kid;

		if (token.resourceServer) {
			if (token.resourceServer.jwt?.sign) {
				({ alg = defaultAlg, key, kid } = token.resourceServer.jwt.sign);
			} else if (
				!token.resourceServer.jwt ||
				(!token.resourceServer.jwt.sign && !token.resourceServer.jwt.encrypt)
			) {
				alg = defaultAlg;
			}
		}

		if (alg === 'none') {
			throw new Error('JWT Access Tokens may not use JWS algorithm "none"');
		} else if (alg) {
			if (alg.startsWith('HS')) {
				if (!key) {
					throw new Error('missing jwt.sign.key Resource Server configuration');
				}
				if (!(key instanceof crypto.KeyObject || key instanceof CryptoKey)) {
					key = crypto.createSecretKey(key);
				}
				if (key.type !== 'secret') {
					throw new Error(
						'jwt.sign.key Resource Server configuration must be a secret (symmetric) key'
					);
				}
			} else {
				[key] = keystore.selectForVerify({ alg, use: 'sig', kid });
				if (!key) {
					throw new Error(
						"resolved Resource Server jwt configuration has no corresponding key in the provider's keystore"
					);
				}
				kid = key.kid;
				key = keystore.getKeyObject(key);
			}
			if (kid !== undefined && typeof kid !== 'string') {
				throw new Error('jwt.sign.kid must be a string when provided');
			}
			sign = { alg, key, kid };
		}
	}

	if (token.resourceServer?.jwt?.encrypt) {
		const { alg, enc, kid } = token.resourceServer.jwt.encrypt;
		let { key } = token.resourceServer.jwt.encrypt;

		if (!alg) {
			throw new Error('missing jwt.encrypt.alg Resource Server configuration');
		}
		if (!enc) {
			throw new Error('missing jwt.encrypt.enc Resource Server configuration');
		}
		if (!key) {
			throw new Error('missing jwt.encrypt.key Resource Server configuration');
		}

		if (
			!(key instanceof crypto.KeyObject || key instanceof CryptoKey) &&
			/^(A|dir$)/.test(alg)
		) {
			key = crypto.createSecretKey(key);
		}

		if (key.type === 'private')
			throw new Error(
				'jwt.encrypt.key Resource Server configuration must be a secret (symmetric) or a public key'
			);
		if (key.type === 'public' && !sign)
			throw new Error('missing jwt.sign Resource Server configuration');

		if (kid !== undefined && typeof kid !== 'string') {
			throw new Error('jwt.encrypt.kid must be a string when provided');
		}
		encrypt = {
			alg,
			enc,
			key,
			kid
		};
	}

	return { sign, encrypt };
}

export const jwt = {
	generateTokenId() {
		return nanoid();
	},
	async getValueAndPayload(payload) {
		const {
			aud,
			jti,
			iat,
			exp,
			scope,
			clientId,
			'x5t#S256': x5t,
			jkt,
			rar
		} = payload;
		let { accountId: sub } = payload;

		if (sub) {
			const { client } = this;
			if (client?.clientId !== clientId) {
				throw new TypeError('clientId and client mismatch');
			}
			if (client.subjectType === 'pairwise') {
				sub = await pairwiseIdentifier(sub, client);
			}
		}

		const tokenPayload = {
			jti,
			sub: sub || clientId,
			iat,
			exp,
			authorization_details: rar,
			scope: scope || undefined,
			client_id: clientId,
			iss: ISSUER,
			aud,
			...(x5t || jkt ? { cnf: {} } : undefined)
		};

		if (x5t) {
			tokenPayload.cnf['x5t#S256'] = x5t;
		}
		if (jkt) {
			tokenPayload.cnf.jkt = jkt;
		}

		const structuredToken = {
			header: undefined,
			payload: tokenPayload
		};

		if (!structuredToken.payload.aud) {
			throw new Error(
				'JWT Access Tokens must contain an audience, for Access Tokens without audience (only usable at the userinfo_endpoint) use an opaque format'
			);
		}

		const config = await getResourceServerConfig(this);

		if (config.sign) {
			const signed = await JWT.sign(
				structuredToken.payload,
				config.sign.key,
				config.sign.alg,
				{
					typ: 'at+jwt',
					fields: { kid: config.sign.kid, ...structuredToken.header }
				}
			);

			if (config.encrypt) {
				const encrypted = await JWT.encrypt(signed, config.encrypt.key, {
					fields: {
						kid: config.encrypt.kid,
						iss: ISSUER,
						aud: structuredToken.payload.aud,
						cty: 'at+jwt'
					},
					enc: config.encrypt.enc,
					alg: config.encrypt.alg
				});

				return { value: encrypted };
			}

			return { value: signed };
		}

		if (config.encrypt) {
			const cleartext = JSON.stringify(structuredToken.payload);
			const encrypted = await JWT.encrypt(cleartext, config.encrypt.key, {
				fields: {
					kid: config.encrypt.kid,
					iss: ISSUER,
					aud: structuredToken.payload.aud,
					typ: 'at+jwt',
					...structuredToken.header
				},
				enc: config.encrypt.enc,
				alg: config.encrypt.alg
			});

			return { value: encrypted };
		}

		throw new Error('invalid Resource Server jwt configuration');
	}
};
