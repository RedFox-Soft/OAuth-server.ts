import * as crypto from 'node:crypto';

import * as JWT from '../../helpers/jwt.ts';
import nanoid from '../../helpers/nanoid.js';
import { keystore } from 'lib/configs/keystore.js';
import { issuerFor } from 'lib/configs/issuer.js';
import { issuingBucket } from 'lib/admin/auth/bucketAddress.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { pairwiseIdentifier } from '../../addon/index.js';
import type { JWK } from 'jose';
import type ResourceServer from '../../helpers/resource_server.ts';
import type { BaseToken } from '../base_token.ts';

type TokenKey = crypto.KeyObject | CryptoKey | JWK | Uint8Array | string;

async function getResourceServerConfig(token: {
	resourceServer?: ResourceServer;
}) {
	const defaultAlg = ClientDefaults.idTokenSignedResponseAlg;

	// Resolved to a key object or one of this server's keys; raw secrets are converted first.
	let sign:
		| { alg: string; key: crypto.KeyObject | CryptoKey | JWK; kid?: string }
		| undefined;
	let encrypt:
		| {
				alg: string;
				enc: string;
				key: crypto.KeyObject | CryptoKey;
				kid?: string;
		  }
		| undefined;

	{
		let alg: string | undefined;
		let key: TokenKey | undefined;
		let kid: string | undefined;

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
				if (typeof key === 'string') {
					key = crypto.createSecretKey(key, 'utf8');
				} else if (ArrayBuffer.isView(key)) {
					key = crypto.createSecretKey(key);
				} else if (!(
					key instanceof crypto.KeyObject || key instanceof CryptoKey
				)) {
					throw new Error(
						'jwt.sign.key Resource Server configuration must be a secret (symmetric) key'
					);
				}
				if (key.type !== 'secret') {
					throw new Error(
						'jwt.sign.key Resource Server configuration must be a secret (symmetric) key'
					);
				}
			} else {
				const [jwk] = keystore.selectForVerify({ alg, use: 'sig', kid });
				if (!jwk) {
					throw new Error(
						"resolved Resource Server jwt configuration has no corresponding key in the provider's keystore"
					);
				}
				kid = jwk.kid;
				key = keystore.getKeyObject(jwk);
			}
			if (kid !== undefined && typeof kid !== 'string') {
				throw new Error('jwt.sign.kid must be a string when provided');
			}
			sign = { alg, key, kid };
		}
	}

	if (token.resourceServer?.jwt?.encrypt) {
		const { alg, enc, kid, key: configured } = token.resourceServer.jwt.encrypt;

		if (!alg) {
			throw new Error('missing jwt.encrypt.alg Resource Server configuration');
		}
		if (!enc) {
			throw new Error('missing jwt.encrypt.enc Resource Server configuration');
		}
		if (!configured) {
			throw new Error('missing jwt.encrypt.key Resource Server configuration');
		}

		// Raw bytes are a symmetric key, which only the symmetric algorithms can use.
		let key: crypto.KeyObject | CryptoKey;
		if (
			configured instanceof crypto.KeyObject ||
			configured instanceof CryptoKey
		) {
			key = configured;
		} else if (/^(A|dir$)/.test(alg)) {
			key =
				typeof configured === 'string'
					? crypto.createSecretKey(configured, 'utf8')
					: crypto.createSecretKey(configured);
		} else {
			throw new Error(
				'jwt.encrypt.key Resource Server configuration must be a key object for this algorithm'
			);
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
	async getValueAndPayload(this: BaseToken, payload: Record<string, unknown>) {
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
		let sub =
			typeof payload.accountId === 'string' ? payload.accountId : undefined;

		/*
		 * The bucket recorded when this token was minted, not the one the current request is addressed
		 * to. RFC 9068 requires `iss` to match exactly what the resource server obtained from the
		 * issuer's metadata, and the metadata a resource server holds is the one it discovered for the
		 * bucket that issued the token — deriving it from anything about the present request would make
		 * that comparison fail the moment the two diverge.
		 *
		 * Absent on a token minted before buckets became tenants, and the default bucket's issuer is the
		 * bare one such a token was minted with, so reading the absence that way is exact rather than a
		 * fallback.
		 */
		const iss = issuerFor(
			await issuingBucket(
				typeof payload.bucketId === 'string' ? payload.bucketId : undefined
			)
		);

		if (sub) {
			const { client } = this;
			if (!client || client.clientId !== clientId) {
				throw new TypeError('clientId and client mismatch');
			}
			if (client.subjectType === 'pairwise') {
				sub = await pairwiseIdentifier(sub, client);
			}
		}

		const cnf: Record<string, unknown> = {};
		if (x5t) {
			cnf['x5t#S256'] = x5t;
		}
		if (jkt) {
			cnf.jkt = jkt;
		}

		const tokenPayload = {
			jti,
			sub: sub || clientId,
			iat,
			exp,
			authorization_details: rar,
			scope: scope || undefined,
			client_id: clientId,
			iss,
			aud,
			...(x5t || jkt ? { cnf } : undefined)
		};

		const structuredToken = { payload: tokenPayload };

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
					fields: { kid: config.sign.kid }
				}
			);

			if (config.encrypt) {
				const encrypted = await JWT.encrypt(signed, config.encrypt.key, {
					fields: {
						kid: config.encrypt.kid,
						iss,
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
					iss,
					aud: structuredToken.payload.aud,
					typ: 'at+jwt'
				},
				enc: config.encrypt.enc,
				alg: config.encrypt.alg
			});

			return { value: encrypted };
		}

		throw new Error('invalid Resource Server jwt configuration');
	}
};
