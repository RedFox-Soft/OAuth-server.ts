import crypto from 'node:crypto';
import { STATUS_CODES } from 'node:http';

import KeyStore from '../../helpers/keystore.ts';
import * as base64url from '../../helpers/base64url.ts';
import epochTime from '../../helpers/epoch_time.ts';
import certificateThumbprint from '../../helpers/certificate_thumbprint.ts';
import { InvalidClientMetadata } from '../../helpers/errors.ts';
import { isPlainObject } from '../../helpers/_/object.js';
import { provider } from '../../provider.js';
import {
	clientAuthSigningAlgValues,
	requestObjectEncryptionAlgValues,
	requestObjectEncryptionEncValues,
	requestObjectSigningAlgValues
} from '../../configs/jwaAlgorithms.js';

// intentionally ignore x5t#S256 so that they are left to be calculated by the library
const EC_CURVES = new Set(['P-256', 'P-384', 'P-521']);
const OKP_SUBTYPES = new Set(['Ed25519', 'X25519']);

export const validateJWKS = (jwks) => {
	if (jwks !== undefined) {
		if (!Array.isArray(jwks?.keys) || !jwks.keys.every(isPlainObject)) {
			throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
		}
	}
};

export function checkJWK(jwk) {
	try {
		if (!isPlainObject(jwk)) throw new Error();
		if (!(typeof jwk.kty === 'string' && jwk.kty)) throw new Error();

		switch (jwk.kty) {
			case 'EC':
				if (!(typeof jwk.crv === 'string' && jwk.crv)) throw new Error();
				if (!EC_CURVES.has(jwk.crv)) return undefined;
				if (!(typeof jwk.x === 'string' && jwk.x)) throw new Error();
				if (!(typeof jwk.y === 'string' && jwk.y)) throw new Error();
				break;
			case 'OKP':
				if (!(typeof jwk.crv === 'string' && jwk.crv)) throw new Error();
				if (!OKP_SUBTYPES.has(jwk.crv)) return undefined;
				if (!(typeof jwk.x === 'string' && jwk.x)) throw new Error();
				break;
			case 'RSA':
				if (!(typeof jwk.e === 'string' && jwk.e)) throw new Error();
				if (!(typeof jwk.n === 'string' && jwk.n)) throw new Error();
				break;
			case 'oct':
				break;
			default:
				return undefined;
		}

		if (!(jwk.d === undefined && jwk.kty !== 'oct')) throw new Error();
		if (!(jwk.alg === undefined || (typeof jwk.alg === 'string' && jwk.alg)))
			throw new Error();
		if (!(jwk.kid === undefined || (typeof jwk.kid === 'string' && jwk.kid)))
			throw new Error();
		if (!(jwk.use === undefined || (typeof jwk.use === 'string' && jwk.use)))
			throw new Error();
		if (
			!(
				jwk.x5c === undefined ||
				(Array.isArray(jwk.x5c) &&
					jwk.x5c.every((x) => typeof x === 'string' && x))
			)
		)
			throw new Error();
	} catch {
		throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
	}

	return jwk;
}

function deriveEncryptionKey(secret, length) {
	const digest =
		length <= 32
			? 'sha256'
			: length <= 48
				? 'sha384'
				: length <= 64
					? 'sha512'
					: false;
	if (!digest) {
		throw new Error('unsupported symmetric encryption key derivation');
	}
	return crypto.hash(digest, secret, 'buffer').subarray(0, length);
}

export class ClientKeyStore extends KeyStore {
	#client;

	#provider = provider;

	constructor(clientInstance) {
		super();

		this.#client = clientInstance;
	}

	get client() {
		return this.#client;
	}

	get provider() {
		return this.#provider;
	}

	get jwksUri() {
		return this.client?.jwksUri;
	}

	fresh() {
		if (!this.jwksUri) return true;
		const now = epochTime();
		return !!this.freshUntil && this.freshUntil > now;
	}

	stale() {
		return !this.fresh();
	}

	add(key) {
		if (
			this.client.clientAuthMethod === 'self_signed_tls_client_auth' &&
			Array.isArray(key.x5c) &&
			key.x5c.length
		) {
			key['x5t#S256'] = certificateThumbprint(key.x5c[0]);
		}
		super.add(key);
	}

	async refresh() {
		if (this.fresh()) return;

		if (!this.lock) {
			this.lock = (async () => {
				const response = await fetch(new URL(this.jwksUri).href, {
					method: 'GET',
					headers: {
						Accept: 'application/json'
					}
				});

				const body = await response.json();
				const { headers, status } = response;

				// min refetch in 60 seconds unless cache headers say a longer response ttl
				const freshUntil = [epochTime() + 60];

				if (headers.has('expires')) {
					freshUntil.push(epochTime(Date.parse(headers.get('expires'))));
				}

				if (
					headers.has('cache-control') &&
					/max-age=(\d+)/.test(headers.get('cache-control'))
				) {
					const maxAge = parseInt(RegExp.$1, 10);
					freshUntil.push(epochTime() + maxAge);
				}

				this.freshUntil = Math.max(...freshUntil.filter(Boolean));

				if (status !== 200) {
					throw new Error(
						`unexpected jwks_uri response status code, expected 200 OK, got ${status} ${STATUS_CODES[status]}`
					);
				}

				validateJWKS(body);

				this.clear();
				body.keys
					.map(checkJWK)
					.filter(Boolean)
					.forEach(ClientKeyStore.prototype.add.bind(this));

				delete this.lock;
			})().catch((err) => {
				delete this.lock;
				throw new InvalidClientMetadata(
					'client JSON Web Key Set failed to be refreshed',
					err.error_description || err.message
				);
			});
		}

		await this.lock;
	}
}

export function buildAsymmetricKeyStore(client) {
	Object.defineProperty(client, 'asymmetricKeyStore', {
		configurable: true,
		get() {
			const keystore = new ClientKeyStore(this);
			Object.defineProperty(this, 'asymmetricKeyStore', {
				configurable: false,
				value: keystore
			});

			return this.asymmetricKeyStore;
		}
	});
}

export function buildSymmetricKeyStore(client) {
	Object.defineProperty(client, 'symmetricKeyStore', {
		configurable: false,
		value: new KeyStore()
	});

	const algs = new Set();

	if (client.clientSecret) {
		if (client.clientAuthMethod === 'client_secret_jwt') {
			if (client.clientAuthSigningAlg) {
				algs.add(client.clientAuthSigningAlg);
			} else {
				clientAuthSigningAlgValues.forEach(Set.prototype.add.bind(algs));
			}
		}

		[
			'introspectionSignedResponseAlg',
			'userinfoSignedResponseAlg',
			'authorizationSignedResponseAlg',
			'idTokenSignedResponseAlg',
			'requestObjectSigningAlg'
		].forEach((prop) => {
			algs.add(client[prop]);
		});

		if (!client.requestObjectSigningAlg) {
			requestObjectSigningAlgValues.forEach(Set.prototype.add.bind(algs));
		}

		requestObjectEncryptionAlgValues.forEach(Set.prototype.add.bind(algs));

		if (requestObjectEncryptionAlgValues.includes('dir')) {
			requestObjectEncryptionEncValues.forEach(Set.prototype.add.bind(algs));
		}

		[
			'idTokenEncryptedResponse',
			'userinfoEncryptedResponse',
			'introspectionEncryptedResponse',
			'authorizationEncryptedResponse'
		].forEach((prop) => {
			algs.add(client[`${prop}Alg`]);
			if (client[`${prop}Alg`] === 'dir') {
				algs.add(client[`${prop}Enc`]);
			}
		});

		algs.delete(undefined);

		for (const alg of algs) {
			if (
				!(
					alg.startsWith('HS') ||
					/^A(\d{3})(?:GCM)?KW$/.test(alg) ||
					/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)
				)
			) {
				algs.delete(alg);
			}
		}

		for (const alg of algs) {
			if (alg.startsWith('HS')) {
				client.symmetricKeyStore.add({
					alg,
					use: 'sig',
					kty: 'oct',
					k: base64url.encode(client.clientSecret)
				});
			} else if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
				const len = parseInt(RegExp.$1, 10) / 8;
				client.symmetricKeyStore.add({
					alg,
					use: 'enc',
					kty: 'oct',
					k: deriveEncryptionKey(client.clientSecret, len).toString('base64url')
				});
			} else if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)) {
				const len = parseInt(RegExp.$2 || RegExp.$1, 10) / 8;
				client.symmetricKeyStore.add({
					alg,
					use: 'enc',
					kty: 'oct',
					k: deriveEncryptionKey(client.clientSecret, len).toString('base64url')
				});
			}
		}
	}
}
