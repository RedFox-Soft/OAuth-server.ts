import crypto from 'node:crypto';
import { STATUS_CODES } from 'node:http';

import { Type as t } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

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
import { ECCurves, OKPCurves } from '../../configs/jwaConsts.js';

// NOTE: client JWKS validation here is intentionally the mirror image of the
// server-side `verifyJWKs` (lib/configs/verifyJWKs.ts): these are PUBLIC keys
// from a third party, so private components (`d`) are forbidden and `oct` is
// rejected (symmetric keys live in the symmetric keystore), whereas verifyJWKs
// validates the provider's own PRIVATE keys. Schemas are kept separate on
// purpose — do not merge them. Extra/unknown members are deliberately tolerated
// (open objects): `ClientKeyStore.add` later writes `x5t#S256` onto keys and
// third-party JWKS commonly carry additional members.
const EC_CURVES = new Set<string>(ECCurves);
const OKP_SUBTYPES = new Set<string>(OKPCurves);

// Shared optional members for any public client JWK. Objects are left open
// (additionalProperties). The private component `d` is rejected separately in
// checkJWK rather than via the schema, because TypeBox treats an optional
// `Never` as a required-but-unsatisfiable property.
const PublicBaseKey = t.Object({
	kid: t.Optional(t.String({ minLength: 1 })),
	alg: t.Optional(t.String({ minLength: 1 })),
	use: t.Optional(t.String({ minLength: 1 })),
	x5c: t.Optional(t.Array(t.String({ minLength: 1 })))
});

const RSAPubKey = t.Composite([
	PublicBaseKey,
	t.Object({
		kty: t.Literal('RSA'),
		e: t.String({ minLength: 1 }),
		n: t.String({ minLength: 1 })
	})
]);

const ECPubKey = t.Composite([
	PublicBaseKey,
	t.Object({
		kty: t.Literal('EC'),
		crv: t.Union(ECCurves.map((c) => t.Literal(c))),
		x: t.String({ minLength: 1 }),
		y: t.String({ minLength: 1 })
	})
]);

const OKPPubKey = t.Composite([
	PublicBaseKey,
	t.Object({
		kty: t.Literal('OKP'),
		crv: t.Union(OKPCurves.map((c) => t.Literal(c))),
		x: t.String({ minLength: 1 })
	})
]);

export function validateJWK(jwk) {
	if (!isPlainObject(jwk) || !(typeof jwk.kty === 'string' && jwk.kty)) {
		throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
	}

	let schema;
	switch (jwk.kty) {
		case 'RSA':
			schema = RSAPubKey;
			break;
		case 'EC':
		case 'OKP': {
			if (!(typeof jwk.crv === 'string' && jwk.crv)) {
				throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
			}
			const curves = jwk.kty === 'EC' ? EC_CURVES : OKP_SUBTYPES;
			// unsupported curve: skip the key rather than reject the whole set
			if (!curves.has(jwk.crv)) return undefined;
			schema = jwk.kty === 'EC' ? ECPubKey : OKPPubKey;
			break;
		}
		case 'oct':
			// symmetric keys do not belong in a client's asymmetric JWKS
			throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
		default:
			// unrecognized key type: skip it, leaving the rest of the set usable
			return undefined;
	}

	// reject private keys: only public key material is accepted here
	if (jwk.d !== undefined || !Value.Check(schema, jwk)) {
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

				if (body !== undefined) {
					if (!Array.isArray(body?.keys) || !body.keys.every(isPlainObject)) {
						throw new InvalidClientMetadata(
							'client JSON Web Key Set is invalid'
						);
					}
				}

				this.clear();
				body.keys
					.map(validateJWK)
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
			'requestObject.signingAlg'
		].forEach((prop) => {
			algs.add(client[prop]);
		});

		if (!client['requestObject.signingAlg']) {
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
			if (!(
				alg.startsWith('HS') ||
				/^A(\d{3})(?:GCM)?KW$/.test(alg) ||
				/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)
			)) {
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
