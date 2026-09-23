import { STATUS_CODES } from 'node:http';

import { Type as t } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

import KeyStore from '../../helpers/keystore.ts';
import epochTime from '../../helpers/epoch_time.ts';
import certificateThumbprint from '../../helpers/certificate_thumbprint.ts';
import { InvalidClientMetadata } from '../../helpers/errors.ts';
import { isPlainObject } from '../../helpers/_/object.js';
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

const RSAPubKey = t.Object({
	...PublicBaseKey.properties,
	kty: t.Literal('RSA'),
	e: t.String({ minLength: 1 }),
	n: t.String({ minLength: 1 })
});

const ECPubKey = t.Object({
	...PublicBaseKey.properties,
	kty: t.Literal('EC'),
	crv: t.Union(ECCurves.map((c) => t.Literal(c))),
	x: t.String({ minLength: 1 }),
	y: t.String({ minLength: 1 })
});

const OKPPubKey = t.Object({
	...PublicBaseKey.properties,
	kty: t.Literal('OKP'),
	crv: t.Union(OKPCurves.map((c) => t.Literal(c))),
	x: t.String({ minLength: 1 })
});

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

export class ClientKeyStore extends KeyStore {
	readonly jwksUri: string | undefined;
	readonly #thumbprintCertificates: boolean;
	// Until when the fetched key set is fresh, and the fetch in flight — shared by concurrent requests.
	freshUntil?: number;
	lock?: Promise<void>;

	/*
	 * Given the values it needs rather than the client. It used to hold the client and read them off
	 * it, which made the key set a property of an object it also pointed back to.
	 */
	constructor({
		keys = [],
		jwksUri,
		thumbprintCertificates = false
	}: {
		keys?: Array<Record<string, unknown>>;
		jwksUri?: string;
		thumbprintCertificates?: boolean;
	}) {
		super();
		this.jwksUri = jwksUri;
		this.#thumbprintCertificates = thumbprintCertificates;
		keys.forEach((key) => this.add(key));
	}

	fresh() {
		if (!this.jwksUri) return true;
		const now = epochTime();
		return !!this.freshUntil && this.freshUntil > now;
	}

	stale() {
		return !this.fresh();
	}

	/*
	 * Annotates a copy. The key it is handed may be a member of the client's own key set, which is
	 * shared by every request using that client and must not change under them.
	 */
	add(key) {
		if (
			this.#thumbprintCertificates &&
			Array.isArray(key.x5c) &&
			key.x5c.length
		) {
			super.add({ ...key, 'x5t#S256': certificateThumbprint(key.x5c[0]) });
			return;
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
