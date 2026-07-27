import { Type as t, type Static } from '@sinclair/typebox';
import { Value, type ValueError } from '@sinclair/typebox/value';
import crypto from 'node:crypto';
import {
	ECCurves,
	ECOKPEncAlg,
	ECSignAlg,
	type encryptionAlgValues,
	OKPCurves,
	OKPSignAlg,
	RSAEncAlg,
	RSASignAlg,
	signingAlgs,
	type signingAlgValues
} from 'lib/configs/jwaConsts.js';

const BaseKey = t.Object({
	kid: t.Optional(t.String()),
	kty: t.Union([t.Literal('RSA'), t.Literal('EC'), t.Literal('OKP')], {
		error: 'only RSA, EC, or OKP keys should be part of jwks'
	}),
	use: t.Optional(t.Union([t.Literal('sig'), t.Literal('enc')])),
	x5c: t.Optional(t.Array(t.String(), { minContains: 1 })),
	key_ops: t.Optional(t.Array(t.String()))
});

const RSAKey = t.Composite(
	[
		BaseKey,
		t.Object({
			kty: t.Literal('RSA'),
			alg: t.Union([...RSASignAlg, ...RSAEncAlg].map((alg) => t.Literal(alg))),
			e: t.String(),
			n: t.String(),
			d: t.String(),
			p: t.String(),
			q: t.String(),
			dp: t.String(),
			dq: t.String(),
			qi: t.String()
		})
	],
	{ additionalProperties: false }
);

const ECKey = t.Composite(
	[
		BaseKey,
		t.Object({
			kty: t.Literal('EC'),
			alg: t.Union([...ECSignAlg, ...ECOKPEncAlg].map((alg) => t.Literal(alg))),
			crv: t.Union(ECCurves.map((c) => t.Literal(c))),
			x: t.String(),
			y: t.String(),
			d: t.String()
		})
	],
	{ additionalProperties: false }
);

const OKPKey = t.Composite(
	[
		BaseKey,
		t.Object({
			kty: t.Literal('OKP'),
			alg: t.Union(
				[...OKPSignAlg, ...ECOKPEncAlg].map((alg) => t.Literal(alg))
			),
			crv: t.Union(OKPCurves.map((c) => t.Literal(c))),
			x: t.String(),
			d: t.String()
		})
	],
	{ additionalProperties: false }
);
type reqProp = {
	kid: string;
	use: 'enc' | 'sig';
};
export type StaticRSAKey = Static<typeof RSAKey>;
type StaticECKey = Static<typeof ECKey>;
type StaticOKPKey = Static<typeof OKPKey>;

/*
 * A key that satisfies its per-kty schema but has not been through verifyJWKs' normalization, so
 * `kid` and `use` may still be absent (`alg` is required by every schema above, and so is always
 * present). This is the type of anything read straight out of the key store; `JWKS` is the same key
 * once normalized, with both filled in.
 */
export type UnnormalizedJWK = StaticRSAKey | StaticECKey | StaticOKPKey;
export type JWKS =
	(reqProp & StaticRSAKey) | (reqProp & StaticECKey) | (reqProp & StaticOKPKey);

const ktyMap = {
	RSA: RSAKey,
	EC: ECKey,
	OKP: OKPKey
};

function typeboxErrorMessage(error?: ValueError) {
	return error?.schema.error ?? `${error?.path} ${error?.message}`;
}

/*
 * Validate a JWK Set and normalize each key in place, filling in `use` (from `alg`) and `kid` (the
 * RFC 7638 thumbprint) where absent. Throws on anything invalid.
 *
 * An assertion rather than a `jwks is ...` predicate: it throws instead of returning false, and
 * every caller invokes it as a statement, where a predicate narrows nothing. As an assertion the
 * caller's key set becomes `JWKS[]` — normalized, `kid`/`use` guaranteed — which is what the
 * downstream code actually relies on and used to re-assert with a cast.
 */
export function verifyJWKs(jwks: unknown): asserts jwks is { keys: JWKS[] } {
	if (
		typeof jwks !== 'object' ||
		jwks === null ||
		!('keys' in jwks) ||
		!Array.isArray(jwks.keys) ||
		jwks.keys.length === 0
	) {
		throw new Error('keystore must be a JSON Web Key Set formatted object');
	}
	const uniqueKid = new Set();
	const SignAlg = new Set<string>(signingAlgs);
	for (let i = 0; i < jwks.keys.length; i++) {
		const key = jwks.keys[i];
		if (typeof key !== 'object' || key === null) {
			throw new Error(`jwks.keys[${i}] must be an object`);
		}

		if (!Value.Check(BaseKey, key)) {
			const error = Value.Errors(BaseKey, key).First();
			const errorMessage = typeboxErrorMessage(error);
			throw new Error(`jwks.keys[${i}] has validation failed ${errorMessage}`);
		}

		const schema = ktyMap[key.kty];
		if (!Value.Check(schema, key)) {
			const error = Value.Errors(schema, key).First();
			const errorMessage = typeboxErrorMessage(error);
			throw new Error(`jwks.keys[${i}] has validation failed ${errorMessage}`);
		}
		key.use ??= SignAlg.has(key.alg) ? 'sig' : 'enc';
		key.kid ??= calculateKid(key);
		if (uniqueKid.has(key.kid)) {
			throw new Error(
				`jwks.keys[${i}].kid must be unique, found duplicate: ${key.kid}`
			);
		}
		uniqueKid.add(key.kid);
	}
}

/*
 * The key's RFC 7638 JWK thumbprint, over the required members for its kty (already in the
 * lexicographic order the spec asks for). Used as the kid of any key that arrives without one —
 * exported so the published-JWKS projection derives the *same* kid this normalization would, which
 * is what lets the admin API compare a raw store key against the live set by kid.
 */
export const calculateKid = (jwk: UnnormalizedJWK) => {
	let components;

	switch (jwk.kty) {
		case 'RSA':
			components = {
				e: jwk.e,
				kty: 'RSA',
				n: jwk.n
			};
			break;
		case 'EC':
			components = {
				crv: jwk.crv,
				kty: 'EC',
				x: jwk.x,
				y: jwk.y
			};
			break;
		case 'OKP':
			components = {
				crv: jwk.crv,
				kty: 'OKP',
				x: jwk.x
			};
			break;
	}

	return crypto.hash('sha256', JSON.stringify(components), 'base64url');
};

export function getAlgorithm(keys: JWKS[]) {
	const signAlg = new Set<string>();
	const encAlg = new Set<string>();
	for (const key of keys) {
		if (key.use === 'sig') {
			signAlg.add(key.alg);
		} else if (key.use === 'enc') {
			encAlg.add(key.alg);
		}
	}
	return {
		sign: Array.from(signAlg) as signingAlgValues[],
		enc: Array.from(encAlg) as encryptionAlgValues[]
	};
}
