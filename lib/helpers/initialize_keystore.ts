import { Type as t, type Static } from '@sinclair/typebox';
import { Value, type ValueError } from '@sinclair/typebox/value';
import crypto from 'node:crypto';

import { DEV_KEYSTORE } from '../consts/index.ts';

import * as attention from './attention.ts';
import instance from './weak_cache.ts';
import KeyStore from './keystore.ts';

const BaseKey = t.Object({
	kid: t.Optional(t.String()),
	kty: t.Union([t.Literal('RSA'), t.Literal('EC'), t.Literal('OKP')], {
		error: 'only RSA, EC, or OKP keys should be part of jwks'
	}),
	use: t.Optional(t.Union([t.Literal('sig'), t.Literal('enc')])),
	x5c: t.Optional(t.Array(t.String(), { minContains: 1 })),
	key_ops: t.Optional(t.Array(t.String()))
});

const RSASignAlg = ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'];
const ECSignAlg = ['ES256', 'ES384', 'ES512'];
const OKPSignAlg = ['EdDSA', 'Ed25519'];
const SignAlg = new Set([...RSASignAlg, ...ECSignAlg, ...OKPSignAlg]);

const RSAEncAlg = ['RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'];
const ECOKPEncAlg = [
	'ECDH-ES',
	'ECDH-ES+A128KW',
	'ECDH-ES+A192KW',
	'ECDH-ES+A256KW'
];
const EncAlg = new Set([...RSAEncAlg, ...ECOKPEncAlg]);

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
			crv: t.Union([
				t.Literal('P-256'),
				t.Literal('P-384'),
				t.Literal('P-521')
			]),
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
			crv: t.Union([t.Literal('Ed25519'), t.Literal('X25519')]),
			x: t.String(),
			d: t.String()
		})
	],
	{ additionalProperties: false }
);
type StaticRSAKey = Static<typeof RSAKey>;
type StaticECKey = Static<typeof ECKey>;
type StaticOKPKey = Static<typeof OKPKey>;
type JWKS = StaticRSAKey | StaticECKey | StaticOKPKey;

const ktyMap = {
	RSA: RSAKey,
	EC: ECKey,
	OKP: OKPKey
};

function typeboxErrorMessage(error?: ValueError) {
	return error?.schema.error ?? `${error?.path} ${error?.message}`;
}

function verifyJWKs(jwks: unknown): jwks is { keys: JWKS[] } {
	if (
		typeof jwks !== 'object' ||
		jwks === null ||
		!('keys' in jwks) ||
		!Array.isArray(jwks.keys)
	) {
		throw new Error('keystore must be a JSON Web Key Set formatted object');
	}
	const uniqueKid = new Set();
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
		key.kid ??= calculateKid(key);
		if (uniqueKid.has(key.kid)) {
			throw new Error(
				`jwks.keys[${i}].kid must be unique, found duplicate: ${key.kid}`
			);
		}
		uniqueKid.add(key.kid);
	}

	return true;
}

const calculateKid = (jwk: JWKS) => {
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

const jwkSignatureAlgorithms = (jwk) => {
	if ((jwk.use && jwk.use !== 'sig') || !SignAlg.has(jwk.alg)) {
		return;
	}
	jwk.use ??= 'sig';
	return jwk.alg;
};

const jwkEncryptionAlgorithms = (jwk) => {
	if ((jwk.use && jwk.use !== 'enc') || !EncAlg.has(jwk.alg)) {
		return;
	}
	jwk.use ??= 'enc';
	return jwk.alg;
};

function registerKey(input, keystore) {
	const { configuration } = instance(this);

	const key = structuredClone(input);

	const encryptionAlgs = jwkEncryptionAlgorithms(key);
	if (encryptionAlgs) {
		[
			// 'idTokenEncryptionAlgValues',
			'requestObjectEncryptionAlgValues'
			// 'userinfoEncryptionAlgValues',
		].forEach((prop) => {
			if (!configuration[prop].includes(encryptionAlgs)) {
				configuration[prop].push(encryptionAlgs);
			}
		});
	}

	const signingAlgs = jwkSignatureAlgorithms(key);
	if (signingAlgs) {
		[
			'idTokenSigningAlgValues',
			// 'requestObjectSigningAlgValues' uses client's keystore
			// 'tokenEndpointAuthSigningAlgValues' uses client's keystore
			'userinfoSigningAlgValues',
			'introspectionSigningAlgValues',
			'authorizationSigningAlgValues'
		].forEach((prop) => {
			if (!configuration[prop].includes(signingAlgs)) {
				configuration[prop].push(signingAlgs);
			}
		});
	}

	keystore.add(key);
}

export default function initialize(jwks) {
	if (jwks === undefined) {
		// eslint-disable-next-line no-param-reassign
		jwks = structuredClone(DEV_KEYSTORE);
		/* eslint-disable no-multi-str */
		attention.warn(
			'a quick start development-only signing keys are used, you are expected to \
provide your own in the configuration "jwks" property'
		);
		/* eslint-enable */
	}

	const keystore = new KeyStore();

	try {
		verifyJWKs(jwks);

		for (let i = 0; i < jwks.keys.length; i++) {
			registerKey.call(this, jwks.keys[i], keystore);
		}
	} catch (err) {
		throw new Error(
			err.message || 'keystore must be a JSON Web Key Set formatted object',
			{ cause: err }
		);
	}

	instance(this).keystore = keystore;
	const keys = [...keystore].map((key) => ({
		kty: key.kty,
		use: key.use,
		key_ops: key.key_ops ? [...key.key_ops] : undefined,
		kid: key.kid,
		alg: key.alg,
		crv: key.crv,
		e: key.e,
		n: key.n,
		x: key.x,
		x5c: key.x5c ? [...key.x5c] : undefined,
		y: key.y
	}));
	instance(this).jwks = { keys };
}
