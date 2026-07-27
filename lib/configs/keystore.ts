import KeyStore from '../helpers/keystore.js';
import { signingAlgs } from './jwaConsts.js';
import { calculateKid, type UnnormalizedJWK } from './verifyJWKs.js';

/*
 * The server's live key material — the in-memory keystore used to sign, verify, encrypt and
 * decrypt, and the JWKS document served at /jwks.
 *
 * This module is deliberately a leaf: it imports nothing that reaches the adapters, the
 * ApplicationConfig or the models (the key type comes in as a type-only import, so it adds no
 * runtime edge). Loading keys is asynchronous (see configs/keys.ts, which reads the jwksStore
 * adapter behind a top-level await); holding the loaded result here keeps that await out of the
 * model import graph, where it reorders module evaluation and trips the
 * base_model -> provider -> models cycle.
 *
 * Both exports are mutated in place and never reassigned, so every module holding the imported
 * reference sees the current keys. The admin JWKS API relies on this to hot-apply a new key.
 */
/*
 * A key as published: normalized (`kid` and `use` always present) and carrying only client-safe
 * members. Which of the type-specific members are set follows from `kty`.
 */
export type PublicJWK = {
	kid: string;
	kty: 'RSA' | 'EC' | 'OKP';
	alg: string;
	use: 'sig' | 'enc';
	key_ops?: string[];
	x5c?: string[];
	crv?: string;
	e?: string;
	n?: string;
	x?: string;
	y?: string;
};

export const keystore = new KeyStore();
export const publicJWKS: { keys: PublicJWK[] } = { keys: [] };

const SIG_ALGS = new Set<string>(signingAlgs);

/*
 * toPublicJwk
 *
 * The client-safe projection of a key as published at /jwks: an explicit allow-list of members per
 * key type (never a blocklist) so an unforeseen private component (d/p/q/dp/dq/qi/oth) can never
 * leak.
 *
 * Normalizes the two members verifyJWKs also fills in, for keys read straight from the store that
 * have not been through it: `kid` from the RFC 7638 thumbprint (via the same calculateKid that
 * normalization uses, so both derive the same value), and `use` from `alg` (which every key schema
 * requires, so it is always available to infer from).
 */
export function toPublicJwk(key: UnnormalizedJWK): PublicJWK {
	const common = {
		kid: key.kid ?? calculateKid(key),
		alg: key.alg,
		use: key.use ?? (SIG_ALGS.has(key.alg) ? 'sig' : 'enc'),
		key_ops: key.key_ops ? [...key.key_ops] : undefined,
		x5c: key.x5c ? [...key.x5c] : undefined
	};

	switch (key.kty) {
		case 'RSA':
			return { ...common, kty: key.kty, e: key.e, n: key.n };
		case 'EC':
			return { ...common, kty: key.kty, crv: key.crv, x: key.x, y: key.y };
		case 'OKP':
			return { ...common, kty: key.kty, crv: key.crv, x: key.x };
	}
}

/*
 * loadKeys
 *
 * Replace the live key material with `keys`, in place. Called once at boot and again on every
 * reload from the key store (see configs/keys.ts) — the server's keys are never set any other way.
 */
export function loadKeys(keys: UnnormalizedJWK[]): void {
	keystore.clear();
	// Cloned: the keystore hands these out for signing, and the caller's array must stay the
	// pristine snapshot of what the key store returned.
	for (const key of keys) keystore.add(structuredClone(key));

	publicJWKS.keys.length = 0;
	for (const key of keys) publicJWKS.keys.push(toPublicJwk(key));
}
