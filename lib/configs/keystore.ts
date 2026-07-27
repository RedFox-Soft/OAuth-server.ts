import * as crypto from 'node:crypto';

import KeyStore from '../helpers/keystore.js';
import { signingAlgs } from './jwaConsts.js';

/*
 * The server's live key material — the in-memory keystore used to sign, verify, encrypt and
 * decrypt, and the JWKS document served at /jwks.
 *
 * This module is deliberately a leaf: it imports nothing that reaches the adapters, the
 * ApplicationConfig or the models. Loading keys is asynchronous (see configs/keys.ts, which reads
 * the jwksStore adapter behind a top-level await); holding the loaded result here keeps that await
 * out of the model import graph, where it reorders module evaluation and trips the
 * base_model -> provider -> models cycle.
 *
 * Both exports are mutated in place and never reassigned, so every module holding the imported
 * reference sees the current keys. The admin JWKS API relies on this to hot-apply a new key.
 */
export const keystore = new KeyStore();
export const publicJWKS: { keys: Array<Record<string, unknown>> } = {
	keys: []
};

// ES256K is deliberately not one of the server's offered signing algorithms, so it is absent from
// signingAlgs; it is still recognised here so a key provisioned out of band with that alg is
// published as a signing key rather than misclassified as an encryption key.
const SIG_ALGS = new Set<string>([...signingAlgs, 'ES256K']);

/*
 * A key as read from the store or held in the keystore. Deliberately looser than `JWKS` (whose
 * per-kty union would need narrowing at every member read): the projection below touches members
 * that only exist on some key types, and treats a missing one as absent rather than as an error.
 */
export type JwkLike = {
	kty?: string;
	kid?: string;
	alg?: string;
	use?: string;
	crv?: string;
	e?: string;
	n?: string;
	x?: string;
	y?: string;
	x5c?: string[];
	key_ops?: string[];
};

// Whether encryption is enabled, captured by loadKeys from ApplicationConfig. Not read from
// ApplicationConfig here — that module awaits the config store at load, and importing it would put
// the await back into the model graph. It is boot-only configuration, and loadKeys runs on every
// key reload, so a captured copy and a live read are equivalent.
let encryptionEnabled = false;

// RFC 7638 JWK thumbprint over the required members (already in lexicographic order per kty).
function jwkThumbprint(key: JwkLike): string | undefined {
	let members;
	switch (key.kty) {
		case 'RSA':
			members = { e: key.e, kty: key.kty, n: key.n };
			break;
		case 'EC':
			members = { crv: key.crv, kty: key.kty, x: key.x, y: key.y };
			break;
		case 'OKP':
			members = { crv: key.crv, kty: key.kty, x: key.x };
			break;
		default:
			return undefined;
	}
	return crypto.hash('sha256', JSON.stringify(members), 'base64url');
}

function sigAlgForKey(key: JwkLike): string | undefined {
	if (key.kty === 'EC') {
		switch (key.crv) {
			case 'P-256':
				return 'ES256';
			case 'P-384':
				return 'ES384';
			case 'P-521':
				return 'ES512';
			default:
				return undefined;
		}
	}
	if (key.kty === 'OKP' && key.crv === 'Ed25519') {
		return 'EdDSA';
	}
	return undefined;
}

/*
 * toPublicJwk
 *
 * The client-safe projection of a key as published at /jwks: an explicit allow-list of members
 * (never a blocklist) so an unforeseen private component (d/p/q/dp/dq/qi/oth) can never leak.
 *
 * Normalizes on the way out: kid is derived from the RFC 7638 thumbprint when absent, and `use` is
 * inferred from an explicit `alg`. When encryption is disabled every key is signing-only, so `use`
 * defaults to 'sig' and a concrete alg is derived for EC/OKP keys.
 */
export function toPublicJwk(key: JwkLike): Record<string, unknown> {
	let { alg, use } = key;
	if (alg) {
		use ??= SIG_ALGS.has(alg) ? 'sig' : 'enc';
	} else if (!encryptionEnabled) {
		use ??= 'sig';
		alg ??= sigAlgForKey(key);
	}
	return {
		kty: key.kty,
		use,
		key_ops: key.key_ops ? [...key.key_ops] : undefined,
		kid: key.kid ?? jwkThumbprint(key),
		alg,
		crv: key.crv,
		e: key.e,
		n: key.n,
		x: key.x,
		x5c: key.x5c ? [...key.x5c] : undefined,
		y: key.y
	};
}

/*
 * loadKeys
 *
 * Replace the live key material with `keys`, in place. Called once at boot and again on every
 * reload from the key store (see configs/keys.ts) — the server's keys are never set any other way.
 */
export function loadKeys(keys: JwkLike[], encryption: boolean): void {
	encryptionEnabled = encryption;

	keystore.clear();
	// Cloned: the keystore hands these out for signing, and the caller's array must stay the
	// pristine snapshot of what the key store returned.
	for (const key of keys) keystore.add(structuredClone(key));

	publicJWKS.keys.length = 0;
	for (const key of keystore) publicJWKS.keys.push(toPublicJwk(key));
}
