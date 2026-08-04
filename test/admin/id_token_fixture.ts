import * as JWT from 'lib/helpers/jwt.ts';
import { keystore } from 'lib/configs/keystore.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { ADMIN_CLIENT_ID } from 'lib/admin/consts.ts';

import generatedKeys from '../keys.ts';

/*
 * Admin ID token fixtures.
 *
 * Minted through the server's own JWT.sign against the live keystore, so a fixture and the real
 * issuer cannot drift: if signing and verification ever disagree, the happy-path test fails first
 * rather than a negative case passing for the wrong reason.
 *
 * A claim may be dropped by passing it as `undefined` — JWT.sign assigns the registered claims onto
 * the payload and JSON.stringify omits undefined values, so `{ sub: undefined }` mints a token with
 * no `sub`.
 */

export type Claims = Record<string, unknown>;

type MintOptions = {
	// Defaults to RS256 — the algorithm the admin client is registered for.
	alg?: string;
	// Signs with this key instead of the live one. Used for the foreign-key forgeries.
	key?: Record<string, unknown>;
	// Advertised `kid`. Defaults to the signing key's own; a forgery sets it to a live key's kid so
	// that key selection succeeds and the signature check is what refuses the token.
	kid?: string;
};

// A key's `kid` is `unknown` until read, because a key is an open bag of JWK members here.
export function kidOf(key: Record<string, unknown>): string | undefined {
	return typeof key.kid === 'string' ? key.kid : undefined;
}

export function liveSigningKey(alg = 'RS256'): Record<string, unknown> {
	const [key] = keystore.selectForSign({ alg });
	if (!key) throw new Error(`live keystore holds no ${alg} signing key`);
	return key;
}

/*
 * The RSA key in the live set whose modulus matches `n`. Used after seeding an extra RS256 key, where
 * selectForSign returns several candidates and the test needs one specific member.
 */
export function liveKeyByModulus(n: unknown): Record<string, unknown> {
	for (const key of keystore) {
		if (key.kty === 'RSA' && key.n === n) return key;
	}
	throw new Error('no live RSA key with that modulus');
}

/*
 * A key the server does not hold, by construction: test/keys.ts generates a fresh pair per run, so it
 * can never collide with the seeded fixture set.
 */
export function foreignKey(alg = 'RS256'): Record<string, unknown> {
	const key = generatedKeys.find((candidate) => candidate.alg === alg);
	if (!key) throw new Error(`no generated ${alg} key to forge with`);
	return key;
}

export async function mintAdminIdToken(
	claims: Claims = {},
	options: MintOptions = {}
): Promise<string> {
	const alg = options.alg ?? 'RS256';
	const key = options.key ?? liveSigningKey(alg);
	const now = epochTime();

	const payload: Claims = {
		iss: ISSUER,
		aud: ADMIN_CLIENT_ID,
		iat: now,
		exp: now + 300,
		...claims
	};

	return JWT.sign(payload, key, alg, {
		fields: { kid: options.kid ?? kidOf(key) }
	});
}

/*
 * A token signed by a key the server does not hold, advertising a live `kid` by default so key
 * selection succeeds and the refusal comes from the signature itself rather than from a missing key.
 */
export async function mintWithForeignKey(
	claims: Claims = {},
	options: { alg?: string; kid?: string | null } = {}
): Promise<string> {
	const alg = options.alg ?? 'RS256';
	const kid =
		options.kid === null
			? undefined
			: (options.kid ?? kidOf(liveSigningKey(alg)));

	return mintAdminIdToken(claims, { alg, key: foreignKey(alg), kid });
}

/*
 * Re-encode the payload segment while keeping the original header and signature — the classic
 * forgery, and the one the removed base64url-decode shortcut accepted without question.
 */
export function tamperPayload(token: string, claims: Claims): string {
	const [header, payload, signature] = token.split('.');
	const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
	const forged = Buffer.from(
		JSON.stringify({ ...decoded, ...claims })
	).toString('base64url');
	return `${header}.${forged}.${signature}`;
}

// An unsecured JWS: `alg: none` with an empty signature (RFC 7515 appendix A.5).
export function mintUnsecured(claims: Claims = {}): string {
	const now = epochTime();
	const segment = (value: unknown) =>
		Buffer.from(JSON.stringify(value)).toString('base64url');
	return `${segment({ alg: 'none' })}.${segment({
		iss: ISSUER,
		aud: ADMIN_CLIENT_ID,
		iat: now,
		exp: now + 300,
		...claims
	})}.`;
}
