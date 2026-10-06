import crypto from 'crypto';
import { STATIC_TOKEN_PREFIX } from '../consts/scim.js';

/*
 * A connection's secrets: generated here, shown once, stored only as a digest.
 *
 * An unsalted SHA-256 is sound for these and only these: each value carries 256 bits from the CSPRNG, so
 * there is no dictionary to precompute and a salt would buy nothing — the reasoning
 * lib/password_reset/challenge.ts records for its reset secrets. A password hash would be the wrong tool:
 * its cost is spent on every SCIM request, and its point is to slow a guess at a low-entropy value.
 */

function random256(): string {
	return crypto.randomBytes(32).toString('base64url');
}

export function newConnectionSecret(): string {
	return random256();
}

export function newStaticToken(): string {
	return `${STATIC_TOKEN_PREFIX}${random256()}`;
}

export function digestOf(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

export function isStaticToken(value: string): boolean {
	return value.startsWith(STATIC_TOKEN_PREFIX);
}
