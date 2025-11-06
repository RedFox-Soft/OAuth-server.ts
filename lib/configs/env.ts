import { verifyJWKs } from 'lib/configs/verifyJWKs.js';

const issuer = process.env.ISSUER;
if (!issuer) {
	throw new Error('ISSUER environment variable is not set');
}

export const ISSUER = issuer;

/*
 * jwks
 *
 * description: JSON Web Key Set used by the authorization server for signing and decryption. The object must
 * be in [JWK Set format](https://www.rfc-editor.org/rfc/rfc7517.html#section-5). All provided keys must
 * be private keys.
 *
 * Supported key types are:
 *
 * - RSA
 * - OKP (Ed25519 and X25519 sub types)
 * - EC (P-256, P-384, and P-521 curves)
 *
 * recommendation: Be sure to follow best practices for distributing private keying material and secrets
 * for your respective target deployment environment.
 *
 * recommendation: The following action order is recommended when rotating signing keys on a distributed
 * deployment with rolling reloads in place.
 *
 * 1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become
 *    available for verification should they be encountered but not yet used for signing
 * 2. reload all your processes
 * 3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be
 *    used for signing after reload
 * 4. reload all your processes
 *
 */
const JWKS = JSON.parse(process.env.JWKS ?? '');
if (!JWKS || verifyJWKs(JWKS) === false) {
	throw new Error('JWKS environment variable is not set');
}

export const JWKS_KEYS = JWKS.keys;
