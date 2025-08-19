import { verifyJWKs } from 'lib/configs/verifyJWKs.js';

const issuer = process.env.ISSUER;
if (!issuer) {
	throw new Error('ISSUER environment variable is not set');
}

export const ISSUER = issuer;

const JWKS = JSON.parse(process.env.JWKS ?? '');
if (!JWKS || verifyJWKs(JWKS) === false) {
	throw new Error('JWKS environment variable is not set');
}

export const JWKS_KEYS = JWKS.keys;
