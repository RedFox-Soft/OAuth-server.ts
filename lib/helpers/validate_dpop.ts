import * as crypto from 'node:crypto';
import { jwtVerify, EmbeddedJWK, calculateJwkThumbprint } from 'jose';

import { ApplicationConfig as config } from 'lib/configs/application.js';
import { InvalidHeaderAuthorization } from './errors.js';
import epochTime from './epoch_time.js';
import { ISSUER } from 'lib/configs/env.js';
import { DPoPNonces } from './dpop_nonces.js';
import { dPoPSigningAlgValues } from 'lib/configs/jwaAlgorithms.js';

const weakMap = new WeakMap();
export const DPOP_OK_WINDOW = 300;

class InvalidDpopProof extends InvalidHeaderAuthorization {
	message = 'invalid_dpop_proof';
	name = 'InvalidDpopProof';
}
export class UseDpopNonce extends InvalidHeaderAuthorization {
	message = 'use_dpop_nonce';
	name = 'UseDpopNonce';
}

type options = {
	accessTokenId?: string;
	method?: 'GET' | 'POST';
	route?: string;
};

export default async (
	ctx,
	{ accessTokenId, method = 'POST', route }: options = {}
) => {
	if (weakMap.has(ctx)) {
		return weakMap.get(ctx);
	}

	const proof = ctx.headers['dpop'];
	if (!config['dpop.enabled'] || !proof) {
		return undefined;
	}

	const dPoPInstance = DPoPNonces.fabrica();
	const requireNonce = config['dpop.requireNonce'];
	if (requireNonce && !dPoPInstance) {
		throw new Error('features.dPoP.nonceSecret configuration is missing');
	}

	const nextNonce = dPoPInstance?.nextNonce();
	let payload;
	let protectedHeader;
	try {
		({ protectedHeader, payload } = await jwtVerify(proof, EmbeddedJWK, {
			algorithms: dPoPSigningAlgValues,
			typ: 'dpop+jwt'
		}));

		if (typeof payload.iat !== 'number' || !payload.iat) {
			throw new InvalidDpopProof('DPoP proof must have a iat number property');
		}

		if (typeof payload.jti !== 'string' || !payload.jti) {
			throw new InvalidDpopProof('DPoP proof must have a jti string property');
		}

		if (payload.nonce !== undefined && typeof payload.nonce !== 'string') {
			throw new InvalidDpopProof('DPoP proof nonce must be a string');
		}

		if (!payload.nonce) {
			const now = epochTime();
			const diff = Math.abs(now - payload.iat);
			if (diff > DPOP_OK_WINDOW) {
				if (dPoPInstance) {
					ctx.set('DPoP-Nonce', nextNonce);
					throw new UseDpopNonce(
						'DPoP proof iat is not recent enough, use a DPoP nonce instead'
					);
				}
				throw new InvalidDpopProof('DPoP proof iat is not recent enough');
			}
		} else if (!dPoPInstance) {
			throw new InvalidDpopProof('DPoP nonces are not supported');
		}

		if (payload.htm !== method) {
			throw new InvalidDpopProof('DPoP proof htm mismatch');
		}

		{
			const actual = URL.parse(payload.htu);
			if (!actual) return false;
			actual.hash = '';
			actual.search = '';

			if (actual?.href !== ISSUER + route) {
				throw new InvalidDpopProof('DPoP proof htu mismatch');
			}
		}

		if (accessTokenId) {
			const ath = crypto.hash('sha256', accessTokenId, 'base64url');
			if (payload.ath !== ath) {
				throw new InvalidDpopProof('DPoP proof ath mismatch');
			}
		}
	} catch (err) {
		if (err instanceof InvalidDpopProof || err instanceof UseDpopNonce) {
			throw err;
		}
		throw new InvalidDpopProof('invalid DPoP key binding', err.message);
	}

	if (!payload.nonce && requireNonce) {
		ctx.set('DPoP-Nonce', nextNonce);
		throw new UseDpopNonce('nonce is required in the DPoP proof');
	}

	if (payload.nonce && !dPoPInstance?.checkNonce(payload.nonce)) {
		ctx.set('DPoP-Nonce', nextNonce);
		throw new UseDpopNonce('invalid nonce in DPoP proof');
	}

	if (payload.nonce !== nextNonce) {
		ctx.set('DPoP-Nonce', nextNonce);
	}

	const thumbprint = await calculateJwkThumbprint(protectedHeader.jwk);

	const result = { thumbprint, jti: payload.jti, iat: payload.iat };
	weakMap.set(ctx, result);

	return result;
};
