import * as crypto from 'node:crypto';
import {
	jwtVerify,
	EmbeddedJWK,
	calculateJwkThumbprint,
	type JWTPayload,
	type JWTHeaderParameters
} from 'jose';

import { ApplicationConfig as config } from 'lib/configs/application.js';
import { InvalidHeaderAuthorization, InvalidToken } from './errors.js';
import epochTime from './epoch_time.js';
import { DPoPNonces } from './dpop_nonces.js';
import { dPoPSigningAlgValues } from 'lib/configs/jwaAlgorithms.js';
import { HTTPHeaders } from 'elysia/types';
import { ReplayDetection } from 'lib/models/replay_detection.js';

export const DPOP_OK_WINDOW = 300;

export class InvalidDpopProof extends InvalidHeaderAuthorization {
	error = 'invalid_dpop_proof';
	name = 'InvalidDpopProof';
	status = 400;
}
export class UseDpopNonce extends InvalidHeaderAuthorization {
	error = 'use_dpop_nonce';
	name = 'UseDpopNonce';
	status = 400;
}

type options = {
	accessTokenId?: string;
	// The request's method, which the proof's `htm` must name (RFC 9449 §4.3).
	method?: string;
	route?: string;
	/*
	 * The identifier of the issuer the request was addressed to, which the proof's `htu` is built from.
	 * Required, because every bucket with an address is its own authorization server: built from the
	 * instance's identifier, `htu` matched the root's URL at every address, so a proof that named
	 * `/acme/token` was refused there.
	 */
	issuer: string;
};

// A verified DPoP proof, or undefined where none was presented or DPoP is off.
export type DPoPProof = Awaited<ReturnType<typeof dpopValidate>>;

export async function dpopValidate(
	proof: string | undefined,
	{ accessTokenId, method = 'POST', route, issuer }: options
) {
	if (!config['dpop.enabled'] || !proof) {
		return;
	}

	const dPoPInstance = DPoPNonces.fabrica();
	const requireNonce = config['dpop.requireNonce'];

	let payload: JWTPayload;
	let protectedHeader: JWTHeaderParameters;
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
				// A nonce can always be offered now, so this is always the recoverable answer. It used to
				// fall back to a flat invalid_dpop_proof when the server had no nonce secret, which told a
				// client its proof was bad when the truth was that the server could not help it — spec 014
				// removed that branch along with the state that produced it.
				throw new UseDpopNonce(
					'DPoP proof iat is not recent enough, use a DPoP nonce instead'
				);
			}
		}

		if (payload.htm !== method) {
			throw new InvalidDpopProof('DPoP proof htm mismatch');
		}

		{
			if (typeof payload.htu !== 'string' || !payload.htu) {
				return;
			}
			const actual = URL.parse(payload.htu);
			if (!actual) return;
			actual.hash = '';
			actual.search = '';

			// A route mounted beneath `/:bucket` arrives as that pattern; the issuer already carries the path.
			const endpoint = route?.startsWith('/:bucket/')
				? route.slice('/:bucket'.length)
				: route;
			if (endpoint === undefined || actual.href !== issuer + endpoint) {
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
		throw new InvalidDpopProof(
			'invalid DPoP key binding',
			err instanceof Error ? err.message : String(err)
		);
	}

	if (!payload.nonce && requireNonce) {
		throw new UseDpopNonce('nonce is required in the DPoP proof');
	}

	if (payload.nonce && !dPoPInstance.checkNonce(payload.nonce)) {
		throw new UseDpopNonce('invalid nonce in DPoP proof');
	}

	/*if (payload.nonce !== nextNonce) {
		ctx.set('DPoP-Nonce', nextNonce);
	}*/

	if (!protectedHeader.jwk) {
		throw new UseDpopNonce('invalid Signed JWT Header Parameter jwk in DPoP');
	}
	const thumbprint = await calculateJwkThumbprint(protectedHeader.jwk);

	return {
		thumbprint,
		jti: payload.jti,
		iat: payload.iat,
		nonce: payload.nonce
	};
}

export function setNonceHeader(
	headers: HTTPHeaders,
	dPoP: { nonce?: string } | undefined
) {
	if (!dPoP?.nonce) {
		return;
	}

	const dPoPInstance = DPoPNonces.fabrica();
	if (dPoP.nonce !== dPoPInstance.nextNonce()) {
		headers['DPoP-Nonce'] = dPoPInstance.nextNonce();
	}
}

export async function validateReplay(
	clientId: string,
	dPoP: Awaited<ReturnType<typeof dpopValidate>>
) {
	if (!dPoP) {
		return;
	}
	if (!config['dpop.allowReplay']) {
		/*
		 * A proof without a nonce is accepted while its iat is within the window of now, so one dated ahead
		 * of this server's clock stays acceptable until iat + window, up to twice the window after it is first
		 * seen. The record has to last that long: kept for the window from now, a captured request was
		 * replayable once it expired. Clamped, because a proof carrying a nonce has its iat unchecked and
		 * takes its freshness from the nonce, which ages out within the window.
		 */
		const now = epochTime();
		const ahead = Math.min(Math.max(dPoP.iat - now, 0), DPOP_OK_WINDOW);
		const unique = await ReplayDetection.unique(
			clientId,
			dPoP.jti,
			now + DPOP_OK_WINDOW + ahead
		);
		if (!unique) {
			throw new InvalidToken('DPoP proof JWT Replay detected');
		}
	}
}
