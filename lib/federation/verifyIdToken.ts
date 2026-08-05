import { errors as joseErrors, jwtVerify } from 'jose';

import * as JWT from '../helpers/jwt.js';
import { clockTolerance } from '../configs/liveTime.js';
import { idTokenSigningAlgValues } from '../configs/jwaAlgorithms.js';
import epochTime from '../helpers/epoch_time.js';
import { keySetFor } from './jwks.js';
import type { ProviderMetadata } from './discovery.js';

/*
 * Prove an upstream provider issued this identity assertion, to us, for this attempt — and return what it
 * says.
 *
 * Structured after lib/admin/auth/verifyIdToken.ts rather than generalised from it: that verifier is bound
 * to this server as issuer at three points (its keystore, its ISSUER, and the console client whose
 * registered algorithm it reads), so parameterising all three would leave both callers reading a function
 * every input of which is a variable. What is copied is its discipline — one failure type so no path
 * escapes as a server fault, and every claim read only after the signature verifies.
 *
 * jose's jwtVerify covers the signature, `iss`, `aud`, `exp` and the algorithm allowlist. The checks below
 * it are the ones it does not make.
 */

export type IdTokenRejectionReason =
	| 'missing'
	| 'malformed'
	| 'algorithm'
	| 'signature'
	| 'issuer'
	| 'audience'
	| 'azp'
	| 'expired'
	| 'issued_in_future'
	| 'subject'
	| 'nonce'
	| 'unverifiable';

export class FederationIdTokenRejected extends Error {
	readonly reason: IdTokenRejectionReason;

	constructor(reason: IdTokenRejectionReason) {
		super(`federated id_token rejected: ${reason}`);
		this.reason = reason;
	}
}

/*
 * Why a mapping rather than a rethrow: the refusal *is* the throw, so a reason landing in the wrong bucket
 * costs a diagnostic label and never a wrong authorization decision. jose's classes are matched
 * structurally; anything unrecognised is reported as unclassified rather than guessed at.
 */
function reasonFor(err: unknown): IdTokenRejectionReason {
	if (
		err instanceof joseErrors.JWKSNoMatchingKey ||
		err instanceof joseErrors.JWSSignatureVerificationFailed
	) {
		return 'signature';
	}
	if (
		err instanceof joseErrors.JWSInvalid ||
		err instanceof joseErrors.JWTInvalid ||
		err instanceof joseErrors.JOSENotSupported ||
		err instanceof TypeError ||
		err instanceof SyntaxError
	) {
		return 'malformed';
	}
	if (err instanceof joseErrors.JWTExpired) return 'expired';
	if (err instanceof joseErrors.JWTClaimValidationFailed) {
		if (err.claim === 'iss') return 'issuer';
		if (err.claim === 'aud') return 'audience';
		if (err.claim === 'nonce') return 'nonce';
		if (err.claim === 'sub') return 'subject';
		return 'unverifiable';
	}
	return 'unverifiable';
}

export interface VerifiedAssertion {
	subject: string;
	claims: Record<string, unknown>;
}

/*
 * The algorithms this exchange may accept: the intersection of what the provider advertises and what this
 * server supports. An empty intersection is refused rather than defaulted — signing algorithm is not a
 * thing to guess at, and a provider advertising none it shares with us is unusable, not permissive.
 *
 * `alg: none` cannot survive this by construction — it is in neither list, so the header check below
 * refuses it as an algorithm violation before jose is reached at all. A test pins the refusal anyway,
 * because "cannot happen" is a claim.
 */
function acceptableAlgorithms(metadata: ProviderMetadata): string[] {
	const ours = new Set<string>(idTokenSigningAlgValues as unknown as string[]);
	const advertised = metadata.signingAlgValues.filter((alg) => ours.has(alg));
	if (advertised.length === 0) {
		throw new FederationIdTokenRejected('algorithm');
	}
	return advertised;
}

export async function verifyFederatedIdToken(
	idToken: string | undefined,
	expected: { metadata: ProviderMetadata; clientId: string; nonce: string }
): Promise<VerifiedAssertion> {
	if (typeof idToken !== 'string' || idToken.length === 0) {
		throw new FederationIdTokenRejected('missing');
	}

	const algorithms = acceptableAlgorithms(expected.metadata);

	/*
	 * The header's algorithm is checked before verification, so an unsecured or wrong-algorithm token is
	 * refused as the algorithm violation it is rather than surfacing as an unclassified key failure from
	 * inside jose. Same ordering, and the same reason, as lib/admin/auth/verifyIdToken.ts.
	 */
	let header: Record<string, unknown>;
	try {
		header = JWT.header(idToken);
	} catch {
		throw new FederationIdTokenRejected('malformed');
	}
	if (typeof header.alg !== 'string' || !algorithms.includes(header.alg)) {
		throw new FederationIdTokenRejected('algorithm');
	}

	let payload: Record<string, unknown>;
	try {
		const verified = await jwtVerify(
			idToken,
			keySetFor(expected.metadata.jwksUri),
			{
				issuer: expected.metadata.issuer,
				audience: expected.clientId,
				algorithms,
				clockTolerance
			}
		);
		payload = verified.payload as Record<string, unknown>;
	} catch (err) {
		throw new FederationIdTokenRejected(reasonFor(err));
	}

	// Every claim below is read only after the signature verified.

	/*
	 * OIDC Core 3.1.3.7 rule 4: with more than one audience the party the token was issued for must be
	 * identified. Written as the rule rather than as a special case, so it stays right whatever a provider
	 * chooses to emit.
	 */
	if (Array.isArray(payload.aud) && payload.aud.length > 1) {
		if (payload.azp !== expected.clientId) {
			throw new FederationIdTokenRejected('azp');
		}
	}

	/*
	 * jose compares `iat` against now only when `exp` is absent, and an ID token always carries `exp` — so
	 * this comparison has to live here or it never runs. Same reasoning as the admin verifier's.
	 */
	if (
		typeof payload.iat === 'number' &&
		payload.iat > epochTime() + clockTolerance
	) {
		throw new FederationIdTokenRejected('issued_in_future');
	}

	/*
	 * OIDC Core 3.1.3.7 rule 11, and the replay defence: `nonce` ties this assertion to the request that
	 * started it, so a genuine token captured from another sign-in cannot be replayed into this one. Both
	 * sides are non-empty by construction — the start route always mints one — so an absent claim fails the
	 * comparison rather than passing it vacuously.
	 */
	if (
		typeof payload.nonce !== 'string' ||
		payload.nonce.length === 0 ||
		payload.nonce !== expected.nonce
	) {
		throw new FederationIdTokenRejected('nonce');
	}

	if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
		throw new FederationIdTokenRejected('subject');
	}

	return { subject: payload.sub, claims: payload };
}
