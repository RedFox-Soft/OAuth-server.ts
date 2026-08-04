import { errors as joseErrors } from 'jose';

import * as JWT from '../../helpers/jwt.js';
import epochTime from '../../helpers/epoch_time.js';
import { keystore } from '../../configs/keystore.js';
import { clockTolerance } from '../../configs/liveTime.js';
import { ISSUER } from '../../configs/env.js';
import { Client } from '../../models/client.js';
import { ADMIN_CLIENT_ID } from '../consts.js';

/*
 * The admin console is a relying party on identity tokens this very server issued to it, so it owes
 * them the same scrutiny an external RP would: OIDC Core 3.1.3.7. Being the issuer is not a licence to
 * skip verification — the console cannot tell a token it minted from one an attacker supplied without
 * checking the signature, and whoever controls that value names themselves any operator.
 *
 * The signature and registered-claim work is delegated to helpers/jwt.ts, the same engine
 * IdToken.validate uses for id_token_hint. Only the checks that engine does not make live here.
 */

export type IdTokenRejectionReason =
	| 'missing'
	| 'malformed'
	| 'client_unresolved'
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

export class IdTokenRejected extends Error {
	readonly reason: IdTokenRejectionReason;

	constructor(reason: IdTokenRejectionReason) {
		super(`admin id_token rejected: ${reason}`);
		this.reason = reason;
	}
}

/*
 * Why a mapping and not a rethrow: the refusal is the throw itself, so a reason that lands in the
 * wrong bucket costs a diagnostic label and never a wrong authorization decision. The two jose classes
 * are matched structurally; the rest are messages from helpers/jwt.ts, which is this repository's own
 * code, and anything unrecognised is reported as unclassified rather than guessed at.
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

	const message = err instanceof Error ? err.message : '';
	if (message === 'jwt expired') return 'expired';
	if (message === 'jwt issuer invalid') return 'issuer';
	if (message.startsWith('jwt audience missing')) return 'audience';
	if (message === 'invalid sub value') return 'subject';
	if (
		message === 'jwt issued in the future' ||
		message === 'jwt not active yet'
	) {
		return 'issued_in_future';
	}
	return 'unverifiable';
}

/*
 * The algorithm the issuer would have signed with — read from the same client field id_token.ts reads
 * when it signs (models/id_token.ts), so verifier and issuer cannot disagree. Read through the model
 * rather than off the stored payload because a stored client record mixes camelCase and snake_case
 * spellings and only validateClient normalizes them.
 *
 * A symmetric algorithm is refused outright: the admin console is registered with no client
 * authentication, so no shared secret exists to verify against. Refusing by policy makes the state
 * unrepresentable instead of leaving it to fail on the absence of an `oct` key.
 */
async function expectedAlgorithm(): Promise<string> {
	let client;
	try {
		client = await Client.tryFind(ADMIN_CLIENT_ID);
	} catch {
		throw new IdTokenRejected('client_unresolved');
	}
	if (!client) throw new IdTokenRejected('client_unresolved');

	const alg = client.idTokenSignedResponseAlg;
	if (typeof alg !== 'string' || alg.startsWith('HS')) {
		throw new IdTokenRejected('algorithm');
	}
	return alg;
}

/*
 * Prove `idToken` was issued by this server, to the admin console, and return the subject it names.
 * Throws IdTokenRejected for every failure — the caller has one failure type to handle, so no path can
 * escape as a server fault. Emits nothing and writes nothing: the route owns the response and the
 * diagnostic.
 */
export async function verifyAdminIdToken(
	idToken: string | undefined,
	expected: { nonce: string }
): Promise<string> {
	if (typeof idToken !== 'string' || idToken.length === 0) {
		throw new IdTokenRejected('missing');
	}

	const alg = await expectedAlgorithm();

	let header: Record<string, unknown>;
	try {
		header = JWT.header(idToken);
	} catch {
		throw new IdTokenRejected('malformed');
	}
	// Checked before verifying so an unsecured token is refused as an algorithm violation, which is
	// what it is, rather than reaching key selection and failing on an unresolvable key type.
	if (header.alg !== alg) throw new IdTokenRejected('algorithm');

	let payload;
	try {
		({ payload } = await JWT.verify(idToken, keystore, {
			algorithm: alg,
			issuer: ISSUER,
			audience: ADMIN_CLIENT_ID,
			subject: true,
			clockTolerance
		}));
	} catch (err) {
		throw new IdTokenRejected(reasonFor(err));
	}

	// Every claim below is read only after the signature verified.

	// OIDC Core 3.1.3.7 rule 4: with more than one audience, the party the token was issued for must
	// be identified. This server emits no `azp`, so a multi-audience token is always refused — which is
	// correct, because it is not a token this server issues to the console. Written as the rule so it
	// stays right if `azp` is ever emitted.
	if (Array.isArray(payload.aud) && payload.aud.length > 1) {
		if (payload.azp !== ADMIN_CLIENT_ID) throw new IdTokenRejected('azp');
	}

	// assertPayload only compares `iat` against now when `exp` is absent, and an ID token always
	// carries `exp` — so this comparison has to live here or it never runs.
	if (
		typeof payload.iat === 'number' &&
		payload.iat > epochTime() + clockTolerance
	) {
		throw new IdTokenRejected('issued_in_future');
	}

	// OIDC Core 3.1.3.7 rule 11. Both sides are non-empty by construction — the login route always
	// mints one — so an absent claim fails the comparison rather than passing it vacuously.
	if (
		typeof payload.nonce !== 'string' ||
		payload.nonce.length === 0 ||
		payload.nonce !== expected.nonce
	) {
		throw new IdTokenRejected('nonce');
	}

	// `subject: true` above already refused an absent `sub`, but assertPayload asserts the payload
	// type, not this field's presence — so narrowing here is what makes the return type honest
	// instead of asserted.
	if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
		throw new IdTokenRejected('subject');
	}
	return payload.sub;
}
