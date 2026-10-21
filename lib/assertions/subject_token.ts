import type { TokenParams } from '../actions/token.js';
import { findAccount } from '../addon/account.js';
import { issuerFor } from '../configs/issuer.js';
import {
	ID_TOKEN_TYPE,
	REFRESH_TOKEN_TYPE
} from '../consts/assertion_grants.js';
import { InvalidRequest } from '../helpers/errors.js';
import type { Account, OIDCContext } from '../helpers/oidc_context.js';
import type { DPoPProof } from '../helpers/validate_dpop.js';
import { IdToken } from '../models/id_token.js';
import {
	RefreshTokenRefused,
	usableRefreshToken
} from '../shared/refresh_token_validation.js';

/*
 * The person a token exchange vouches for, read off its subject token (specs/108, ID-JAG §4.3): an ID token
 * this project issued to the application asking, or a refresh token it holds. Anything else, and any failure,
 * is `invalid_request` — RFC 8693 §2.2.2 says an invalid or unacceptable subject token "MUST" be. Neither
 * token is spent: an exchange "has no impact on the validity of the subject token" (RFC 8693 §2.1).
 */

export interface Subject {
	account: Account;
	/* The authentication the ID token recorded, which an ID-JAG may carry on (ID-JAG §3.1). */
	auth_time?: number;
	acr?: string;
	amr?: string[];
}

function refused(reason: string): InvalidRequest {
	return new InvalidRequest('subject_token is invalid', 400, reason);
}

async function fromIdToken(
	oidc: OIDCContext<TokenParams>,
	jwt: string
): Promise<Subject> {
	const { client } = oidc;
	/*
	 * A narrowing of ID-JAG §4.3 ("MUST accept Identity Assertions"), deliberately. A pairwise `sub` is a one-way
	 * digest of the account and the client's sector, and nothing maps it back — sessions are not indexed by the
	 * `sid` an ID token carries — so the project cannot tell whom such an ID token names. The refresh token the
	 * same application holds names the account directly, and the profile offers it as the subject for this.
	 */
	if (client.subjectType === 'pairwise') {
		throw new InvalidRequest(
			'an application with pairwise subject identifiers presents its refresh token as the subject_token',
			400,
			'pairwise'
		);
	}

	let verified;
	try {
		verified = await IdToken.verifyFresh(
			jwt,
			client,
			issuerFor(oidc.bucket),
			oidc.bucket
		);
	} catch {
		throw refused('id_token');
	}
	const { payload, header } = verified;
	/*
	 * The same keys sign this project's logout tokens and introspection responses for the same audience; they
	 * are typed, an ID token is not. A signed userinfo response is not typed either, but it is issued to the
	 * same application about the same person, so presenting it proves nothing an ID token would not.
	 */
	const typ =
		typeof header.typ === 'string' ? header.typ.toLowerCase() : undefined;
	if (typ !== undefined && typ !== 'jwt') throw refused('type');
	if (typeof payload.exp !== 'number' || typeof payload.iat !== 'number') {
		throw refused('lifetime');
	}

	const account = await findAccount(oidc, payload.sub);
	if (!account) throw refused('account');
	return {
		account,
		...(typeof payload.auth_time === 'number'
			? { auth_time: payload.auth_time }
			: {}),
		...(typeof payload.acr === 'string' ? { acr: payload.acr } : {}),
		...(Array.isArray(payload.amr) &&
		payload.amr.every((value) => typeof value === 'string')
			? { amr: payload.amr }
			: {})
	};
}

async function fromRefreshToken(
	oidc: OIDCContext<TokenParams>,
	value: string,
	dPoP: DPoPProof
): Promise<Subject> {
	try {
		const { account } = await usableRefreshToken(oidc, value, dPoP);
		/*
		 * ID-JAG §4.3.3: the person's claims are read as when a new identity assertion is issued, so the ID-JAG
		 * reflects them now — which is what reading the account rather than the token's copy does.
		 */
		return { account };
	} catch (error) {
		if (error instanceof RefreshTokenRefused) throw refused(error.reason);
		throw error;
	}
}

export async function subjectOf(
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
): Promise<Subject> {
	const { subject_token: token, subject_token_type: type } = oidc.params;
	if (!token || !type) {
		throw new InvalidRequest(
			'subject_token and subject_token_type are required'
		);
	}
	if (type === ID_TOKEN_TYPE) return fromIdToken(oidc, token);
	if (type === REFRESH_TOKEN_TYPE) return fromRefreshToken(oidc, token, dPoP);
	throw refused('unsupported_type');
}
