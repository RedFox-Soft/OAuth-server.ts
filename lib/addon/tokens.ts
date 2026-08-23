import crypto from 'node:crypto';

import nanoid from '../helpers/nanoid.ts';
import { pairwiseSalt } from '../configs/pairwiseSalt.ts';
import { TemporarilyUnavailable } from '../helpers/errors.ts';

export function idFactory(_ctx) {
	return nanoid();
}

export async function secretFactory(_ctx) {
	return crypto.randomBytes(64).toString('base64url');
}

// Decides whether the given artifact is bound to the end-user session; the
// default binds everything except offline_access grants so they survive logout.
export async function expiresWithSession(ctx, code) {
	return !code.scopes.has('offline_access');
}

// Decides whether a refresh token is issued for this exchange (grant advertisement
// is a separate concern owned by ApplicationConfig['refreshToken.enabled']).
export async function issueRefreshToken(ctx, client, code) {
	return (
		client.grantTypeAllowed('refresh_token') &&
		code.scopes.has('offline_access')
	);
}

/*
 * The pseudonym a relying party receives instead of the account's own identifier, scoped to the
 * client's sector. It is that relying party's account key, so it has to be reproducible for as long
 * as the account exists — across restarts, hosts and instances.
 *
 * The salt used to be `os.hostname()`, which made it reproducible for as long as one container lived.
 * It now comes from persistent server state (configs/pairwiseSalt.ts), resolved once at startup.
 *
 * When there is no usable salt the request is refused rather than answered with a freshly derived
 * identifier. That asymmetry is the point: an identifier derived from a salt the server cannot
 * reproduce is worse than no identifier at all, because the relying party would store it and treat
 * the same person as a new account on the next restart. Refusing here covers every surface at once —
 * ID token, userinfo, introspection, interaction prompts and back-channel logout all reach the
 * derivation through this one function.
 */
export async function pairwiseIdentifier(accountId, client) {
	const salt = pairwiseSalt();

	if (salt === null) {
		// Per refusal, not just once at startup: the startup line scrolls away, and this is the only
		// place that knows a real request was turned down because of it.
		console.warn(
			`refusing a pairwise identifier for client ${client.clientId}: the server has no usable ` +
				'pairwise salt, so any sub it derived now would change on the next restart. Repair the ' +
				'stored salt; every non-pairwise client is unaffected.'
		);
		throw new TemporarilyUnavailable(
			'the request cannot be served at this time',
			'no usable pairwise identifier salt; see the startup warning from configs/pairwiseSalt.ts'
		);
	}

	return crypto
		.createHash('sha256')
		.update(client.sectorIdentifier)
		.update(accountId)
		.update(salt)
		.digest('hex');
}

// Decides if and how a refresh token is rotated after use. Returns a Boolean;
// the default rotates public-client and near-expiry tokens (capped at ~1 year).
export function rotateRefreshToken(ctx) {
	const { RefreshToken: refreshToken, Client: client } = ctx.oidc.entities;

	// cap the maximum amount of time a refresh token can be
	// rotated for up to 1 year, afterwards its TTL is final
	if (refreshToken.totalLifetime() >= 365.25 * 24 * 60 * 60) {
		return false;
	}

	// rotate non sender-constrained public client refresh tokens
	if (
		client.clientAuthMethod === 'none' &&
		!refreshToken.isSenderConstrained()
	) {
		return true;
	}

	// rotate if the token is nearing expiration (it's beyond 70% of its lifetime)
	return refreshToken.ttlPercentagePassed() >= 70;
}
