import type { Client } from 'lib/models/client.js';
import type { IdToken } from 'lib/models/id_token.js';

/*
 * clockTolerance
 *
 * description: A `Number` value (in seconds) describing the allowed system clock skew for
 *   validating client-provided JWTs, e.g. Request Objects, DPoP Proofs and otherwise comparing
 *   timestamps
 * recommendation: Only set this to a reasonable value when needed to cover server-side client and
 *   oidc-provider server clock skew.
 */
export const clockTolerance = 10;

/*
 * ttl
 *
 * description: description: Expirations for various token and session types.
 * The value can be a number (in seconds) or a synchronous function that dynamically returns
 * value based on the context.
 *
 * recommendation: Do not set token TTLs longer then they absolutely have to be, the shorter
 * the TTL, the better.
 *
 * recommendation: Rather than setting crazy high Refresh Token TTL look into `rotateRefreshToken`
 * configuration option which is set up in way that when refresh tokens are regularly used they
 * will have their TTL refreshed (via rotation).
 */
export const ttl = {
	AccessToken(token, client) {
		return token.resourceServer?.accessTokenTTL || 60 * 60; // 1 hour in seconds
	},
	AuthorizationCode(code, client) {
		return 60; // 1 minute in seconds
	},
	BackchannelAuthenticationRequest(ctx, request, client) {
		if (ctx?.oidc?.params.requested_expiry) {
			return Math.min(10 * 60, +ctx.oidc.params.requested_expiry); // 10 minutes in seconds or requested_expiry, whichever is shorter
		}

		return 10 * 60; // 10 minutes in seconds
	},
	ClientCredentials(token, client) {
		return token.resourceServer?.accessTokenTTL || 10 * 60; // 10 minutes in seconds
	},
	DeviceCode(deviceCode, client) {
		return 10 * 60; // 10 minutes in seconds
	},
	Grant(grant, client) {
		return 14 * 24 * 60 * 60; // 14 days in seconds
	},
	IdToken(token: IdToken, client: Client) {
		return 60 * 60; // 1 hour in seconds
	},
	Interaction(interaction) {
		return 60 * 60; // 1 hour in seconds
	},
	RefreshToken(ctx, token, client) {
		if (
			ctx?.oidc?.entities.RotatedRefreshToken &&
			client.applicationType === 'web' &&
			client.clientAuthMethod === 'none' &&
			!token.isSenderConstrained()
		) {
			// Non-Sender Constrained SPA RefreshTokens do not have infinite expiration through rotation
			return ctx.oidc.entities.RotatedRefreshToken.remainingTTL;
		}

		return 14 * 24 * 60 * 60; // 14 days in seconds
	},
	Session(ctx, session) {
		return 14 * 24 * 60 * 60; // 14 days in seconds
	}
};
