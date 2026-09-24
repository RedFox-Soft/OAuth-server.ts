import type { Client } from 'lib/models/client.js';
import type { IdToken } from 'lib/models/id_token.js';
import type { AccessToken } from 'lib/models/access_token.js';
import type { AuthorizationCode } from 'lib/models/authorization_code.js';
import type { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import type { ClientCredentials } from 'lib/models/client_credentials.js';
import type { DeviceCode } from 'lib/models/device_code.js';
import type { Grant } from 'lib/models/grant.js';
import type { RefreshToken } from 'lib/models/refresh_token.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { isRecord } from 'lib/helpers/_/object.js';

/*
 * The constant which determines how many bits of randomness the opaque token should have. 256 bits is the same as the default for uuidv4, and is considered sufficient for security purposes. It also results in a token length of 43 characters when using nanoid, which is a reasonable length for an opaque token.
 * If you want to increase the security of the opaque tokens, you can increase this constant. However, keep in mind that increasing the number of bits will also increase the length of the generated token, which may have implications for storage and transmission.
 * For most applications, 256 bits should be more than enough to ensure the security of opaque tokens.
 */
export const bitsOfOpaqueRandomness = 256;

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
	AccessToken(token: AccessToken, _client: Client | undefined) {
		return token.resourceServer?.accessTokenTTL || 60 * 60; // 1 hour in seconds
	},
	AuthorizationCode(_code: AuthorizationCode, _client: Client | undefined) {
		return 60; // 1 minute in seconds
	},
	BackchannelAuthenticationRequest(
		request: BackchannelAuthenticationRequest,
		_client: Client | undefined
	) {
		const { params } = request.payload;
		const requestedExpiry = isRecord(params)
			? params.requested_expiry
			: undefined;
		if (
			requestedExpiry &&
			(typeof requestedExpiry === 'number' ||
				typeof requestedExpiry === 'string')
		) {
			return Math.min(10 * 60, +requestedExpiry); // 10 minutes in seconds or requested_expiry, whichever is shorter
		}

		return 10 * 60; // 10 minutes in seconds
	},
	ClientCredentials(token: ClientCredentials, _client: Client | undefined) {
		return token.resourceServer?.accessTokenTTL || 10 * 60; // 10 minutes in seconds
	},
	DeviceCode(_deviceCode: DeviceCode, _client: Client | undefined) {
		return 10 * 60; // 10 minutes in seconds
	},
	Grant(_grant: Grant, _client: Client | undefined) {
		return 14 * 24 * 60 * 60; // 14 days in seconds
	},
	IdToken(_token: IdToken, _client: Client | undefined) {
		return 60 * 60; // 1 hour in seconds
	},
	RefreshToken(token: RefreshToken, client: Client | undefined) {
		const lifetime = 14 * 24 * 60 * 60; // 14 days in seconds
		/*
		 * A browser application's chain ends when its first token would have: rotation carries the
		 * remaining lifetime forward instead of starting a new one, so a stolen token cannot be kept
		 * alive by using it. Decided from the token's own record — `iiat` is the chain's first issuance
		 * and survives every rotation — because a lifetime is computed whenever it is first read, not
		 * necessarily inside a request. The rule once read the rotated token off an ambient request
		 * store; when that store stopped being filled (54ba556) it went silently dead.
		 *
		 * Floored at one second, not zero: a zero lifetime reads as "not computed yet" to the token.
		 */
		if (
			(token.payload.rotations ?? 0) >= 1 &&
			client?.applicationType === 'web' &&
			client.tokenEndpointAuthMethod === 'none' &&
			!token.isSenderConstrained()
		) {
			return Math.max(1, token.payload.iiat + lifetime - epochTime());
		}

		return lifetime;
	},
	Interaction: 60 * 60, // 1 hour in seconds
	Session: 14 * 24 * 60 * 60 // 14 days in seconds
};
