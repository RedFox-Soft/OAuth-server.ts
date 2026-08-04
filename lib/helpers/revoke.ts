import { DeviceCode } from 'lib/models/device_code.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';
import { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import { eventBus } from 'lib/event_bus.js';

/*
 * Revokes every token issued under one grant, across all five grantable areas, unconditionally.
 *
 * The grant-type filter this replaced asked the client whether it still allowed each grant type before
 * revoking that area. It was wrong twice over. Narrowing a client's grant types after issuance left its
 * refresh tokens un-revokable on MongoDB — while on the in-memory adapter the first call wiped every
 * area regardless, so the two adapters disagreed about what revocation meant. And on the end-session
 * path `oidc.client` is the *logout-initiating* client, applied to every authorization in the session,
 * so the filter consulted an unrelated client's grant types to decide another client's tokens' fate.
 * Dropping it costs at most four deletes that match nothing.
 *
 * The Grant record itself survives, deliberately: the grant is the consent, and revoking a token is not
 * withdrawing consent. Only a principal cascade (lib/helpers/cascade.ts) destroys grant rows.
 */
export default async function revoke(grantId: string) {
	await Promise.all([
		AccessToken.revokeByGrantId(grantId),
		RefreshToken.revokeByGrantId(grantId),
		AuthorizationCode.revokeByGrantId(grantId),
		DeviceCode.revokeByGrantId(grantId),
		BackchannelAuthenticationRequest.revokeByGrantId(grantId)
	]);
	eventBus.emit('grant.revoked', grantId);
}
