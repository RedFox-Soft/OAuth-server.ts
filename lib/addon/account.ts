import { Grant } from '../models/grant.js';
import { getUserStore } from '../adapters/index.js';
import { resolveBucketForClient } from '../admin/auth/resolveBucket.js';

export async function findAccount(oidc, sub, _token?) {
	// @param oidc - the OIDC context (ctx.oidc) for the current request.
	// @param sub {string} - account identifier (subject); equals the user record _id.
	// @param token - reference to the token the account is being loaded for;
	//   undefined at the authorization endpoint.

	// Resolve the user bucket exactly as login does (resolveBucketForClient):
	// prefer the live client, falling back to the token's client for the
	// token/userinfo flows where `oidc.client` may not be populated.
	const clientId = oidc?.client?.clientId ?? _token?.payload?.clientId;
	const bucketId = await resolveBucketForClient(clientId);
	const user = await getUserStore(bucketId).find(sub);

	// A missing or deactivated user resolves to nothing so the calling flow
	// rejects it. Active-status is therefore enforced at every account
	// resolution, not only at login (a user deactivated after login can no
	// longer mint tokens via refresh/device/CIBA).
	if (!user || !user.active) {
		return undefined;
	}

	return {
		accountId: sub,
		// @param use {string} - "id_token" or "userinfo"; the provider masks the
		//   returned claims by granted scope automatically. Any extra claims stored
		//   on the record (profile, distributed/aggregated) are merged in.
		async claims(_use, _scope, _claims, _rejected) {
			return {
				sub,
				email: user.email,
				email_verified: user.verified,
				...user.claims
			};
		}
	};
}

export async function loadExistingGrant(oidc) {
	const clientId = oidc.client.clientId;
	const grantId =
		oidc.result?.consent?.grantId || oidc.session.grantIdFor(clientId);

	if (grantId) {
		return Grant.tryFind(grantId);
	}
	const accountId = oidc.account?.accountId;
	if (oidc.client['consent.require'] === false && accountId) {
		// Mark the auto-created grant `trusted` (this is a consent-not-required
		// client). A trusted grant's getOIDCScopeFiltered()/getResourceScopeFiltered()
		// return the full requested scope set. Without it the grant has no scopes,
		// so `interactions()` denies the request with access_denied ("no scope was
		// granted"). `trusted` is persisted, so reloaded grants stay trusted too.
		const grant = new Grant({ accountId, clientId, trusted: true });
		await grant.save();
		return grant;
	}
}
