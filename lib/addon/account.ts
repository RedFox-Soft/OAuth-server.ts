import { Grant } from '../models/grant.js';

export async function findAccount(ctx, sub, _token) {
	// @param ctx - koa request context
	// @param sub {string} - account identifier (subject)
	// @param token - is a reference to the token used for which a given account is being loaded,
	//   is undefined in scenarios where claims are returned from authorization endpoint
	// const user = await getUserStore().find(sub);

	return {
		accountId: sub,
		// @param use {string} - can either be "id_token" or "userinfo", depending on
		//   where the specific claims are intended to be put in
		// @param scope {string} - the intended scope, while oidc-provider will mask
		//   claims depending on the scope automatically you might want to skip
		//   loading some claims from external resources or through db projection etc. based on this
		//   detail or not return them in ID Tokens but only UserInfo and so on
		// @param claims {object} - the part of the claims authorization parameter for either
		//   "id_token" or "userinfo" (depends on the "use" param)
		// @param rejected {Array[String]} - claim names that were rejected by the end-user, you might
		//   want to skip loading some claims from external resources or through db projection
		async claims(_use, _scope, _claims, _rejected) {
			return { sub };
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
