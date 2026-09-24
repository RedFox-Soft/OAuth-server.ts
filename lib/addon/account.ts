import { Grant } from '../models/grant.js';
import { getUserStore } from '../adapters/index.js';
import { resolveBucketForRequest } from '../admin/auth/resolveBucket.js';
import type { OIDCContext } from '../helpers/oidc_context.ts';

// The token an account is loaded for at the token and userinfo endpoints.
type AccountToken = {
	payload: { clientId?: string; resource?: string | readonly string[] };
};

// Generic over the endpoint's parameters: all it reads from them is the resource the request names.
export async function findAccount<
	P extends Record<string, unknown> & {
		resource?: string | readonly string[];
	}
>(
	oidc: OIDCContext<P> | undefined,
	sub: string | undefined,
	_token?: AccountToken
) {
	// @param oidc - the OIDC context for the current request.
	// @param sub {string} - account identifier (subject); equals the user record _id.
	// @param token - reference to the token the account is being loaded for;
	//   undefined at the authorization endpoint.

	// A token issued to no account (client credentials) has none to load.
	if (!sub) return undefined;

	// Resolve the user bucket exactly as login does (resolveBucketForRequest):
	// prefer the live client, falling back to the token's client for the
	// token/userinfo flows where no client may be resolved (`entities.Client`).
	const clientId = oidc?.entities.Client?.clientId ?? _token?.payload?.clientId;
	/*
	 * The resource matters here for the same reason the client does, and leaving it out is not a
	 * harmless omission: bucket resolution can derive a project from the declared resource a request
	 * names, so a login that found the user in a project's bucket while this resolved against the
	 * default one would authenticate somebody the very next step could not load. That is not a
	 * hypothetical — it is what happened before this argument was passed, and it surfaced as a 500 in
	 * the consent prompt rather than as a refusal, because `loadGrant` leaves the grant (`oidc.entities.Grant`) unset when
	 * no account resolved.
	 *
	 * Taken from the live request where there is one, and from the token otherwise, mirroring the
	 * client fallback directly above.
	 */
	const resource = oidc?.params?.resource ?? _token?.payload?.resource;
	const bucketId = await resolveBucketForRequest(clientId, resource);
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
		async claims(
			_use?: string,
			_scope?: string,
			_claims?: unknown,
			_rejected?: readonly string[]
		) {
			return {
				sub,
				email: user.email,
				email_verified: user.verified,
				...user.claims
			};
		}
	};
}

export async function loadExistingGrant(oidc: OIDCContext) {
	const clientId = oidc.client.clientId;
	const grantId =
		oidc.result?.consent?.grantId || oidc.session.grantIdFor(clientId);

	if (grantId) {
		const existing = await Grant.tryFind(grantId);
		/*
		 * A grant established before the client stopped requiring consent is persisted with
		 * `trusted: false`, and every filtered getter then narrows to what that grant happens to hold —
		 * so a returning End-User of a consent-not-required client would silently receive fewer scopes,
		 * claims and authorization details than were requested. Trust is a property of the client, so it
		 * is re-derived here rather than frozen at the moment the grant was created. Not persisted: the
		 * derivation is free on every load, and writing on every authorization is not.
		 */
		if (existing && oidc.client['consent.require'] === false) {
			existing.payload.trusted = true;
		}
		return existing;
	}
	const accountId = oidc.entities.Account?.accountId;
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
