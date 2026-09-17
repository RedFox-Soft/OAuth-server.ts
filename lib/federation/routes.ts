import { issuingBucket } from '../admin/auth/bucketAddress.js';
import { Elysia, t } from 'elysia';

import { getBucketStore } from '../adapters/index.js';
import { eventBus } from '../event_bus.js';
import { NOTICE_FEDERATION_ABORTED } from '../interactions/notices.js';
import {
	buildUIFederationCompletePath,
	buildUILoginPath
} from '../interactions/buildUIPath.js';
import { IdentityError, identityFor } from './identity/index.js';
import {
	federationDomainRefusedPage,
	federationExpiredPage,
	federationInactivePage,
	federationLinkRefusedPage,
	federationNoEmailPage,
	federationProvisioningClosedPage,
	federationRejectedPage,
	federationUpstreamPage
} from './pages.js';
import { findEnabledProvider } from './providers.js';
import { resolveFederatedAccount } from './resolve.js';
import { consumePending, openHandoff } from './state.js';

/*
 * The return leg from an upstream provider.
 *
 * Mounted outside the `ui` instance because it cannot satisfy that instance's guard: the interaction cookie
 * is scoped `path: /ui/${uid}`, and this route's URL must be byte-identical for every interaction, so it can
 * never be inside that path. Everything it needs comes from a short-lived record found by the digest of the
 * `state` it was given. It reads no cookie and sets none.
 */

/*
 * What an upstream sends back, however it sends it.
 *
 * `iss` is RFC 9207 and must be tolerated; `error`/`error_description` are how a provider reports a
 * decline. All are declared because the app runs `normalize: false` — an undeclared parameter a real
 * provider sends would 422 the request before the handler ran. Only `state` is required: without it there
 * is no round trip to identify.
 *
 * One provider also posts a `user` field on a first authorization, carrying the name it will never send
 * again. Declared for that reason, and read by the identity layer rather than here.
 */
const ReturnParams = t.Object({
	state: t.String(),
	code: t.Optional(t.String()),
	iss: t.Optional(t.String()),
	error: t.Optional(t.String()),
	error_description: t.Optional(t.String()),
	user: t.Optional(t.String())
});

type ReturnParams = typeof ReturnParams.static;

export const federationRoutes = new Elysia({ name: 'federation-callback' })
	.get('/federation/callback', ({ query }) => completeReturn(query), {
		query: ReturnParams
	})
	/*
	 * The same path, a second method, one handler.
	 *
	 * One recognised provider **requires** the return to be posted whenever a name or an address is among
	 * the scopes, and refuses the authorization request outright otherwise — so this is a precondition of
	 * connecting it, not an accommodation.
	 *
	 * On the same path deliberately. The reason this route reads no cookie is that the interaction cookie
	 * is scoped `path: /ui/${uid}` and a fixed callback address is outside it — a property of the path, not
	 * the method, so a POST is cookieless on exactly the same grounds. A second path would mean a second
	 * address for every administrator to register and a second place for these rules to drift apart.
	 */
	.post('/federation/callback', ({ body }) => completeReturn(body), {
		body: ReturnParams
	});

async function completeReturn(params: ReturnParams) {
	/*
	 * The state is spent first, whatever happens next — including when the provider reports an error.
	 * A round trip is one attempt, and an attempt that came back at all is over.
	 */
	const pending = await consumePending(params.state);
	{
		if (
			!pending ||
			!pending.bucketId ||
			!pending.providerId ||
			!pending.nonce
		) {
			// Unknown, expired, already spent, or the wrong stage. One answer for all four: telling them
			// apart would tell the holder of one dead value something about another.
			return federationExpiredPage();
		}
		const uid = pending.interactionUid;

		/*
		 * The user declined, or the provider refused. This is the one federation failure that returns to a
		 * page the user carries on working in — but it *redirects* there rather than rendering it here, and
		 * that is not a style choice. The client bundle derives both the page and the interaction id from
		 * `window.location.pathname`, so a login document served at this URL would hydrate into an empty root
		 * — in a browser only, with nothing logged. The message travels as a server-owned notice identifier,
		 * which also keeps every byte of the provider's `error_description` off the page.
		 */
		if (params.error) {
			return Response.redirect(
				buildUILoginPath(uid, NOTICE_FEDERATION_ABORTED),
				303
			);
		}

		if (!params.code) {
			return federationRejectedPage(uid);
		}

		/*
		 * Re-resolved from current configuration rather than from the record: a provider deleted, disabled or
		 * re-keyed while the user was away must refuse rather than complete against settings that no longer
		 * exist. This is also what makes the deployment switch effective mid-flight.
		 */
		const bucket = await getBucketStore().find(pending.bucketId);
		const provider = findEnabledProvider(bucket, pending.providerId);
		if (!bucket || !provider) {
			return federationInactivePage();
		}

		let identity;
		try {
			identity = await identityFor({
				provider,
				code: params.code,
				/* The same address the authorization leg sent, recovered from the pending state — an
				 * upstream matches `redirect_uri` by exact string across the two legs. */
				bucket: await issuingBucket(pending.bucketId),
				nonce: pending.nonce,
				codeVerifier: pending.codeVerifier
			});
		} catch (err) {
			if (err instanceof IdentityError) {
				/*
				 * One response per stage, and the reason goes to the event bus rather than to the console:
				 * this route is unauthenticated, so an attacker-triggerable log write is a vector of its own.
				 * The reasoning is lib/admin/auth/login.ts's, and it applies here with more force — anyone who
				 * can follow a redirect can reach this.
				 */
				if (err.stage === 'upstream') {
					eventBus.emit('federation.upstream.error', {
						providerId: provider.id,
						reason: err.reason
					});
					return federationUpstreamPage();
				}
				eventBus.emit('federation.idtoken.error', {
					providerId: provider.id,
					reason: err.reason
				});
				return federationRejectedPage(uid);
			}
			throw err;
		}

		const resolution = await resolveFederatedAccount({
			bucket,
			provider,
			subject: identity.subject,
			claims: identity.claims
		});

		if (!resolution.ok) {
			switch (resolution.reason) {
				case 'no_email':
					return federationNoEmailPage();
				case 'domain_not_allowed':
					return federationDomainRefusedPage();
				case 'link_not_permitted':
					return federationLinkRefusedPage(uid);
				case 'provisioning_closed':
					return federationProvisioningClosedPage();
				case 'inactive':
					return federationInactivePage();
			}
		}

		/*
		 * A fresh single-use value, and a *relative* redirect: same-site is what makes the strict interaction
		 * cookie arrive on the next hop, which is the whole reason this three-hop shape exists.
		 */
		const ref = await openHandoff({
			interactionUid: uid,
			accountId: resolution.account._id
		});
		return Response.redirect(buildUIFederationCompletePath(uid, ref), 303);
	}
}
