import { Elysia, t } from 'elysia';

import { getBucketStore } from '../adapters/index.js';
import { eventBus } from '../event_bus.js';
import { NOTICE_FEDERATION_ABORTED } from '../interactions/notices.js';
import {
	buildUIFederationCompletePath,
	buildUILoginPath
} from '../interactions/buildUIPath.js';
import { DiscoveryError, discover } from './discovery.js';
import { ExchangeError, exchangeCode } from './flow.js';
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
import {
	FederationIdTokenRejected,
	verifyFederatedIdToken
} from './verifyIdToken.js';

/*
 * The return leg from an upstream provider.
 *
 * Mounted outside the `ui` instance because it cannot satisfy that instance's guard: the interaction cookie
 * is scoped `path: /ui/${uid}` and `sameSite: 'strict'`, and this route is reached by a cross-site top-level
 * navigation to a URL that must be byte-identical for every interaction. Everything it needs comes from a
 * short-lived record found by the digest of the `state` it was given. It reads no cookie and sets none.
 */

export const federationRoutes = new Elysia({ name: 'federation-callback' }).get(
	'/federation/callback',
	async ({ query }) => {
		/*
		 * The state is spent first, whatever happens next — including when the provider reports an error.
		 * A round trip is one attempt, and an attempt that came back at all is over.
		 */
		const pending = await consumePending(query.state);
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
		if (query.error) {
			return Response.redirect(
				buildUILoginPath(uid, NOTICE_FEDERATION_ABORTED),
				303
			);
		}

		if (!query.code) {
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

		let idToken: string | undefined;
		let metadata;
		try {
			metadata = await discover(provider.issuer);
			idToken = await exchangeCode(
				provider,
				metadata,
				query.code,
				pending.codeVerifier
			);
		} catch (err) {
			if (err instanceof DiscoveryError || err instanceof ExchangeError) {
				eventBus.emit('federation.upstream.error', {
					providerId: provider.id,
					reason: err.reason
				});
				return federationUpstreamPage();
			}
			throw err;
		}

		let assertion;
		try {
			assertion = await verifyFederatedIdToken(idToken, {
				metadata,
				clientId: provider.clientId,
				nonce: pending.nonce
			});
		} catch (err) {
			if (err instanceof FederationIdTokenRejected) {
				/*
				 * One response for every cause, and the reason goes to the event bus rather than to the console:
				 * this route is unauthenticated, so an attacker-triggerable log write is a vector of its own.
				 * The reasoning is lib/admin/auth/login.ts's, and it applies here with more force — anyone who
				 * can follow a redirect can reach this.
				 */
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
			subject: assertion.subject,
			claims: assertion.claims
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
	},
	{
		/*
		 * `iss` is RFC 9207 and must be tolerated; `error`/`error_description` are how a provider reports a
		 * decline. All three are declared because the app runs `normalize: false` — an undeclared parameter a
		 * real provider sends would 422 the request before the handler ran. Only `state` is required: without
		 * it there is no round trip to identify.
		 */
		query: t.Object({
			state: t.String(),
			code: t.Optional(t.String()),
			iss: t.Optional(t.String()),
			error: t.Optional(t.String()),
			error_description: t.Optional(t.String())
		})
	}
);
