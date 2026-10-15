import { issuingBucket } from '../admin/auth/bucketAddress.js';
import { registeredAdministrator } from '../admin/administrators.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { Elysia, t } from 'elysia';

import { getBucketStore } from '../adapters/index.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
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
	federationNoConsoleAccountPage,
	federationProvisioningClosedPage,
	federationRejectedPage,
	federationUpstreamPage
} from './pages.js';
import { findEnabledProvider } from './providers.js';
import { resolveFederatedAccount } from './resolve.js';
import { consumePending, openHandoff } from './state.js';
import { completeTry } from './try.js';
import type { Language } from '../i18n/languages.js';
import { languageOfRequest } from '../i18n/request.js';
import { Interaction } from '../models/interaction.js';
import { registrationClosedPage } from '../interactions/registrationPages.js';

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
 * `iss` is RFC 9207; `error`/`error_description` are how a provider reports a decline. Only `state` is
 * required: without it there is no round trip to identify.
 *
 * Any other member is admitted and left unread, because RFC 6749 §4.1.2 says a client MUST ignore response
 * parameters it does not recognise — and real providers send them: Keycloak adds OIDC Session Management's
 * `session_state` to every return. The app runs `normalize: false`, so an object closed to undeclared
 * members answered that 400 before the handler ran, and no Keycloak sign-in could complete (found by the
 * live check of specs/073).
 *
 * One provider also posts a `user` field on a first authorization, carrying the name it will never send
 * again. Declared for that reason, and read by the identity layer rather than here.
 */
const ReturnParams = t.Object(
	{
		state: t.String(),
		code: t.Optional(t.String()),
		iss: t.Optional(t.String()),
		error: t.Optional(t.String()),
		error_description: t.Optional(t.String()),
		user: t.Optional(t.String())
	},
	{ additionalProperties: true }
);

type ReturnParams = typeof ReturnParams.static;

export const federationRoutes = new Elysia({ name: 'federation-callback' })
	.get(
		'/federation/callback',
		({ query, request }) => completeReturn(query, request),
		{ query: ReturnParams }
	)
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
	.post(
		'/federation/callback',
		({ body, request }) => completeReturn(body, request),
		{ body: ReturnParams }
	);

/*
 * The language of a page this leg shows (specs/097): the one the sign-in it belongs to decided, read from the
 * interaction the pending state names; the request's own when there is none to read.
 */
async function returnLanguage(
	uid: string | undefined,
	request: Request
): Promise<Language> {
	const interaction = uid ? await Interaction.tryFind(uid) : undefined;
	return interaction?.payload.language ?? languageOfRequest(request).language;
}

async function completeReturn(params: ReturnParams, request: Request) {
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
			return federationExpiredPage(languageOfRequest(request).language);
		}

		/*
		 * A try of a provider (specs/088) — decided by what was stored when the round trip began, never by
		 * anything in this request, so a sign-in cannot be turned into a try or a try into a sign-in. Before
		 * any interaction is touched: a try has none, and writes nothing a sign-in writes.
		 */
		if (pending.purpose === 'try') {
			return completeTry(pending, params);
		}

		const uid = pending.interactionUid;
		const language = await returnLanguage(uid, request);
		if (!uid) return federationExpiredPage(language);

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
			return federationRejectedPage(uid, language);
		}

		/*
		 * Re-resolved from current configuration rather than from the record: a provider deleted, disabled or
		 * re-keyed while the user was away must refuse rather than complete against settings that no longer
		 * exist. This is also what makes the deployment switch effective mid-flight.
		 */
		const found = await getBucketStore().find(pending.bucketId);
		/* A bucket scheduled for deletion while the user was away has no sign-in to complete (specs/090). */
		const bucket = found && !isScheduledForDeletion(found) ? found : null;
		const provider = findEnabledProvider(bucket, pending.providerId);
		if (!bucket || !provider) {
			return federationInactivePage(language);
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
				codeVerifier: pending.codeVerifier,
				/* RFC 9207: which issuer says it answered, compared by the identity layer. */
				iss: params.iss
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
					return federationUpstreamPage(language);
				}
				eventBus.emit('federation.idtoken.error', {
					providerId: provider.id,
					reason: err.reason
				});
				return federationRejectedPage(uid, language);
			}
			throw err;
		}

		const resolution = await resolveFederatedAccount({
			bucket,
			provider,
			subject: identity.subject,
			claims: identity.claims
		});

		/*
		 * Where this sign-in came from, carried to the session it makes: the provider, and its own session
		 * identifier when the verified assertion has one — what that provider's back-channel logout will name
		 * (specs/073). Read only from the verified claims; a provider without an ID token sends none.
		 */
		const sid =
			typeof identity.claims.sid === 'string' && identity.claims.sid
				? identity.claims.sid
				: undefined;
		const upstream = { providerId: provider.id, ...(sid ? { sid } : {}) };

		/*
		 * Handed back like a sign-in, because leg three is where the interaction cookie applies again and so
		 * the only place the identity may be written onto the interaction. Leg three signs nobody in for it.
		 */
		if (!resolution.ok && resolution.reason === 'password_required') {
			const ref = await openHandoff({
				interactionUid: uid,
				accountId: resolution.account._id,
				link: { ...resolution.link, ...(sid ? { sid } : {}) }
			});
			return Response.redirect(buildUIFederationCompletePath(uid, ref), 303);
		}

		if (!resolution.ok) {
			switch (resolution.reason) {
				case 'no_email':
					return federationNoEmailPage(language);
				case 'domain_not_allowed':
					return federationDomainRefusedPage(language);
				case 'link_not_permitted':
					return federationLinkRefusedPage(uid, language);
				/*
				 * The two refusals of a provider bound to a SCIM connection render the provisioning-closed page:
				 * to the person signing in, both mean "your organisation has not given you access here yet",
				 * and which of the two it was is not theirs to learn (the conflict is reported on the event bus).
				 */
				case 'provisioning_closed':
				case 'not_provisioned':
				case 'link_conflict':
					return bucket._id === ADMIN_BUCKET_ID
						? federationNoConsoleAccountPage()
						: federationProvisioningClosedPage(language);
				case 'inactive':
					return federationInactivePage(language);
				/*
				 * The page a paused self-registration answers, not the provisioning-closed one: that one tells the
				 * person to ask an administrator for an account, which is not what a paused project needs (specs/102).
				 */
				case 'signups_paused':
					return registrationClosedPage(language);
			}
		}

		/*
		 * An administrator created at a first sign-in gets what one created by sign-up gets: a personal group
		 * to land in, and a sign-up entry in the audit trail (specs/080). Never the instance privilege — only
		 * its own grant routes change that membership.
		 */
		if (resolution.provisioned && bucket._id === ADMIN_BUCKET_ID) {
			await registeredAdministrator(resolution.account);
		}

		/*
		 * A fresh single-use value, and a *relative* redirect: same-site is what makes the strict interaction
		 * cookie arrive on the next hop, which is the whole reason this three-hop shape exists.
		 */
		const ref = await openHandoff({
			interactionUid: uid,
			accountId: resolution.account._id,
			upstream
		});
		return Response.redirect(buildUIFederationCompletePath(uid, ref), 303);
	}
}
