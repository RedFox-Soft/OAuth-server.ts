import { Elysia, t } from 'elysia';

import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { ACCOUNT_REAUTHENTICATION_SECONDS } from '../consts/account_page.js';
import { AuthorizationCookies, routeNames } from '../consts/param_list.js';
import { profileClaims } from '../consts/profile_claims.js';
import { hostOfRequest } from '../consts/request_host.js';
import { ApplicationConfig } from '../configs/application.js';
import type { RequestBucket } from '../configs/issuer.js';
import { EndUserError, endApplicationAccess } from '../end_users/service.js';
import { connectedApplications } from '../end_users/sessions.js';
import constantEquals from '../helpers/constant_equals.js';
import epochTime from '../helpers/epoch_time.js';
import { versionedAsset } from '../html/versionedAsset.js';
import { sanitiseClientName } from '../interactions/clientName.js';
import type {
	DeclaredResourceFacts,
	SortingContext
} from '../interactions/consentView.js';
import { Client, clientProvenance } from '../models/client.js';
import { readLogo } from '../models/client/logo.js';
import type { Grant } from '../models/grant.js';
import { findDeclaredResource } from '../resources/registry.js';
import { namespaceOf } from '../resources/namespace.js';
import {
	accountPageBase,
	accountPageUrl,
	isAccountPageClient
} from './client.js';
import {
	confirmationPage,
	listPage,
	outcomePage,
	type PageFrame
} from './html.js';
import {
	clearPending,
	ensureXsrf,
	fromThisOrigin,
	readPending,
	signInRedirect,
	usablePerson,
	xsrfMatches,
	type PagePerson
} from './session.js';
import { ACCOUNT_PAGE_TEXTS as T } from './texts.js';
import {
	applicationRow,
	byNewest,
	type ApplicationFacts,
	type ApplicationRow,
	type GrantFacts
} from './view.js';

/*
 * The end-user connected-applications page (specs/095): the applications holding access to the person's
 * account in one bucket, and the one act of removing one. Mounted bare and beneath `/:bucket`, as every
 * bucket-scoped surface is; the address names the bucket, and the bucket's own sign-in session names the
 * person (session.ts).
 *
 * No route here declares a `params` schema: the bare mount has none and the prefixed one has `bucket`, and a
 * schema naming one would refuse the other (the app runs `strictPath`).
 */

function addressOfRequest(params: unknown, request: Request) {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

function pathOf(bucket: RequestBucket): string {
	return new URL(accountPageUrl(bucket)).pathname;
}

function frameFor(person: PagePerson): PageFrame {
	const base = accountPageBase(person.bucket);
	return {
		service: person.bucket.displayName ?? new URL(base).host,
		logoSrc: versionedAsset('logo.svg'),
		path: pathOf(person.bucket),
		signOutHref: `${base}${routeNames.end_session}`,
		email: person.user.email
	};
}

function grantFacts(grant: Grant): GrantFacts {
	return {
		trusted: grant.payload.trusted,
		createdAt: grant.payload.createdAt,
		granted: {
			oidcScopes: grant.getOIDCScope().split(' ').filter(Boolean),
			oidcClaims: grant.getOIDCClaims(),
			resourceScopes: Object.fromEntries(
				Object.keys(grant.payload.resources ?? {}).map((indicator) => [
					indicator,
					grant.getResourceScope(indicator).split(' ').filter(Boolean)
				])
			),
			rar: grant.payload.rar ?? []
		}
	};
}

/* Everything the list says about the person's applications, read here and decided in view.ts. */
async function rowsFor(
	person: PagePerson,
	addressed: RequestBucket
): Promise<ApplicationRow[]> {
	const accountId = person.user._id;
	const applications = await connectedApplications(person.bucket, accountId);

	const profile = profileClaims(person.user);
	// `groups` is never read from stored claims; membership decides it (lib/addon/account.ts).
	const { groups: _groups, ...storedClaims } = person.user.claims ?? {};
	const resources: Record<string, DeclaredResourceFacts> = {};
	const context: SortingContext = {
		userClaims: { ...storedClaims, ...profile, email: person.user.email },
		scopeDescriptions: ApplicationConfig['consent.scopeDescriptions'],
		resources,
		rarLabels: Object.fromEntries(
			Object.entries(ApplicationConfig['richAuthorizationRequests.types']).map(
				([type, descriptor]) => [type, descriptor.label]
			)
		)
	};

	const rows: ApplicationRow[] = [];
	for (const application of applications) {
		const grants = application.grants.map(grantFacts);
		for (const grant of grants) {
			for (const indicator of Object.keys(grant.granted.resourceScopes)) {
				if (indicator in resources) continue;
				const declared = await findDeclaredResource(
					indicator,
					namespaceOf(addressed)
				);
				if (declared) {
					resources[indicator] = {
						name: declared.name,
						...(declared.scopeDescriptions
							? { scopeDescriptions: declared.scopeDescriptions }
							: {})
					};
				}
			}
		}
		const client = await Client.tryFind(application.clientId);
		const tier = client
			? await clientProvenance(client, person.bucket)
			: 'self-registered';
		/* Read only where it could be shown, as on the consent page (specs/094). */
		const logo =
			tier === 'this-organization'
				? await readLogo(application.clientId)
				: undefined;
		const facts: ApplicationFacts = {
			clientId: application.clientId,
			...(client
				? {
						client: {
							...(client.clientName ? { name: client.clientName } : {}),
							redirectUris: client.redirectUris
						}
					}
				: {}),
			tier,
			...(logo ? { logo } : {}),
			grants,
			...(application.lastTokenAt !== undefined
				? { lastTokenAt: application.lastTokenAt }
				: {}),
			liveRefresh: application.liveRefresh
		};
		rows.push(applicationRow(facts, context));
	}
	return rows.sort(byNewest);
}

/* The name an application went by, re-read rather than echoed back from the address bar. */
async function nameOf(clientId: string): Promise<string> {
	const client = await Client.tryFind(clientId);
	if (!client) return T.deletedApp;
	return sanitiseClientName(client.clientName) ?? clientId;
}

const ListQuery = t.Object({
	revoke: t.Optional(t.String()),
	done: t.Optional(t.String()),
	gone: t.Optional(t.Literal('1'))
});

const RemovalBody = t.Object({
	clientId: t.Optional(t.String()),
	xsrf: t.Optional(t.String())
});

const CallbackQuery = t.Object({
	state: t.Optional(t.String()),
	iss: t.Optional(t.String()),
	error: t.Optional(t.String()),
	error_description: t.Optional(t.String())
});

function seeOther(location: string): Response {
	return new Response(null, { status: 303, headers: { location } });
}

export const accountPageRoutes = new Elysia({ name: 'account-page' })
	.guard({ cookie: AuthorizationCookies })
	.get(
		routeNames.account_apps,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const person = await usablePerson(addressed, cookie);
			if (!person) return seeOther(signInRedirect(cookie, addressed));

			const frame = frameFor(person);
			const rows = await rowsFor(person, addressed);

			if (query.revoke !== undefined) {
				const row = rows.find((r) => r.clientId === query.revoke);
				if (row) {
					return confirmationPage(frame, row, await ensureXsrf(person.session));
				}
				return listPage(frame, rows, T.gone);
			}

			const notice =
				query.done !== undefined
					? T.done(await nameOf(query.done))
					: query.gone !== undefined
						? T.gone
						: undefined;
			return listPage(frame, rows, notice);
		},
		{ query: ListQuery }
	)
	.post(
		routeNames.account_apps,
		async ({ body, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const path = pathOf(addressed);
			/*
			 * Checked before anything else, the session included: a request another site sent says nothing this
			 * page should act on, and answering it differently by session would tell that site who is signed in.
			 */
			if (
				!fromThisOrigin(request, new URL(accountPageBase(addressed)).origin)
			) {
				return outcomePage(T.refusedTitle, T.refused, path, 403);
			}
			const person = await usablePerson(addressed, cookie);
			if (!person) return seeOther(signInRedirect(cookie, addressed));
			if (!xsrfMatches(person.session, body.xsrf)) {
				return outcomePage(T.refusedTitle, T.refused, path, 403);
			}

			const accountId = person.user._id;
			const clientId = body.clientId ?? '';
			/*
			 * A sign-in older than the window is asked for again, and the person comes back to the confirmation —
			 * never to a removal made on their behalf by the return trip (research R4).
			 */
			const loginTs = person.session.payload.loginTs ?? 0;
			if (epochTime() - loginTs > ACCOUNT_REAUTHENTICATION_SECONDS) {
				return seeOther(
					signInRedirect(cookie, person.bucket, {
						reauthenticate: {
							accountId,
							...(clientId ? { revoke: clientId } : {})
						}
					})
				);
			}

			const pagePath = pathOf(person.bucket);
			const holding = (
				await connectedApplications(person.bucket, accountId)
			).some((application) => application.clientId === clientId);
			/*
			 * One answer for an application that does not exist, one the person never connected and one already
			 * gone, so the response says nothing about any of them. The page's own client is not an application.
			 */
			if (!clientId || isAccountPageClient(clientId) || !holding) {
				return seeOther(`${pagePath}?gone=1`);
			}

			try {
				await endApplicationAccess(person.bucket, accountId, clientId, () =>
					recordEndUserAudit(
						person.bucket._id,
						accountId,
						'enduser.application.signout',
						{
							targetScope: person.bucket._id,
							clientId,
							ownerGroupId: person.bucket.ownerGroupId
						}
					)
				);
			} catch (err) {
				/* Gone between the read above and the removal — another tab, or an administrator. */
				if (err instanceof EndUserError && err.status === 404) {
					return seeOther(`${pagePath}?gone=1`);
				}
				throw err;
			}
			return seeOther(`${pagePath}?done=${encodeURIComponent(clientId)}`);
		},
		{ body: RemovalBody, parse: 'urlencoded' }
	)
	.get(
		routeNames.account_apps_callback,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const path = pathOf(addressed);
			const pending = readPending(cookie);
			clearPending(cookie, addressed);

			if (
				!pending ||
				typeof query.state !== 'string' ||
				query.state.length !== pending.state.length ||
				!constantEquals(query.state, pending.state)
			) {
				return outcomePage(T.expiredTitle, T.expired, path, 400);
			}
			if (query.error === 'access_denied') {
				return outcomePage(T.notSignedInTitle, T.notSignedIn, path, 200);
			}
			if (query.error !== undefined) {
				return outcomePage(T.failedTitle, T.failed, path, 400);
			}

			const person = await usablePerson(addressed, cookie);
			/*
			 * Signed in, yet not someone this page can show — a person who may not sign in, or a sign-in that
			 * landed elsewhere. Said, rather than sent round again: the page would only start the same sign-in.
			 */
			if (!person) return outcomePage(T.failedTitle, T.failed, path, 400);

			const pagePath = pathOf(person.bucket);
			if (pending.accountId !== undefined) {
				/* Someone else finished the sign-in: whatever was asked for belonged to the person who asked. */
				if (person.user._id !== pending.accountId) return seeOther(pagePath);
				if ((person.session.payload.loginTs ?? 0) < pending.startedAt) {
					return outcomePage(T.failedTitle, T.failed, pagePath, 400);
				}
				if (pending.revoke !== undefined) {
					return seeOther(
						`${pagePath}?revoke=${encodeURIComponent(pending.revoke)}`
					);
				}
			}
			return seeOther(pagePath);
		},
		{ query: CallbackQuery }
	);
