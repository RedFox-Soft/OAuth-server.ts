import { Elysia, t } from 'elysia';

import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { ACCOUNT_REAUTHENTICATION_SECONDS } from '../consts/account_page.js';
import { connectedServiceEntry } from '../consts/connected_service_catalogue.js';
import {
	AuthorizationCookies,
	routeNames,
	sessionCookieName
} from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import type { RequestBucket } from '../configs/issuer.js';
import { eventBus, type RevocationOutcome } from '../event_bus.js';
import epochTime from '../helpers/epoch_time.js';
import { versionedAsset } from '../html/versionedAsset.js';
import type { Language } from '../i18n/languages.js';
import { text } from '../i18n/message.js';
import { languageOfRequest } from '../i18n/request.js';
import { storedLocaleRanges } from '../i18n/resolve.js';
import { ACCOUNT_TEXTS } from '../i18n/texts/account/index.js';
import {
	ConnectRefused,
	disconnect,
	finishConnect,
	listForPerson,
	serviceOf,
	startConnect,
	type ConnectNotice
} from '../connected_services/accounts.js';
import { digestOf, spendConnect } from '../connected_services/state.js';
import { resolveService } from '../connected_services/catalogue.js';
import { accountPageBase } from './client.js';
import {
	connectConfirmation,
	connectOutcomePage,
	disconnectConfirmation,
	outcomePage,
	servicesPage,
	type PageFrame,
	type ServicesNotice
} from './html.js';
import {
	ensureXsrf,
	fromThisOrigin,
	signInRedirect,
	usablePerson,
	xsrfMatches,
	type PagePerson
} from './session.js';

/*
 * The person's connected services (specs/117 contracts/account-page.md): their accounts at other services, the
 * one place a connect flow starts, and the address a provider sends them back to. In the family of
 * /account/apps (specs/095): plain, script-free, every act a confirmation and a same-origin form, mounted bare
 * and beneath `/:bucket` with no `params` schema for the reason that page gives.
 */

function addressOfRequest(params: unknown, request: Request) {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

function servicesPath(bucket: RequestBucket): string {
	return new URL(`${accountPageBase(bucket)}${routeNames.account_services}`)
		.pathname;
}

function appsPath(bucket: RequestBucket): string {
	return new URL(`${accountPageBase(bucket)}${routeNames.account_apps}`)
		.pathname;
}

function personLanguage(person: PagePerson, request: Request): Language {
	return languageOfRequest(request, [storedLocaleRanges(person.user)]).language;
}

function frameFor(person: PagePerson, language: Language): PageFrame {
	const base = accountPageBase(person.bucket);
	return {
		language,
		service: person.bucket.displayName ?? new URL(base).host,
		logoSrc: versionedAsset('logo.svg'),
		path: servicesPath(person.bucket),
		signOutHref: `${base}${routeNames.end_session}`,
		email: person.user.email
	};
}

function seeOther(location: string): Response {
	return new Response(null, { status: 303, headers: { location } });
}

const NOTICES: readonly ConnectNotice[] = [
	'declined',
	'failed',
	'limit',
	'unavailable',
	'expired',
	'refused'
];
const OUTCOMES: readonly RevocationOutcome[] = [
	'revoked',
	'not_supported',
	'failed',
	'unreadable'
];

const NOTICE_KEY = {
	declined: 'noticeDeclined',
	failed: 'noticeFailed',
	limit: 'noticeLimit',
	unavailable: 'noticeUnavailable',
	expired: 'noticeExpired',
	refused: 'noticeRefused'
} as const;

const REVOCATION_KEY = {
	revoked: 'revocationRevoked',
	not_supported: 'revocationNotSupported',
	failed: 'revocationFailed',
	unreadable: 'revocationUnreadable'
} as const;

/*
 * The page's sentence after an act, built from the query only by whitelist: nothing a link carries is echoed, and
 * the service is named from the project's own record.
 */
function noticeOf(
	person: PagePerson,
	language: Language,
	query: {
		done?: string;
		notice?: string;
		revocation?: string;
		service?: string;
	}
): ServicesNotice | undefined {
	const T = ACCOUNT_TEXTS[language];
	const service = query.service
		? serviceOf(person.bucket, query.service)
		: undefined;
	const name = service?.displayName ?? '';
	const notice = NOTICES.find((value) => value === query.notice);
	if (notice) return { lines: [T[NOTICE_KEY[notice]]] };
	if (query.done === 'connected' || query.done === 'updated') {
		return {
			lines: [
				text(query.done === 'connected' ? T.connectedDone : T.updatedDone, {
					service: name
				})
			]
		};
	}
	if (query.done !== 'disconnected') return undefined;
	const outcome = OUTCOMES.find((value) => value === query.revocation);
	const lines: string[] = [T.disconnectedDone];
	if (outcome) lines.push(text(T[REVOCATION_KEY[outcome]], { service: name }));
	const href =
		outcome && outcome !== 'revoked' && service?.catalogueId
			? connectedServiceEntry(service.catalogueId)?.manageAccessUrls[0]
			: undefined;
	return { lines, ...(href ? { manage: { href, service: name } } : {}) };
}

function noticeHref(
	person: PagePerson,
	notice: ConnectNotice,
	serviceId?: string
) {
	const params = new URLSearchParams({ notice });
	if (serviceId) params.set('service', serviceId);
	return `${servicesPath(person.bucket)}?${params.toString()}`;
}

/*
 * Where the connect form's redirect will go, for the page's `form-action`. Undefined when the service cannot be
 * resolved now: the form then posts and the server answers with the page's own notice, which needs no hand-off.
 */
async function providerAddressOf(
	person: PagePerson,
	serviceId: string
): Promise<string | undefined> {
	const service = serviceOf(person.bucket, serviceId);
	if (!service) return undefined;
	try {
		return (await resolveService(service)).authorizationEndpoint;
	} catch {
		return undefined;
	}
}

const ListQuery = t.Object({
	connect: t.Optional(t.String()),
	disconnect: t.Optional(t.String()),
	done: t.Optional(t.String()),
	notice: t.Optional(t.String()),
	revocation: t.Optional(t.String()),
	service: t.Optional(t.String())
});

const ActBody = t.Object({
	action: t.Optional(t.String()),
	serviceId: t.Optional(t.String()),
	connectedAccountId: t.Optional(t.String()),
	xsrf: t.Optional(t.String())
});

/* Providers add parameters of their own; only these are read. */
const CallbackQuery = t.Object(
	{
		state: t.Optional(t.String()),
		code: t.Optional(t.String()),
		iss: t.Optional(t.String()),
		error: t.Optional(t.String()),
		error_description: t.Optional(t.String())
	},
	{ additionalProperties: true }
);

export const accountServicesRoutes = new Elysia({ name: 'account-services' })
	.guard({ cookie: AuthorizationCookies })
	.get(
		routeNames.account_services,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const person = await usablePerson(addressed, cookie);
			if (!person) {
				return seeOther(signInRedirect(cookie, addressed, { services: true }));
			}
			const language = personLanguage(person, request);
			const frame = frameFor(person, language);
			const views = await listForPerson(person.bucket, person.user._id);
			const rows = views.map((view) => ({
				id: view.id,
				serviceName: view.serviceName,
				label: view.label,
				scopes: view.scopes,
				missingScopes: view.missingScopes,
				connectedAt: view.connectedAt,
				status: view.status
			}));
			const offered = (person.bucket.connectedServices ?? []).map(
				(service) => ({
					id: service.id,
					displayName: service.displayName
				})
			);

			if (query.connect !== undefined) {
				const service = offered.find((item) => item.id === query.connect);
				if (service) {
					return connectConfirmation(
						frame,
						service,
						await ensureXsrf(person.session),
						await providerAddressOf(person, service.id)
					);
				}
			}
			if (query.disconnect !== undefined) {
				const row = rows.find((item) => item.id === query.disconnect);
				if (row) {
					return disconnectConfirmation(
						frame,
						row,
						await ensureXsrf(person.session)
					);
				}
			}
			return servicesPage(
				frame,
				appsPath(person.bucket),
				rows,
				offered,
				noticeOf(person, language, query)
			);
		},
		{ query: ListQuery }
	)
	.post(
		routeNames.account_services,
		async ({ body, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const path = servicesPath(addressed);
			/* Before the session, as the applications page does: another site's request says nothing to act on. */
			if (
				!fromThisOrigin(request, new URL(accountPageBase(addressed)).origin)
			) {
				return outcomePage(
					'refused',
					path,
					403,
					languageOfRequest(request).language
				);
			}
			const person = await usablePerson(addressed, cookie);
			if (!person) {
				return seeOther(signInRedirect(cookie, addressed, { services: true }));
			}
			if (!xsrfMatches(person.session, body.xsrf)) {
				return outcomePage(
					'refused',
					path,
					403,
					languageOfRequest(request).language
				);
			}
			const accountId = person.user._id;
			const action = body.action;
			/*
			 * A sign-in older than the window is asked for again (Clarifications: connecting and disconnecting both),
			 * and the person comes back to the confirmation, never to an act the return trip made for them.
			 */
			const loginTs = person.session.payload.loginTs ?? 0;
			if (epochTime() - loginTs > ACCOUNT_REAUTHENTICATION_SECONDS) {
				return seeOther(
					signInRedirect(cookie, person.bucket, {
						services: true,
						reauthenticate: {
							accountId,
							...(action === 'connect' && body.serviceId
								? { connect: body.serviceId }
								: {}),
							...(action === 'disconnect' && body.connectedAccountId
								? { disconnect: body.connectedAccountId }
								: {})
						}
					})
				);
			}
			const pagePath = servicesPath(person.bucket);

			if (action === 'connect') {
				const sessionId = cookie[sessionCookieName(addressed)].value;
				if (!body.serviceId || typeof sessionId !== 'string' || !sessionId) {
					return seeOther(noticeHref(person, 'refused'));
				}
				try {
					return seeOther(
						await startConnect({
							bucket: person.bucket,
							serviceId: body.serviceId,
							accountId,
							sessionId
						})
					);
				} catch (err) {
					if (err instanceof ConnectRefused) {
						return seeOther(noticeHref(person, err.notice, body.serviceId));
					}
					throw err;
				}
			}

			if (action === 'disconnect' && body.connectedAccountId) {
				const views = await listForPerson(person.bucket, accountId);
				const view = views.find((item) => item.id === body.connectedAccountId);
				/* Another person's account, one already gone, one that never was: one answer for all three. */
				if (!view) return seeOther(pagePath);
				await recordEndUserAudit(
					person.bucket._id,
					accountId,
					'connected.account.delete',
					{
						targetScope: person.bucket._id,
						connectedAccountId: view.id,
						ownerGroupId: person.bucket.ownerGroupId
					}
				);
				const result = await disconnect({
					bucket: person.bucket,
					accountId,
					connectedAccountId: view.id,
					by: 'person'
				});
				const params = new URLSearchParams({
					done: 'disconnected',
					service: view.serviceId,
					...(result.revocation ? { revocation: result.revocation } : {})
				});
				return seeOther(`${pagePath}?${params.toString()}`);
			}
			return seeOther(pagePath);
		},
		{ body: ActBody, parse: 'urlencoded' }
	)
	/*
	 * Where a provider sends the person back. Every refusal stores nothing and exchanges nothing: the order is the
	 * contract's, and each step closes one way of crossing the flow (User Story 3).
	 */
	.get(
		routeNames.account_services_callback,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const language = languageOfRequest(request).language;
			const path = servicesPath(addressed);
			const refused = (reason: string, serviceId?: string) => {
				eventBus.emit('connected_account.refused', {
					bucketId: addressed._id,
					...(serviceId ? { serviceId } : {}),
					reason
				});
			};

			const pending =
				typeof query.state === 'string' && query.state
					? await spendConnect(query.state)
					: null;
			if (!pending) {
				refused('state');
				return connectOutcomePage('expired', path, 400, language);
			}
			if (pending.bucketId !== addressed._id) {
				refused('project', pending.serviceId);
				return connectOutcomePage('refused', path, 403, language);
			}
			const sessionId = cookie[sessionCookieName(addressed)].value;
			const person = await usablePerson(addressed, cookie);
			if (
				typeof sessionId !== 'string' ||
				!person ||
				digestOf(sessionId) !== pending.sessionDigest ||
				person.user._id !== pending.accountId
			) {
				refused('session', pending.serviceId);
				return connectOutcomePage('refused', path, 403, language);
			}
			if (query.error !== undefined) {
				return seeOther(
					noticeHref(
						person,
						query.error === 'access_denied' ? 'declined' : 'failed',
						pending.serviceId
					)
				);
			}
			if (typeof query.code !== 'string' || !query.code) {
				return seeOther(noticeHref(person, 'failed', pending.serviceId));
			}
			try {
				const { done, record } = await finishConnect({
					bucket: person.bucket,
					pending,
					code: query.code,
					iss: query.iss
				});
				await recordEndUserAudit(
					person.bucket._id,
					person.user._id,
					'connected.account.connect',
					{
						targetScope: person.bucket._id,
						serviceId: record.serviceId,
						connectedAccountId: record._id,
						ownerGroupId: person.bucket.ownerGroupId
					}
				);
				const params = new URLSearchParams({ done, service: record.serviceId });
				return seeOther(`${servicesPath(person.bucket)}?${params.toString()}`);
			} catch (err) {
				if (err instanceof ConnectRefused) {
					if (err.notice === 'refused') refused('issuer', pending.serviceId);
					return seeOther(noticeHref(person, err.notice, pending.serviceId));
				}
				throw err;
			}
		},
		{ query: CallbackQuery }
	);
