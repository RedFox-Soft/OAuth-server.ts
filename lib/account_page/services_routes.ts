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
import { closeLink } from '../connected_services/link.js';
import type {
	ConnectedAccount,
	ConnectStatePayload
} from '../connected_services/types.js';
import { resolveService } from '../connected_services/catalogue.js';
import {
	agentsByAccount,
	changeConsent,
	servicesFor
} from '../connected_services/consent.js';
import { getConnectedAccountStore } from '../adapters/index.js';
import { grantsIn } from '../end_users/sessions.js';
import { sanitiseClientName } from '../interactions/clientName.js';
import { Client } from '../models/client.js';
import { accountPageBase, connectLinkUrl } from './client.js';
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

export function addressOfRequest(params: unknown, request: Request) {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

export function servicesPath(bucket: RequestBucket): string {
	return new URL(`${accountPageBase(bucket)}${routeNames.account_services}`)
		.pathname;
}

function appsPath(bucket: RequestBucket): string {
	return new URL(`${accountPageBase(bucket)}${routeNames.account_apps}`)
		.pathname;
}

export function personLanguage(person: PagePerson, request: Request): Language {
	return languageOfRequest(request, [storedLocaleRanges(person.user)]).language;
}

export function frameFor(person: PagePerson, language: Language): PageFrame {
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

export function seeOther(location: string): Response {
	return new Response(null, { status: 303, headers: { location } });
}

export const NOTICES: readonly ConnectNotice[] = [
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

export const NOTICE_KEY = {
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
async function noticeOf(
	person: PagePerson,
	language: Language,
	query: {
		done?: string;
		notice?: string;
		revocation?: string;
		service?: string;
		app?: string;
	}
): Promise<ServicesNotice | undefined> {
	const T = ACCOUNT_TEXTS[language];
	const service = query.service
		? serviceOf(person.bucket, query.service)
		: undefined;
	const name = service?.displayName ?? '';
	if ((query.done === 'allowed' || query.done === 'withdrawn') && query.app) {
		/* The application is named from its own record, never echoed back from the address bar. */
		const app = await appName(query.app, language);
		return {
			lines: [
				text(query.done === 'allowed' ? T.allowedDone : T.withdrawnDone, {
					app,
					service: name
				})
			]
		};
	}
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
export async function providerAddressOf(
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
	service: t.Optional(t.String()),
	app: t.Optional(t.String())
});

const ActBody = t.Object({
	action: t.Optional(t.String()),
	serviceId: t.Optional(t.String()),
	connectedAccountId: t.Optional(t.String()),
	/* The application a use consent is given to or withdrawn from (specs/118). */
	clientId: t.Optional(t.String()),
	xsrf: t.Optional(t.String())
});

export async function appName(
	clientId: string,
	language: Language
): Promise<string> {
	const client = await Client.tryFind(clientId);
	if (!client) return ACCOUNT_TEXTS[language].deletedApp;
	return sanitiseClientName(client.clientName) ?? clientId;
}

/* Whether `clientId`'s access, as the person granted it, could use a service: the page's offer and its check. */
async function couldUse(
	person: PagePerson,
	clientId: string,
	serviceId: string
): Promise<boolean> {
	const grants = (await grantsIn(person.bucket._id, person.user._id)).filter(
		(grant) => grant.payload.clientId === clientId
	);
	if (grants.length === 0) return false;
	const resources = grants.flatMap((grant) =>
		Object.keys(grant.payload.resources ?? {})
	);
	return (await servicesFor(person.bucket, clientId, resources)).some(
		(service) => service.id === serviceId
	);
}

/*
 * Per connected account: the applications the person allowed to use it, with their last use, and the ones they have
 * granted access to that could use it but are not allowed yet (specs/118 FR-022, FR-022a).
 */
async function consentRows(
	person: PagePerson,
	language: Language
): Promise<
	Map<
		string,
		{
			agents: { clientId: string; name: string; lastUsedAt?: number }[];
			candidates: { clientId: string; name: string }[];
		}
	>
> {
	const records = await getConnectedAccountStore().listByAccount(
		person.bucket._id,
		person.user._id
	);
	const allowed = await agentsByAccount(
		person.bucket,
		person.user._id,
		records
	);
	const grants = await grantsIn(person.bucket._id, person.user._id);
	const applications = [
		...new Set(grants.map((grant) => grant.payload.clientId))
	];
	const rows = new Map<
		string,
		{
			agents: { clientId: string; name: string; lastUsedAt?: number }[];
			candidates: { clientId: string; name: string }[];
		}
	>();
	for (const record of records) {
		const agents = [];
		for (const agent of allowed.get(record._id) ?? []) {
			agents.push({ ...agent, name: await appName(agent.clientId, language) });
		}
		const candidates = [];
		for (const clientId of applications) {
			if (agents.some((agent) => agent.clientId === clientId)) continue;
			if (!(await couldUse(person, clientId, record.serviceId))) continue;
			candidates.push({ clientId, name: await appName(clientId, language) });
		}
		rows.set(record._id, { agents, candidates });
	}
	return rows;
}

function linkPath(person: PagePerson, value: string): string {
	return new URL(connectLinkUrl(person.bucket, value)).pathname;
}

/*
 * A connect from an agent's link has come back connected (specs/119 R6). For a connect, the account just connected
 * is the agent's to use, as the button said, once the administrator's list and the person's grant to the agent are
 * checked again: thirty minutes and a provider lie between the press and now. A reconnect writes no consent; it says
 * whether it was the account asked for.
 */
async function finishLink(
	person: PagePerson,
	link: NonNullable<ConnectStatePayload['link']>,
	record: ConnectedAccount
): Promise<'connected' | 'connectedOnly' | 'reconnected' | 'other'> {
	let outcome: 'connected' | 'connectedOnly' | 'reconnected' | 'other';
	if (link.act === 'reconnect') {
		outcome = record._id === link.connectedAccountId ? 'reconnected' : 'other';
	} else {
		const service = serviceOf(person.bucket, record.serviceId);
		const granted = (await grantsIn(person.bucket._id, person.user._id)).some(
			(grant) => grant.payload.clientId === link.clientId
		);
		if (!granted || !(service?.applications ?? []).includes(link.exchangedBy)) {
			outcome = 'connectedOnly';
		} else {
			await recordEndUserAudit(
				person.bucket._id,
				person.user._id,
				'connected.account.consent',
				{
					targetScope: person.bucket._id,
					connectedAccountId: record._id,
					serviceId: record.serviceId,
					clientId: link.clientId,
					to: 'allowed',
					ownerGroupId: person.bucket.ownerGroupId
				}
			);
			await changeConsent({
				bucket: person.bucket,
				record,
				clientId: link.clientId,
				change: 'allowed',
				via: 'connect_link'
			});
			outcome = 'connected';
		}
	}
	await closeLink(link.value, link.slot, 'completed', record._id);
	return outcome;
}

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
			const consents = await consentRows(person, language);
			const rows = views.map((view) => ({
				id: view.id,
				serviceName: view.serviceName,
				label: view.label,
				scopes: view.scopes,
				missingScopes: view.missingScopes,
				connectedAt: view.connectedAt,
				status: view.status,
				agents: consents.get(view.id)?.agents ?? [],
				candidates: consents.get(view.id)?.candidates ?? []
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
				await ensureXsrf(person.session),
				await noticeOf(person, language, query)
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

			if (
				(action === 'allow' || action === 'withdraw') &&
				body.connectedAccountId &&
				body.clientId
			) {
				const record = await getConnectedAccountStore().find(
					person.bucket._id,
					body.connectedAccountId
				);
				/* Another person's account, one already gone, one that never was: one answer for all three. */
				if (!record || record.accountId !== accountId)
					return seeOther(pagePath);
				const change = action === 'allow' ? 'allowed' : 'withdrawn';
				/* Only an application this account could serve is ever allowed: the same test the page drew. */
				if (
					change === 'allowed' &&
					!(await couldUse(person, body.clientId, record.serviceId))
				) {
					return seeOther(pagePath);
				}
				await recordEndUserAudit(
					person.bucket._id,
					accountId,
					'connected.account.consent',
					{
						targetScope: person.bucket._id,
						connectedAccountId: record._id,
						serviceId: record.serviceId,
						clientId: body.clientId,
						to: change,
						ownerGroupId: person.bucket.ownerGroupId
					}
				);
				const known = await changeConsent({
					bucket: person.bucket,
					record,
					clientId: body.clientId,
					change
				});
				if (!known) return seeOther(pagePath);
				const params = new URLSearchParams({
					done: change,
					service: record.serviceId,
					app: body.clientId
				});
				return seeOther(`${pagePath}?${params.toString()}`);
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
			/* A connect started from an agent's link goes back to the link, which can be tried again while it lives. */
			const back = (notice: ConnectNotice) =>
				pending.link
					? `${linkPath(person, pending.link.value)}?notice=${notice}`
					: noticeHref(person, notice, pending.serviceId);
			if (query.error !== undefined) {
				return seeOther(
					back(query.error === 'access_denied' ? 'declined' : 'failed')
				);
			}
			if (typeof query.code !== 'string' || !query.code) {
				return seeOther(back('failed'));
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
				if (pending.link) {
					const outcome = await finishLink(person, pending.link, record);
					return seeOther(
						`${linkPath(person, pending.link.value)}?done=${outcome}`
					);
				}
				const params = new URLSearchParams({ done, service: record.serviceId });
				return seeOther(`${servicesPath(person.bucket)}?${params.toString()}`);
			} catch (err) {
				if (err instanceof ConnectRefused) {
					if (err.notice === 'refused') refused('issuer', pending.serviceId);
					return seeOther(back(err.notice));
				}
				throw err;
			}
		},
		{ query: CallbackQuery }
	);
