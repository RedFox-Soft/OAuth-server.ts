import { Elysia, t } from 'elysia';

import { getBucketStore, getConnectedAccountStore } from '../adapters/index.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { issuingBucket } from '../admin/auth/bucketAddress.js';
import { ACCOUNT_REAUTHENTICATION_SECONDS } from '../consts/account_page.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import {
	AuthorizationCookies,
	routeNames,
	sessionCookieName
} from '../consts/param_list.js';
import type { RequestBucket } from '../configs/issuer.js';
import epochTime from '../helpers/epoch_time.js';
import type { Language } from '../i18n/languages.js';
import { text } from '../i18n/message.js';
import { languageOfRequest } from '../i18n/request.js';
import { ACCOUNT_TEXTS } from '../i18n/texts/account/index.js';
import {
	ACCOUNTS_PER_SERVICE,
	ConnectRefused,
	serviceOf,
	startConnect,
	statusOf,
	viewOf
} from '../connected_services/accounts.js';
import { changeConsent } from '../connected_services/consent.js';
import {
	closeLink,
	findLink,
	refusedEvent,
	slotOf
} from '../connected_services/link.js';
import type {
	ConnectedAccount,
	ConnectedService,
	ConnectLinkPayload
} from '../connected_services/types.js';
import { grantsIn } from '../end_users/sessions.js';
import { connectedAccountKey } from '../models/grant.js';
import { accountPageBase, connectLinkUrl } from './client.js';
import {
	linkOutcomePage,
	linkPage,
	outcomePage,
	type LinkPageView,
	type PageFrame
} from './html.js';
import {
	NOTICES,
	NOTICE_KEY,
	addressOfRequest,
	appName,
	frameFor,
	personLanguage,
	providerAddressOf,
	seeOther,
	servicesPath
} from './services_routes.js';
import {
	ensureXsrf,
	fromThisOrigin,
	signInRedirect,
	usablePerson,
	xsrfMatches,
	type PagePerson
} from './session.js';

/*
 * Where an agent's connect link leads (specs/119 contracts/link-page.md): the one act that fixes the exchange's
 * refusal, for the person the agent's token named and nobody else. In the account page's family, beside
 * /account/services: plain, script-free, every act a button on a same-origin form, a sign-in within the page's
 * reauthentication window, mounted bare and beneath `/:bucket`.
 */

type CookieJar = Parameters<typeof usablePerson>[1];

interface Opened {
	link: ConnectLinkPayload;
	value: string;
	slot: string;
	person: PagePerson;
	language: Language;
	frame: PageFrame;
	app: string;
}

function valueOf(params: unknown): string {
	const link = (params as { link?: unknown } | undefined)?.link;
	return typeof link === 'string' ? link : '';
}

/* A link of `bucketId` read at this address: its own, or the root it shares, as a session there is read. */
async function servedHere(
	bucketId: string,
	addressed: RequestBucket
): Promise<boolean> {
	if (bucketId === addressed._id) return true;
	return (
		sessionCookieName(await issuingBucket(bucketId)) ===
		sessionCookieName(addressed)
	);
}

function invalid(language: Language): Response {
	const T = ACCOUNT_TEXTS[language];
	return linkOutcomePage(T.linkInvalidTitle, [T.linkInvalid], 404, language);
}

/*
 * The research's order (R5): an unknown, replaced or declined value says nothing; then who is signed in, and how
 * recently. A completed one goes as far as a live one, so only its own person learns it was completed.
 */
async function open(
	params: unknown,
	cookie: CookieJar,
	request: Request
): Promise<Response | Opened> {
	const addressed = await addressOfRequest(params, request);
	const value = valueOf(params);
	const link = await findLink(value);
	if (
		!link ||
		link.state === 'declined' ||
		!(await servedHere(link.bucketId, addressed))
	) {
		return invalid(languageOfRequest(request).language);
	}
	const bucket = await getBucketStore().find(link.bucketId);
	/* A project being deleted signs nobody in, so its links lead nowhere, as its account page does. */
	if (!bucket || isScheduledForDeletion(bucket)) {
		return invalid(languageOfRequest(request).language);
	}
	const person = await usablePerson(addressed, cookie);
	if (!person) {
		return seeOther(signInRedirect(cookie, bucket, { link: value }));
	}
	const language = personLanguage(person, request);
	const T = ACCOUNT_TEXTS[language];
	if (
		person.bucket._id !== link.bucketId ||
		person.user._id !== link.accountId
	) {
		refusedEvent(link, 'other_person');
		return linkOutcomePage(T.linkOtherTitle, [T.linkOther], 403, language);
	}
	const loginTs = person.session.payload.loginTs ?? 0;
	if (epochTime() - loginTs > ACCOUNT_REAUTHENTICATION_SECONDS) {
		return seeOther(
			signInRedirect(cookie, person.bucket, {
				link: value,
				reauthenticate: { accountId: person.user._id }
			})
		);
	}
	return {
		link,
		value,
		slot: slotOf(link),
		person,
		language,
		frame: {
			...frameFor(person, language),
			path: new URL(connectLinkUrl(person.bucket, value)).pathname
		},
		app: await appName(link.clientId, language)
	};
}

interface Situation {
	service: ConnectedService;
	target?: ConnectedAccount;
	view: LinkPageView;
}

/*
 * Everything the exchange checked about the agent and the administrator, checked again now (FR-014), and whether
 * the act was already done elsewhere, on the account page say (spec edge case).
 */
async function situation(opened: Opened): Promise<Response | Situation> {
	const { link, person, language, app } = opened;
	const T = ACCOUNT_TEXTS[language];
	const changed = (sentence: string) => {
		refusedEvent(link, 'changed');
		return linkOutcomePage(
			T.linkChangedTitle,
			[sentence],
			200,
			language,
			servicesPath(person.bucket)
		);
	};
	const service = serviceOf(person.bucket, link.serviceId);
	if (!service) return changed(T.linkChangedService);
	const vars = { app, service: service.displayName };
	if (!(service.applications ?? []).includes(link.exchangedBy)) {
		return changed(text(T.linkChangedApp, vars));
	}
	const grants = (await grantsIn(person.bucket._id, person.user._id)).filter(
		(grant) => grant.payload.clientId === link.clientId
	);
	if (grants.length === 0) return changed(text(T.linkChangedAccess, vars));
	const records = (
		await getConnectedAccountStore().listByAccount(
			person.bucket._id,
			person.user._id
		)
	).filter((record) => record.serviceId === service.id);
	const target = link.connectedAccountId
		? records.find((record) => record._id === link.connectedAccountId)
		: undefined;
	if (link.connectedAccountId && !target) {
		return changed(text(T.linkChangedAccount, vars));
	}
	const allowed = (record: ConnectedAccount) =>
		grants.some(
			(grant) =>
				grant.connectedConsent(connectedAccountKey(record._id)) === 'allowed'
		);
	const done =
		link.act === 'reconnect'
			? target !== undefined &&
				statusOf(target) === 'connected' &&
				viewOf(person.bucket, target).missingScopes.length === 0
			: target
				? allowed(target)
				: records.some(allowed);
	if (done) {
		await closeLink(opened.value, opened.slot, 'completed', target?._id);
		return linkOutcomePage(
			T.linkDoneTitle,
			[T.linkAlreadyDone, text(T.linkReturn, vars)],
			200,
			language,
			servicesPath(person.bucket)
		);
	}
	const offered = target ? [target] : records;
	return {
		service,
		...(target ? { target } : {}),
		view: {
			act: link.act,
			app,
			service: service.displayName,
			accounts:
				link.act === 'reconnect'
					? []
					: offered.map((record) => ({ id: record._id, label: record.label })),
			named: target !== undefined,
			...(target && link.act === 'reconnect'
				? { account: { id: target._id, label: target.label } }
				: {}),
			atLimit: records.length >= ACCOUNTS_PER_SERVICE
		}
	};
}

/* What a completed link says, by the outcome its last step put in the address; nothing else there is read. */
const DONE = {
	connected: 'linkDoneConnected',
	connectedOnly: 'linkDoneConnectedOnly',
	allowed: 'linkDoneAllowed',
	reconnected: 'linkDoneReconnected',
	other: 'linkDoneOther'
} as const;

/* A completed link, to its own person: what was done when the query says, else that it already was. */
async function donePage(
	opened: Opened,
	query: { done?: string }
): Promise<Response> {
	const { link, person, language, app } = opened;
	const T = ACCOUNT_TEXTS[language];
	const service = serviceOf(person.bucket, link.serviceId);
	const target = link.connectedAccountId
		? await getConnectedAccountStore().find(
				person.bucket._id,
				link.connectedAccountId
			)
		: undefined;
	const vars = {
		app,
		service: service?.displayName ?? '',
		account: target?.label ?? ''
	};
	const done = Object.entries(DONE).find(([value]) => value === query.done);
	const key = done ? done[1] : 'linkAlreadyDone';
	return linkOutcomePage(
		T.linkDoneTitle,
		[text(T[key], vars), text(T.linkReturn, vars)],
		200,
		language,
		servicesPath(person.bucket)
	);
}

const LinkQuery = t.Object({
	done: t.Optional(t.String()),
	notice: t.Optional(t.String())
});

const LinkBody = t.Object({
	action: t.Optional(t.String()),
	/* The ticked accounts: one value per checkbox, so a single tick arrives as a string. */
	connectedAccountId: t.Optional(
		t.Union([
			t.String({ maxLength: 512 }),
			t.Array(t.String({ maxLength: 512 }), { maxItems: 64 })
		])
	),
	xsrf: t.Optional(t.String())
});

export const accountLinkRoutes = new Elysia({ name: 'account-services-link' })
	.guard({ cookie: AuthorizationCookies })
	.get(
		routeNames.account_services_link,
		async ({ query, cookie, params, request }) => {
			const opened = await open(params, cookie, request);
			if (opened instanceof Response) return opened;
			if (opened.link.state === 'completed') return donePage(opened, query);
			const now = await situation(opened);
			if (now instanceof Response) return now;
			const notice = NOTICES.find((value) => value === query.notice);
			const view: LinkPageView = {
				...now.view,
				...(notice
					? { notice: ACCOUNT_TEXTS[opened.language][NOTICE_KEY[notice]] }
					: {})
			};
			/* Where a connect form's redirect will go, for the page's `form-action`. */
			const connects = view.act === 'reconnect' || !view.atLimit;
			return linkPage(
				opened.frame,
				view,
				await ensureXsrf(opened.person.session),
				connects
					? await providerAddressOf(opened.person, now.service.id)
					: undefined
			);
		},
		{ query: LinkQuery }
	)
	.post(
		routeNames.account_services_link,
		async ({ body, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			/* Before the session, as the other account pages do: another site's request says nothing to act on. */
			if (
				!fromThisOrigin(request, new URL(accountPageBase(addressed)).origin)
			) {
				return outcomePage(
					'refused',
					servicesPath(addressed),
					403,
					languageOfRequest(request).language
				);
			}
			const opened = await open(params, cookie, request);
			if (opened instanceof Response) return opened;
			const { link, person, language, frame, app } = opened;
			if (!xsrfMatches(person.session, body.xsrf)) {
				return outcomePage(
					'refused',
					servicesPath(person.bucket),
					403,
					language
				);
			}
			if (link.state === 'completed') return donePage(opened, {});
			const now = await situation(opened);
			if (now instanceof Response) return now;
			const T = ACCOUNT_TEXTS[language];
			const vars = { app, service: now.service.displayName };
			const decline = async () => {
				await closeLink(opened.value, opened.slot, 'declined');
				return linkOutcomePage(
					T.linkDeclinedTitle,
					[text(T.linkDeclined, vars)],
					200,
					language,
					servicesPath(person.bucket)
				);
			};

			if (body.action === 'connect') {
				if (link.act !== 'reconnect' && now.view.atLimit) {
					return seeOther(`${frame.path}?notice=limit`);
				}
				const sessionId = cookie[sessionCookieName(addressed)].value;
				if (typeof sessionId !== 'string' || !sessionId) {
					return seeOther(`${frame.path}?notice=refused`);
				}
				try {
					return seeOther(
						await startConnect({
							bucket: person.bucket,
							serviceId: now.service.id,
							accountId: person.user._id,
							sessionId,
							/*
							 * "Connect another" from a consent link connects as a connect link does (R6): the new account is
							 * the agent's to use, as the button said.
							 */
							link: {
								slot: opened.slot,
								value: opened.value,
								clientId: link.clientId,
								exchangedBy: link.exchangedBy,
								act: link.act === 'reconnect' ? 'reconnect' : 'connect',
								...(link.act === 'reconnect' && now.target
									? { connectedAccountId: now.target._id }
									: {})
							}
						})
					);
				} catch (err) {
					if (err instanceof ConnectRefused) {
						return seeOther(`${frame.path}?notice=${err.notice}`);
					}
					throw err;
				}
			}

			if (body.action === 'allow') {
				const ticked = new Set(
					body.connectedAccountId === undefined
						? []
						: Array.isArray(body.connectedAccountId)
							? body.connectedAccountId
							: [body.connectedAccountId]
				);
				/* Only what the page offered: a value it did not offer is ignored, never acted on. */
				const chosen = now.view.accounts.filter((account) =>
					ticked.has(account.id)
				);
				if (chosen.length === 0) return decline();
				for (const account of chosen) {
					const record = await getConnectedAccountStore().find(
						person.bucket._id,
						account.id
					);
					if (!record) continue;
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
				}
				await closeLink(opened.value, opened.slot, 'completed', chosen[0].id);
				return seeOther(`${frame.path}?done=allowed`);
			}

			if (body.action === 'decline') return decline();
			return seeOther(frame.path);
		},
		{ body: LinkBody, parse: 'urlencoded' }
	);
