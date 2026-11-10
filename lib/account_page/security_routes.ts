import { Elysia, t } from 'elysia';

import { getBucketStore, getUserStore } from '../adapters/index.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { AuthorizationCookies, routeNames } from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import { shownNameOf, type RequestBucket } from '../configs/issuer.js';
import {
	disownAuthenticator,
	EndUserError,
	enrolOwnAuthenticator,
	enrolmentInstant,
	removeOwnAuthenticator
} from '../end_users/service.js';
import { languageOfRequest } from '../i18n/request.js';
import { storedLocaleRanges } from '../i18n/resolve.js';
import { ACCOUNT_TEXTS } from '../i18n/texts/account/index.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import { text } from '../i18n/message.js';
import {
	confirm,
	dropOffer,
	noteWrongCode,
	offer,
	waitingOffer
} from '../totp/enrollment.js';
import { MAX_ATTEMPTS_PER_INTERACTION } from '../totp/consts.js';
import { qrSvg } from '../totp/qr.js';
import {
	followLink,
	freshCode,
	freshPassword,
	notifyEnrolled,
	notifyTwoStep,
	pageHolder,
	raiseSession,
	readDisownLink,
	securityPageUrl,
	selfServiceState,
	sendLink,
	spendDisownLink,
	type LinkSent
} from '../totp/self_service.js';
import { accountPageBase } from './client.js';
import {
	disownConfirmPage,
	disownOutcomePage,
	outcomePage,
	securityPage,
	type AccountNav,
	type SecurityNotice,
	type SecurityView
} from './html.js';
import { frameFor, personLanguage } from './routes.js';
import {
	ensureXsrf,
	fromThisOrigin,
	signInRedirect,
	usablePerson,
	xsrfMatches,
	type PagePerson,
	type SecurityStep
} from './session.js';

/*
 * The person's own two-step verification (specs/126 contracts/security-page.md): turning it on, moving it to another
 * phone, turning it off, and the "This wasn't me" link. Mounted bare and beneath `/:bucket`, as the other account
 * pages are; no route declares a `params` schema, for the reason lib/account_page/routes.ts gives.
 *
 * Every act needs proof a password thief lacks: a fresh password sign-in and a link mailed to the account to turn it
 * on, a fresh code from the factor to change or remove it. Re-authentication returns to this page, never to the act.
 */

function addressOfRequest(params: unknown, request: Request) {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

function pathOf(bucket: RequestBucket): string {
	return new URL(securityPageUrl(bucket)).pathname;
}

function seeOther(location: string): Response {
	return new Response(null, { status: 303, headers: { location } });
}

function navOf(person: PagePerson): AccountNav {
	const base = accountPageBase(person.bucket);
	return {
		apps: new URL(`${base}${routeNames.account_apps}`).pathname,
		...(person.bucket.connectedServices?.length
			? {
					services: new URL(`${base}${routeNames.account_services}`).pathname
				}
			: {}),
		security: pathOf(person.bucket),
		current: 'security'
	};
}

function linkUrl(bucket: RequestBucket, token: string): string {
	return `${accountPageBase(bucket)}${routeNames.account_security_link}?token=${encodeURIComponent(token)}`;
}

/* The names of the providers this person can also sign in with, which never ask for the code. */
function providersOf(person: PagePerson): string[] {
	const linked = new Set(
		(person.user.federated ?? []).map((identity) => identity.providerId)
	);
	return person.bucket.federation
		.filter((provider) => linked.has(provider.id))
		.map((provider) => provider.displayName);
}

function hasPassword(person: PagePerson): boolean {
	return person.user.passwordSet !== false;
}

const PageQuery = t.Object({
	sent: t.Optional(t.Union([t.Literal('enrol'), t.Literal('replace')])),
	done: t.Optional(t.String()),
	notice: t.Optional(t.String()),
	off: t.Optional(t.Literal('1'))
});

const PageBody = t.Object({
	action: t.Optional(t.String()),
	xsrf: t.Optional(t.String()),
	code: t.Optional(t.String())
});

const TokenQuery = t.Object({ token: t.Optional(t.String()) });
const TokenBody = t.Object({ token: t.Optional(t.String()) });

function noticeFor(
	query: { done?: string; notice?: string },
	person: PagePerson,
	language: ReturnType<typeof personLanguage>
): SecurityNotice | undefined {
	const T = ACCOUNT_TEXTS[language];
	const values = { email: person.user.email };
	switch (query.done) {
		case 'on':
			return { kind: 'success', text: text(T.securityDoneOn, values) };
		case 'changed':
			return { kind: 'success', text: T.securityDoneChanged };
		case 'off':
			return { kind: 'success', text: T.securityDoneOff };
	}
	switch (query.notice) {
		case 'throttled':
			return { kind: 'error', text: T.securityThrottled };
		case 'mail':
			return { kind: 'error', text: T.securityMailFailed };
		case 'link':
			return { kind: 'error', text: T.securityLinkInvalid };
		case 'changed':
			return { kind: 'error', text: T.securityChanged };
	}
	return undefined;
}

function reauthenticate(
	cookie: Parameters<typeof signInRedirect>[0],
	person: PagePerson,
	step: SecurityStep
): Response {
	return seeOther(
		signInRedirect(cookie, person.bucket, {
			reauthenticate: { accountId: person.user._id },
			security: step
		})
	);
}

function sentAnswer(
	path: string,
	sent: LinkSent,
	purpose: 'enrol' | 'replace'
) {
	if (sent === 'sent') return seeOther(`${path}?sent=${purpose}`);
	return seeOther(
		`${path}?notice=${sent === 'throttled' ? 'throttled' : 'mail'}`
	);
}

/* Whether this person may set up a factor here at all, right now (FR-003, FR-004). */
async function mayEnrol(person: PagePerson): Promise<boolean> {
	return (
		hasPassword(person) && (await selfServiceState(person.bucket)) === 'on'
	);
}

export const accountSecurityRoutes = new Elysia({ name: 'account-security' })
	.guard({ cookie: AuthorizationCookies })
	.get(
		routeNames.account_security,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const person = await usablePerson(addressed, cookie);
			if (!person) {
				return seeOther(
					signInRedirect(cookie, addressed, { security: 'view' })
				);
			}
			const language = personLanguage(person, request);
			const frame = {
				...frameFor(person, language),
				path: pathOf(person.bucket)
			};
			const xsrf = await ensureXsrf(person.session);
			const notice = noticeFor(query, person, language);
			const { user, bucket, session } = person;

			const holder = pageHolder(session);
			const waiting = await waitingOffer(holder, user._id, bucket._id);
			const offerView = async (): Promise<SecurityView> => {
				const shown = await offer(holder, user._id, bucket._id, {
					email: user.email,
					label: shownNameOf(bucket)
				});
				return {
					state: 'offer',
					qrSvg: qrSvg(
						shown.otpauthUri,
						ACCOUNT_TEXTS[language].securityQrLabel
					),
					key: shown.secretText,
					otpauthUri: shown.otpauthUri,
					wrong: query.notice === 'code'
				};
			};

			let view: SecurityView;
			if (user.totp) {
				// A replacement under way shows its new code; otherwise the factor in place.
				view =
					waiting?.replacing !== undefined
						? await offerView()
						: query.sent === 'replace'
							? { state: 'sent', purpose: 'replace' }
							: {
									state: 'on',
									since: new Date(user.totp.enrolledAt),
									required: bucket.totpRequired,
									providers: providersOf(person),
									confirmOff: query.off === '1' && !bucket.totpRequired
								};
			} else if (!hasPassword(person)) {
				view = { state: 'noPassword' };
			} else if ((await selfServiceState(bucket)) !== 'on') {
				view = { state: 'unavailable' };
			} else if (waiting) {
				view = await offerView();
			} else if (query.sent !== undefined) {
				view = { state: 'sent', purpose: query.sent };
			} else {
				view = {
					state: 'off',
					providerSession:
						!freshPassword(session) && !session.payload.amr?.includes('pwd')
				};
			}
			return securityPage(frame, navOf(person), view, xsrf, notice);
		},
		{ query: PageQuery }
	)
	.post(
		routeNames.account_security,
		async ({ body, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const path = pathOf(addressed);
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
			if (!person)
				return seeOther(
					signInRedirect(cookie, addressed, { security: 'view' })
				);
			if (!xsrfMatches(person.session, body.xsrf)) {
				return outcomePage(
					'refused',
					path,
					403,
					languageOfRequest(request).language
				);
			}
			const { user, bucket, session } = person;
			const holder = pageHolder(session);
			const pagePath = pathOf(bucket);
			const audit =
				(
					action:
						| 'enduser.totp.enrol'
						| 'enduser.totp.replace'
						| 'enduser.totp.remove'
				) =>
				() =>
					recordEndUserAudit(bucket._id, user._id, action, {
						targetScope: bucket._id,
						ownerGroupId: bucket.ownerGroupId
					});

			switch (body.action) {
				case 'start': {
					if (user.totp || !(await mayEnrol(person))) return seeOther(pagePath);
					if (!freshPassword(session))
						return reauthenticate(cookie, person, 'enrol');
					await dropOffer(holder);
					const sent = await sendLink(bucket, user, 'enrol', holder, {
						request,
						urlFor: (token) => linkUrl(bucket, token)
					});
					return sentAnswer(pagePath, sent, 'enrol');
				}
				case 'replace': {
					const current = enrolmentInstant(user.totp?.enrolledAt);
					if (current === undefined) return seeOther(pagePath);
					if (!freshCode(session))
						return reauthenticate(cookie, person, 'replace');
					if ((await selfServiceState(bucket)) === 'no_mail') {
						return seeOther(`${pagePath}?notice=mail`);
					}
					await dropOffer(holder);
					const sent = await sendLink(bucket, user, 'replace', holder, {
						request,
						urlFor: (token) => linkUrl(bucket, token),
						enrolledAt: current
					});
					return sentAnswer(pagePath, sent, 'replace');
				}
				case 'confirm': {
					const waiting = await waitingOffer(holder, user._id, bucket._id);
					if (!waiting) return seeOther(pagePath);
					const replacing = waiting.replacing;
					/*
					 * Checked again at the last step: a project that stopped offering this, or a person who lost the
					 * password meanwhile, does not get a factor from an offer made before (spec edge case).
					 */
					if (replacing === undefined && !(await mayEnrol(person))) {
						await dropOffer(holder);
						return seeOther(pagePath);
					}
					if (waiting.attempts >= MAX_ATTEMPTS_PER_INTERACTION) {
						await dropOffer(holder);
						return seeOther(`${pagePath}?notice=changed`);
					}
					// Set from inside the write below, which is where a replacement learns the factor changed meanwhile.
					const meanwhile = { changed: false };
					const outcome = await confirm(
						holder,
						user._id,
						bucket._id,
						body.code ?? '',
						async (proved) => {
							try {
								await enrolOwnAuthenticator(
									bucket,
									user._id,
									{
										secret: proved.secret,
										step: proved.step,
										via: 'self',
										...(replacing !== undefined ? { replacing } : {})
									},
									audit(
										replacing === undefined
											? 'enduser.totp.enrol'
											: 'enduser.totp.replace'
									),
									{ addressProved: true }
								);
								return true;
							} catch (error) {
								if (error instanceof EndUserError && error.status === 409) {
									meanwhile.changed = true;
									return false;
								}
								if (error instanceof EndUserError && error.status === 404)
									return false;
								throw error;
							}
						}
					);
					if (!outcome.ok) {
						if (outcome.reason === 'invalid') {
							const attempts = await noteWrongCode(holder);
							if (attempts >= MAX_ATTEMPTS_PER_INTERACTION) {
								await dropOffer(holder);
								return seeOther(`${pagePath}?notice=changed`);
							}
							return seeOther(`${pagePath}?notice=code`);
						}
						return seeOther(
							`${pagePath}?notice=${meanwhile.changed ? 'changed' : 'link'}`
						);
					}
					const enrolled = await getUserStore(bucket._id).find(user._id);
					if (enrolled) {
						if (replacing === undefined && freshPassword(session)) {
							await raiseSession(session);
						}
						await notifyEnrolled(
							bucket,
							enrolled,
							replacing === undefined ? 'on' : 'changed'
						);
					}
					return seeOther(
						`${pagePath}?done=${replacing === undefined ? 'on' : 'changed'}`
					);
				}
				case 'off': {
					if (!user.totp || bucket.totpRequired) return seeOther(pagePath);
					if (!freshCode(session)) return reauthenticate(cookie, person, 'off');
					await removeOwnAuthenticator(
						bucket,
						user._id,
						audit('enduser.totp.remove')
					);
					await notifyTwoStep(bucket, user, {
						kind: 'off',
						pageUrl: securityPageUrl(bucket)
					});
					return seeOther(`${pagePath}?done=off`);
				}
				default:
					return seeOther(pagePath);
			}
		},
		{ body: PageBody, parse: 'urlencoded' }
	)
	.get(
		routeNames.account_security_link,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const person = await usablePerson(addressed, cookie);
			const path = pathOf(addressed);
			// Signed out, or in another browser: the link can only work where it was asked for.
			if (!person) return seeOther(`${path}?notice=link`);
			const { user, bucket, session } = person;
			const holder = pageHolder(session);
			const link = await followLink(
				query.token ?? '',
				holder,
				user._id,
				bucket._id
			);
			if (!link) return seeOther(`${path}?notice=link`);
			if (
				link.purpose === 'enrol' &&
				(user.totp || !(await mayEnrol(person)))
			) {
				return seeOther(path);
			}
			if (
				link.purpose === 'replace' &&
				enrolmentInstant(user.totp?.enrolledAt) !== link.enrolledAt
			) {
				return seeOther(`${path}?notice=changed`);
			}
			await dropOffer(holder);
			await offer(
				holder,
				user._id,
				bucket._id,
				{ email: user.email, label: shownNameOf(bucket) },
				link.purpose === 'replace' && link.enrolledAt !== undefined
					? { replacing: link.enrolledAt }
					: {}
			);
			return seeOther(path);
		},
		{ query: TokenQuery }
	)
	.get(
		routeNames.account_security_disown,
		async ({ query, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const link = await readDisownLink(query.token ?? '');
			const user = link
				? await getUserStore(link.bucketId).find(link.accountId)
				: undefined;
			const bucket = link ? await getBucketStore().find(link.bucketId) : null;
			const language = languageOfRequest(
				request,
				user ? [storedLocaleRanges(user)] : []
			).language;
			if (!link || !user || !bucket) {
				return disownOutcomePage(
					language,
					false,
					shownNameOf(addressed),
					SIGN_IN_TEXTS[language].login.forgotPassword
				);
			}
			return disownConfirmPage(
				language,
				new URL(
					`${accountPageBase(bucket)}${routeNames.account_security_disown}`
				).pathname,
				query.token ?? '',
				user.email
			);
		},
		{ query: TokenQuery }
	)
	.post(
		routeNames.account_security_disown,
		async ({ body, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const language = languageOfRequest(request).language;
			if (
				!fromThisOrigin(request, new URL(accountPageBase(addressed)).origin)
			) {
				return outcomePage('refused', pathOf(addressed), 403, language);
			}
			const token = body.token ?? '';
			const link = await readDisownLink(token);
			const bucket = link ? await getBucketStore().find(link.bucketId) : null;
			const service = bucket ? shownNameOf(bucket) : shownNameOf(addressed);
			// In the person's language, as the confirmation page before it was, not only the browser's.
			const owner = link
				? await getUserStore(link.bucketId).find(link.accountId)
				: null;
			const shown = languageOfRequest(
				request,
				owner ? [storedLocaleRanges(owner)] : []
			).language;
			const forgot = SIGN_IN_TEXTS[shown].login.forgotPassword;
			if (
				!link ||
				!bucket ||
				link.enrolledAt === undefined ||
				!(await spendDisownLink(token))
			) {
				return disownOutcomePage(shown, false, service, forgot);
			}
			const removed = await disownAuthenticator(
				bucket,
				link.accountId,
				link.enrolledAt,
				() =>
					recordEndUserAudit(
						bucket._id,
						link.accountId,
						'enduser.totp.disown',
						{
							targetScope: bucket._id,
							ownerGroupId: bucket.ownerGroupId
						}
					)
			);
			return disownOutcomePage(shown, removed, service, forgot);
		},
		{ body: TokenBody, parse: 'urlencoded' }
	);
