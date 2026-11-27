import { Elysia, t } from 'elysia';

import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from '../adapters/index.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import {
	consoleStaysReachable,
	loadReachabilityState
} from '../admin/federation/reachability.js';
import { signOutAdministrator } from '../admin/users/sign_out.js';
import { reportPasskeyDisownToSuperAdministrators } from '../sign_in_alerts/report.js';
import { AuthorizationCookies, routeNames } from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import { shownNameOf, type RequestBucket } from '../configs/issuer.js';
import {
	disownAuthenticator,
	disownPasskeys,
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
import epochTime from '../helpers/epoch_time.js';
import { request as requestPasswordReset } from '../password_reset/challenge.js';
import { selfServiceResetAllowed } from '../password_reset/eligibility.js';
import { qrSvg } from '../totp/qr.js';
import {
	followLink,
	freshCode,
	freshPasskey,
	freshPassword,
	freshSignIn,
	notifyEnrolled,
	notifyTwoStep,
	pageHolder,
	raiseSession,
	readDisownLink,
	securityPageUrl,
	selfServiceState,
	sendLink,
	spendDisownLink,
	strongRecentSignIn,
	type LinkSent
} from '../totp/self_service.js';
import { versionedAsset } from '../html/versionedAsset.js';
import { passkeysAccepted } from '../passkeys/accepted.js';
import {
	addAvailability,
	completeAdd,
	completeRemove,
	creationOptionsFor,
	isLastWayIn,
	liveAdd,
	liveRemove,
	notMeBucketId,
	notMePasskey,
	ownPasskey,
	passkeysOf,
	prepareAdd,
	prepareRemove,
	renamePasskey,
	type AddProof,
	type AddRefused,
	type PageSession,
	type RemoveRefused
} from '../passkeys/account.js';
import { confirmByLink, confirmOnPage } from '../passkeys/offer.js';
import { passkeyName } from '../passkeys/names.js';
import { relyingPartyOf } from '../passkeys/relying_party.js';
import type { Session } from '../models/session.js';
import { accountPageBase } from './client.js';
import {
	disownConfirmPage,
	disownOutcomePage,
	notMeAdministratorDonePage,
	outcomePage,
	passkeyConfirmOutcomePage,
	passkeyConfirmPage,
	passkeyDisownConfirmPage,
	passkeyDisownDonePage,
	passkeyDisownGonePage,
	passkeyDisownRefusedPage,
	securityPage,
	type AccountNav,
	type PasskeysView,
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
		signIns: new URL(`${base}${routeNames.account_sign_ins}`).pathname,
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

/* The name of the project a page is addressed to, as its people know it: the stored record carries its shown name. */
async function serviceAt(addressed: RequestBucket): Promise<string> {
	return shownNameOf((await getBucketStore().find(addressed._id)) ?? addressed);
}

function hasPassword(person: PagePerson): boolean {
	return person.user.passwordSet !== false;
}

const PageQuery = t.Object({
	sent: t.Optional(
		t.Union([
			t.Literal('enrol'),
			t.Literal('replace'),
			t.Literal('passkey'),
			t.Literal('passkey_remove')
		])
	),
	done: t.Optional(t.String()),
	notice: t.Optional(t.String()),
	off: t.Optional(t.Literal('1')),
	/* The passkey whose rename form to open, and the one whose removal to confirm (specs/139). */
	rename: t.Optional(t.String()),
	remove: t.Optional(t.String())
});

const PageBody = t.Object({
	action: t.Optional(t.String()),
	xsrf: t.Optional(t.String()),
	code: t.Optional(t.String()),
	/* A passkey add: the browser's answer as JSON, read and bounded by lib/passkeys/ceremony.ts. */
	credential: t.Optional(t.String()),
	/* A passkey's record id, and the name a rename gives it. */
	passkey: t.Optional(t.String()),
	name: t.Optional(t.String())
});

const TokenQuery = t.Object({ token: t.Optional(t.String()) });
const TokenBody = t.Object({ token: t.Optional(t.String()) });
/* A passkey's "This wasn't me" link also names its project where the project's address cannot (`notMeBucketId`). */
const NotMeQuery = t.Object({
	token: t.Optional(t.String()),
	project: t.Optional(t.String())
});
const NotMeBody = t.Object({
	token: t.Optional(t.String()),
	project: t.Optional(t.String())
});

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
		case 'passkey_added':
			return { kind: 'success', text: text(T.passkeyAdded, values) };
		case 'passkey_renamed':
			return { kind: 'success', text: T.passkeyRenamed };
		case 'passkey_removed':
			return { kind: 'success', text: text(T.passkeyRemoved, values) };
		case 'passkey_confirmed':
			return { kind: 'success', text: T.passkeyConfirmed };
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
		case 'passkey_ready':
			return { kind: 'success', text: T.passkeyReady };
		case 'passkey_expired':
			return { kind: 'error', text: T.passkeyTooLong };
		case 'passkey_no_uv':
			return { kind: 'error', text: T.passkeyNoUserVerification };
		case 'passkey_exists':
			return { kind: 'error', text: T.passkeyExists };
		case 'passkey_failed':
			return { kind: 'error', text: T.passkeyAddFailed };
		case 'passkey_name':
			return { kind: 'error', text: T.passkeyNameInvalid };
		case 'passkey_last':
			return {
				kind: 'error',
				text: text(T.passkeyLast, { service: shownNameOf(person.bucket) })
			};
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
			security: step,
			// Two-step verification's own acts need a password, or a password and its code: no passkey there (R13).
			passwordOnly: step === 'enrol' || step === 'replace' || step === 'off'
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

/* The browser session the page's passkey ceremonies belong to (specs/139 research R15). */
function pageSession(session: Session): PageSession {
	return { uid: session.payload.uid, holder: pageHolder(session) };
}

/*
 * The proof a strong recent sign-in gives an add (specs/139 research R13): a passkey, or a password with a code, in
 * this browser within fifteen minutes. A password alone gives none: it needs the mailed link as well.
 */
function strongProof(session: Session): AddProof | undefined {
	if (freshPasskey(session)) return 'passkey';
	if (freshCode(session)) return 'password_code';
	return undefined;
}

const REMOVE_REFUSED: Record<Exclude<RemoveRefused, 'gone'>, string> = {
	last: 'passkey_last',
	expired: 'passkey_expired'
};

const ADD_REFUSED: Record<AddRefused, string> = {
	expired: 'passkey_expired',
	no_user_verification: 'passkey_no_uv',
	exists: 'passkey_exists',
	full: 'passkey_failed',
	unavailable: 'passkey_failed',
	failed: 'passkey_failed'
};

/*
 * The Passkeys part of the page (contracts/account-page.md), or none: shown where the project accepts passkeys, or
 * where the person still holds some there. A strong recent sign-in prepares the add on the GET itself, so the button is
 * ready the moment the page is; a live add (prepared before, or by a followed link) is used as it is, never replaced,
 * so a mailed link's proof is not lost to a reload.
 */
async function passkeysView(
	person: PagePerson,
	language: ReturnType<typeof personLanguage>,
	query: { sent?: string; rename?: string; remove?: string }
): Promise<PasskeysView | undefined> {
	const { user, bucket, session } = person;
	const held = await passkeysOf(bucket, user);
	if (!passkeysAccepted(bucket) && held.length === 0) return undefined;
	const rpId = relyingPartyOf(bucket).rpId;
	const at = pageSession(session);
	const listed = (id: string | undefined) =>
		id !== undefined && held.some((passkey) => passkey._id === id)
			? id
			: undefined;
	const renaming = listed(query.rename);
	const removing = listed(query.remove);
	/*
	 * A removal is confirmed on the page only where the act would be allowed: a strong recent sign-in, or a removal a
	 * mailed link prepared in this browser for that very passkey.
	 */
	const confirms =
		removing !== undefined &&
		(strongRecentSignIn(session) ||
			(await liveRemove(user, bucket, at, removing)));
	const manage = {
		...(renaming === undefined ? {} : { renaming }),
		...(confirms ? { removing } : {}),
		...(query.sent === 'passkey_remove' ? { removeSent: true } : {})
	};
	const rows = held.map((passkey) => ({
		id: passkey._id,
		name: passkeyName(passkey, language),
		createdAt: new Date(passkey.createdAt),
		...(passkey.lastUsedAt ? { lastUsedAt: new Date(passkey.lastUsedAt) } : {}),
		synced: passkey.backedUp,
		via: passkey.createdVia,
		...(passkey.conditional ? { unconfirmed: true as const } : {}),
		...(passkey.copiedAt
			? { mark: 'copied' as const }
			: passkey.rpId !== rpId
				? { mark: 'oldAddress' as const }
				: {})
	}));
	/*
	 * The browser is told which of the person's passkeys this project accepts at this site, and their current label
	 * (specs/141 research R10). Only while the project accepts passkeys and the person has a passkey identity here: the
	 * list is for that identity alone, so a passkey of another project at the same site is never touched.
	 */
	const party = relyingPartyOf(bucket);
	const signalling =
		passkeysAccepted(bucket) && user.webauthnUserId !== undefined
			? {
					signals: {
						rpId,
						userId: user.webauthnUserId,
						accepted: held
							.filter(
								(passkey) =>
									passkey.copiedAt === undefined && passkey.rpId === rpId
							)
							.map((passkey) => passkey.credentialId),
						name: `${user.email} · ${party.name}`,
						displayName: `${user.email} · ${party.name}`
					},
					script: versionedAsset('passkeyButton.js')
				}
			: {};
	const manageAll = {
		...manage,
		...signalling,
		...(strongRecentSignIn(session) ? { confirmable: true } : {})
	};
	switch (await addAvailability(bucket, user, held.length)) {
		case 'not_accepted':
			return { rows, ...manageAll, state: 'stopped' };
		case 'provider_only':
			return {
				rows,
				...manageAll,
				state: 'providerOnly',
				providers: providersOf(person)
			};
		case 'no_mail':
			return { rows, ...manageAll, state: 'noMail' };
		case 'unconfirmed':
			return { rows, ...manageAll, state: 'unconfirmed' };
		case 'full':
			return { rows, ...manageAll, state: 'full' };
		case 'ready':
			break;
	}
	let ceremony = await liveAdd(user, bucket, at);
	const proof = strongProof(session);
	if (!ceremony && proof) ceremony = await prepareAdd(bucket, user, at, proof);
	const options = ceremony
		? await creationOptionsFor(bucket, user, ceremony)
		: undefined;
	if (options) {
		return {
			rows,
			...manageAll,
			state: 'add',
			options: JSON.stringify(options),
			script: versionedAsset('passkeyButton.js')
		};
	}
	return {
		rows,
		...manageAll,
		state: query.sent === 'passkey' ? 'sent' : 'start'
	};
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
			const totpSent =
				query.sent === 'passkey' || query.sent === 'passkey_remove'
					? undefined
					: query.sent;
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
						: totpSent === 'replace'
							? { state: 'sent', purpose: 'replace' }
							: {
									state: 'on',
									since: new Date(user.totp.enrolledAt),
									required: bucket.totpRequired,
									providers: providersOf(person),
									confirmOff: query.off === '1' && !bucket.totpRequired
								};
			} else if (
				!hasPassword(person) ||
				// Without password sign-in nobody here is asked for a code, so it is not theirs to set up either (specs/127).
				(await selfServiceState(bucket)) === 'no_password_login'
			) {
				view = { state: 'noPassword' };
			} else if ((await selfServiceState(bucket)) !== 'on') {
				view = { state: 'unavailable' };
			} else if (waiting) {
				view = await offerView();
			} else if (totpSent !== undefined) {
				view = { state: 'sent', purpose: totpSent };
			} else {
				view = {
					state: 'off',
					providerSession:
						!freshPassword(session) && !session.payload.amr?.includes('pwd')
				};
			}
			return securityPage(
				frame,
				navOf(person),
				view,
				xsrf,
				notice,
				await passkeysView(person, language, query)
			);
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
				case 'passkey_start': {
					/*
					 * Adding a passkey (specs/139 contracts/account-page.md): a strong recent sign-in opens the page's add
					 * button at once; a fresh password alone mails a link that works only in this browser; anything else
					 * signs in again, returning to this page and never to the act.
					 */
					const held = await passkeysOf(bucket, user);
					if ((await addAvailability(bucket, user, held.length)) !== 'ready')
						return seeOther(pagePath);
					if (strongProof(session)) return seeOther(pagePath);
					if (!freshPassword(session))
						return reauthenticate(cookie, person, 'passkey_add');
					const sent = await sendLink(bucket, user, 'passkey_add', holder, {
						request,
						urlFor: (token) => linkUrl(bucket, token)
					});
					if (sent === 'sent') return seeOther(`${pagePath}?sent=passkey`);
					return seeOther(
						`${pagePath}?notice=${sent === 'throttled' ? 'throttled' : 'mail'}`
					);
				}
				case 'passkey_add': {
					const added = await completeAdd(
						bucket,
						user,
						pageSession(session),
						body.credential ?? '',
						request
					);
					return seeOther(
						added.ok
							? `${pagePath}?done=passkey_added`
							: `${pagePath}?notice=${ADD_REFUSED[added.reason]}`
					);
				}
				case 'passkey_rename': {
					/* The person's own label (FR-028): a sign-in of any kind within fifteen minutes, else sign in again. */
					const passkey = await ownPasskey(bucket, user, body.passkey);
					if (!passkey) return seeOther(pagePath);
					if (!freshSignIn(session))
						return reauthenticate(cookie, person, 'passkey_rename');
					const renamed = await renamePasskey(
						bucket,
						user,
						passkey._id,
						body.name
					);
					if (renamed === 'renamed')
						return seeOther(`${pagePath}?done=passkey_renamed`);
					if (renamed === 'invalid') {
						return seeOther(
							`${pagePath}?notice=passkey_name&rename=${encodeURIComponent(passkey._id)}`
						);
					}
					return seeOther(pagePath);
				}
				case 'passkey_remove_start': {
					/*
					 * Removing a passkey takes the proof adding one does (FR-028): a strong recent sign-in confirms on the
					 * page; a fresh password alone mails a link for this passkey that works only in this browser; anything
					 * else signs in again, returning to this page. The last way in is refused before any of it (FR-029).
					 */
					const passkey = await ownPasskey(bucket, user, body.passkey);
					if (!passkey) return seeOther(pagePath);
					if (await isLastWayIn(bucket, user, passkey))
						return seeOther(`${pagePath}?notice=passkey_last`);
					if (strongRecentSignIn(session)) {
						return seeOther(
							`${pagePath}?remove=${encodeURIComponent(passkey._id)}`
						);
					}
					if (!freshPassword(session))
						return reauthenticate(cookie, person, 'passkey_remove');
					const sent = await sendLink(bucket, user, 'passkey_remove', holder, {
						request,
						urlFor: (token) => linkUrl(bucket, token),
						passkeyId: passkey._id
					});
					if (sent === 'sent')
						return seeOther(`${pagePath}?sent=passkey_remove`);
					return seeOther(
						`${pagePath}?notice=${sent === 'throttled' ? 'throttled' : 'mail'}`
					);
				}
				case 'passkey_confirm': {
					/*
					 * Confirming a passkey made after a password alone (specs/141 FR-017): only after a strong recent
					 * sign-in, so nothing a password alone opens can raise a password-made passkey to two factors.
					 */
					const confirmed = await confirmOnPage(
						bucket,
						user,
						session,
						body.passkey
					);
					return seeOther(
						confirmed === 'cannot'
							? pagePath
							: `${pagePath}?done=passkey_confirmed`
					);
				}
				case 'passkey_remove': {
					const removed = await completeRemove(
						bucket,
						user,
						pageSession(session),
						body.passkey,
						strongRecentSignIn(session)
					);
					if (removed.ok) return seeOther(`${pagePath}?done=passkey_removed`);
					return seeOther(
						removed.reason === 'gone'
							? pagePath
							: `${pagePath}?notice=${REMOVE_REFUSED[removed.reason]}`
					);
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
			/*
			 * A passkey's proof link (specs/139 research R14) prepares an add, or the removal of one passkey, proved by the
			 * mailbox, for this browser session only; it never becomes an authenticator offer.
			 */
			if (link.purpose === 'passkey_add') {
				const held = await passkeysOf(bucket, user);
				if ((await addAvailability(bucket, user, held.length)) !== 'ready')
					return seeOther(path);
				await prepareAdd(bucket, user, pageSession(session), 'password_mail');
				return seeOther(`${path}?notice=passkey_ready`);
			}
			if (link.purpose === 'passkey_remove') {
				const passkey = await ownPasskey(bucket, user, link.passkeyId);
				if (!passkey) return seeOther(path);
				await prepareRemove(bucket, user, pageSession(session), passkey._id);
				return seeOther(`${path}?remove=${encodeURIComponent(passkey._id)}`);
			}
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
	)
	/*
	 * "Yes, this was me" about a conditional passkey (specs/141 contracts/account-page-and-mail.md). It acts only in the
	 * browser session that made the passkey, signed in at this address: anywhere else, including the owner's own browser
	 * for a passkey someone else made, it changes nothing. Opening the link only shows the form; the POST is the act.
	 */
	.get(
		routeNames.account_passkey_confirm,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const person = await usablePerson(addressed, cookie);
			if (!person) {
				return passkeyConfirmOutcomePage(
					languageOfRequest(request).language,
					'cannot'
				);
			}
			return passkeyConfirmPage(
				personLanguage(person, request),
				new URL(
					`${accountPageBase(addressed)}${routeNames.account_passkey_confirm}`
				).pathname,
				{
					token: query.token ?? '',
					xsrf: await ensureXsrf(person.session),
					...(query.project ? { project: query.project } : {})
				},
				shownNameOf(person.bucket)
			);
		},
		{ query: NotMeQuery }
	)
	.post(
		routeNames.account_passkey_confirm,
		async ({ body, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const person = await usablePerson(addressed, cookie);
			if (
				!person ||
				!fromThisOrigin(request, new URL(accountPageBase(addressed)).origin) ||
				!xsrfMatches(person.session, body.xsrf)
			) {
				return passkeyConfirmOutcomePage(
					person
						? personLanguage(person, request)
						: languageOfRequest(request).language,
					'cannot'
				);
			}
			return passkeyConfirmOutcomePage(
				personLanguage(person, request),
				await confirmByLink(
					person.bucket,
					person.user,
					person.session,
					body.token ?? ''
				)
			);
		},
		{
			body: t.Object({
				token: t.Optional(t.String()),
				xsrf: t.Optional(t.String()),
				project: t.Optional(t.String())
			}),
			parse: 'urlencoded'
		}
	)
	/*
	 * "This wasn't me" about an added passkey (specs/139 research R16, contracts/account-page.md). The link's state lives
	 * on the passkey record, which a sign-out everywhere never touches, so whoever added the passkey cannot kill the
	 * owner's link by signing out everywhere with it. The token is looked up only among the passkeys of the project the
	 * request is addressed to, which is the address its mail named: at any other project's address it names nothing.
	 */
	.get(
		routeNames.account_passkey_disown,
		async ({ query, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const bucketId = await notMeBucketId(addressed, query.project);
			const hit = bucketId
				? await notMePasskey(bucketId, query.token ?? '')
				: undefined;
			const owner =
				hit && bucketId
					? await getUserStore(bucketId).find(hit.passkey.accountId)
					: null;
			const language = languageOfRequest(
				request,
				owner ? [storedLocaleRanges(owner)] : []
			).language;
			if (!hit || !owner) {
				return passkeyDisownGonePage(language, await serviceAt(addressed));
			}
			return passkeyDisownConfirmPage(
				language,
				new URL(
					`${accountPageBase(addressed)}${routeNames.account_passkey_disown}`
				).pathname,
				{
					token: query.token ?? '',
					...(bucketId === addressed._id ? {} : { project: bucketId })
				},
				owner.email
			);
		},
		{ query: NotMeQuery }
	)
	.post(
		routeNames.account_passkey_disown,
		async ({ body, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			if (
				!fromThisOrigin(request, new URL(accountPageBase(addressed)).origin)
			) {
				return outcomePage(
					'refused',
					pathOf(addressed),
					403,
					languageOfRequest(request).language
				);
			}
			const bucketId = await notMeBucketId(addressed, body.project);
			const hit = bucketId
				? await notMePasskey(bucketId, body.token ?? '')
				: undefined;
			const bucket =
				hit && bucketId ? await getBucketStore().find(bucketId) : null;
			const owner =
				hit && bucket
					? await getUserStore(bucket._id).find(hit.passkey.accountId)
					: null;
			const language = languageOfRequest(
				request,
				owner ? [storedLocaleRanges(owner)] : []
			).language;
			if (!hit || !bucket || !owner) {
				return passkeyDisownGonePage(language, await serviceAt(addressed));
			}
			/*
			 * An administrator disowning a passkey (specs/144 FR-009, FR-018): refuse before spending the link if
			 * removing this passkey and any added at or after it would leave zero active super administrators able to
			 * reach the console; otherwise spend, audit `admin.passkey.disown`, remove, sign out everywhere (console
			 * sessions included), alert super administrators, and never send a self-service password reset.
			 */
			if (bucket._id === ADMIN_BUCKET_ID) {
				const since = new Date(hit.passkey.createdAt);
				const held = await getPasskeyStore().listOf(bucket._id, owner._id);
				const removedWorking = held.filter(
					(p) =>
						new Date(p.createdAt).getTime() >= since.getTime() &&
						p.rpId === relyingPartyOf(bucket).rpId &&
						p.copiedAt === undefined &&
						p.conditional !== true
				).length;
				const state = await loadReachabilityState();
				if (state.superAdministrators.some((s) => s._id === owner._id)) {
					const nextCounts = new Map(state.superAdminPasskeyCounts);
					nextCounts.set(
						owner._id,
						Math.max(0, (nextCounts.get(owner._id) ?? 0) - removedWorking)
					);
					if (
						!consoleStaysReachable({
							...state,
							superAdminPasskeyCounts: nextCounts
						})
					) {
						return passkeyDisownRefusedPage(
							language,
							'Removing this passkey would leave no super administrator able to sign in to the console. Add another passkey or have another super administrator add one first.'
						);
					}
				}
				if (
					!(await getPasskeyStore().spendNotMe(
						bucket._id,
						hit.passkey._id,
						hit.digest,
						epochTime()
					))
				) {
					return passkeyDisownGonePage(language, await serviceAt(addressed));
				}
				await recordEndUserAudit(
					bucket._id,
					owner._id,
					'admin.passkey.disown',
					{
						targetScope: bucket._id
					}
				);
				const removed = await getPasskeyStore().removeAddedSince(
					bucket._id,
					owner._id,
					since
				);
				let done = true;
				try {
					await signOutAdministrator(owner._id);
				} catch (error) {
					console.error(
						'This wasn’t me about an administrator passkey left access behind',
						{ error }
					);
					done = false;
				}
				await reportPasskeyDisownToSuperAdministrators(owner, removed);
				return notMeAdministratorDonePage(language, done);
			}
			if (
				!(await getPasskeyStore().spendNotMe(
					bucket._id,
					hit.passkey._id,
					hit.digest,
					epochTime()
				))
			) {
				return passkeyDisownGonePage(language, await serviceAt(addressed));
			}
			const { swept } = await disownPasskeys(
				bucket,
				owner._id,
				new Date(hit.passkey.createdAt),
				() =>
					recordEndUserAudit(bucket._id, owner._id, 'enduser.passkey.disown', {
						targetScope: bucket._id,
						ownerGroupId: bucket.ownerGroupId
					})
			);
			const service = shownNameOf(bucket);
			const forgot = SIGN_IN_TEXTS[language].login.forgotPassword;
			if (swept.failedAreas.length > 0) {
				console.error('This wasn’t me about a passkey left access behind', {
					failedAreas: swept.failedAreas
				});
				return passkeyDisownDonePage(language, {
					done: false,
					service,
					email: owner.email,
					forgot,
					mail: 'none'
				});
			}
			/* The password goes too where there is one to reset: whoever added the passkey knew it (FR-031). */
			let mail: 'sent' | 'refused' | 'none' = 'none';
			if (
				owner.passwordSet !== false &&
				selfServiceResetAllowed(bucket._id, bucket)
			) {
				const asked = await requestPasswordReset(
					owner.email,
					bucket._id,
					language
				);
				mail = asked.ok && asked.sent ? 'sent' : 'refused';
			}
			return passkeyDisownDonePage(language, {
				done: true,
				service,
				email: owner.email,
				forgot,
				mail
			});
		},
		{ body: NotMeBody, parse: 'urlencoded' }
	);
