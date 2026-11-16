import { Elysia, t } from 'elysia';

import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { AuthorizationCookies, routeNames } from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import type { RequestBucket } from '../configs/issuer.js';
import { signOutOwnAccount } from '../end_users/service.js';
import { languageOfRequest } from '../i18n/request.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import { request as requestPasswordReset } from '../password_reset/challenge.js';
import { selfServiceResetAllowed } from '../password_reset/eligibility.js';
import { ownSignIns } from '../person_activity/own.js';
import { freshSignIn } from '../totp/self_service.js';
import { accountPageBase } from './client.js';
import {
	outcomePage,
	signInsPage,
	signOutConfirmPage,
	signOutOutcomePage,
	type AccountNav,
	type PageFrame,
	type SignOutMail
} from './html.js';
import { frameFor, personLanguage } from './routes.js';
import {
	ensureXsrf,
	fromThisOrigin,
	signInRedirect,
	usablePerson,
	xsrfMatches,
	type PagePerson
} from './session.js';

/*
 * The person's own recent sign-ins and "Sign out everywhere" (specs/135 contracts/account-page.md). Mounted bare and
 * beneath `/:bucket`, as the other account pages are; no route declares a `params` schema, for the reason
 * lib/account_page/routes.ts gives.
 *
 * Both the list and the act need a sign-in in this browser within fifteen minutes, by any method: a session left open
 * on a shared computer shows nothing and ends nothing until whoever is at it signs in again. Re-authentication
 * returns to the page, never to the act.
 */

function addressOfRequest(params: unknown, request: Request) {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

function pathOf(bucket: RequestBucket): string {
	return new URL(`${accountPageBase(bucket)}${routeNames.account_sign_ins}`)
		.pathname;
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
		security: new URL(`${base}${routeNames.account_security}`).pathname,
		signIns: pathOf(person.bucket),
		current: 'signIns'
	};
}

function frameOf(
	person: PagePerson,
	language: ReturnType<typeof personLanguage>
): PageFrame {
	return { ...frameFor(person, language), path: pathOf(person.bucket) };
}

/* What signing out everywhere will do about a password: the reset mail "Forgot password" would send, or where to go. */
function mailFor(person: PagePerson): SignOutMail {
	const { user, bucket } = person;
	if (
		user.passwordSet !== false &&
		selfServiceResetAllowed(bucket._id, bucket)
	) {
		return 'reset';
	}
	const linked = new Set(
		(user.federated ?? []).map((identity) => identity.providerId)
	);
	const providers = bucket.federation
		.filter((provider) => linked.has(provider.id))
		.map((provider) => provider.displayName);
	return providers.length ? { providers } : 'none';
}

const PageQuery = t.Object({ confirm: t.Optional(t.Literal('1')) });
const PageBody = t.Object({ xsrf: t.Optional(t.String()) });

export const accountSignInsRoutes = new Elysia({ name: 'account-sign-ins' })
	.guard({ cookie: AuthorizationCookies })
	.get(
		routeNames.account_sign_ins,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const person = await usablePerson(addressed, cookie);
			if (!person) {
				return seeOther(signInRedirect(cookie, addressed, { signIns: true }));
			}
			if (!freshSignIn(person.session)) {
				return seeOther(
					signInRedirect(cookie, person.bucket, {
						reauthenticate: { accountId: person.user._id },
						signIns: true
					})
				);
			}
			const language = personLanguage(person, request);
			const frame = frameOf(person, language);
			if (query.confirm === '1') {
				return signOutConfirmPage(
					frame,
					await ensureXsrf(person.session),
					mailFor(person)
				);
			}
			const now = new Date();
			return signInsPage(
				frame,
				navOf(person),
				await ownSignIns(
					person.bucket,
					person.user._id,
					person.session.payload.loginTs,
					now
				),
				now
			);
		},
		{ query: PageQuery }
	)
	.post(
		routeNames.account_sign_ins,
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
			if (!person) {
				return seeOther(signInRedirect(cookie, addressed, { signIns: true }));
			}
			const language = personLanguage(person, request);
			if (!xsrfMatches(person.session, body.xsrf)) {
				return outcomePage('refused', path, 403, language);
			}
			if (!freshSignIn(person.session)) {
				return seeOther(
					signInRedirect(cookie, person.bucket, {
						reauthenticate: { accountId: person.user._id },
						signIns: true
					})
				);
			}
			const { user, bucket } = person;
			const frame = frameOf(person, language);
			const accountHref = new URL(
				`${accountPageBase(bucket)}${routeNames.account_apps}`
			).pathname;
			const mail = mailFor(person);
			const swept = await signOutOwnAccount(bucket, user._id, () =>
				recordEndUserAudit(bucket._id, user._id, 'enduser.signout', {
					targetScope: bucket._id,
					ownerGroupId: bucket.ownerGroupId
				})
			);
			if (swept.failedAreas.length > 0) {
				console.error('sign out everywhere left access behind', {
					failedAreas: swept.failedAreas
				});
				return signOutOutcomePage(language, frame.service, accountHref, {
					done: false
				});
			}
			let mailed: 'sent' | 'refused' | 'none' = 'none';
			if (mail === 'reset') {
				const asked = await requestPasswordReset(
					user.email,
					bucket._id,
					language
				);
				mailed = asked.ok && asked.sent ? 'sent' : 'refused';
			}
			return signOutOutcomePage(language, frame.service, accountHref, {
				done: true,
				mail: mailed,
				email: user.email,
				forgot: SIGN_IN_TEXTS[language].login.forgotPassword
			});
		},
		{ body: PageBody, parse: 'urlencoded' }
	);
