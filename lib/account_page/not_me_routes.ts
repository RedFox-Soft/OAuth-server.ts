import { Elysia, t } from 'elysia';

import { getBucketStore, getUserStore } from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { signOutAdministrator } from '../admin/users/sign_out.js';
import { routeNames } from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import { shownNameOf, type RequestBucket } from '../configs/issuer.js';
import { signOutOwnAccount } from '../end_users/service.js';
import { languageOfRequest } from '../i18n/request.js';
import { storedLocaleRanges } from '../i18n/resolve.js';
import { EMAIL_TEXTS } from '../i18n/texts/email/index.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import { request as requestPasswordReset } from '../password_reset/challenge.js';
import { selfServiceResetAllowed } from '../password_reset/eligibility.js';
import { readNotMeLink, spendNotMeLink } from '../sign_in_alerts/link.js';
import { reportToSuperAdministrators } from '../sign_in_alerts/report.js';
import type { NotMeLinkPayload } from '../totp/types.js';
import { accountPageBase, accountPageUrl } from './client.js';
import {
	notMeAdministratorDonePage,
	notMeConfirmPage,
	notMeGonePage,
	outcomePage,
	signOutOutcomePage,
	type NotMeAfter
} from './html.js';
import { fromThisOrigin } from './session.js';

/*
 * "This wasn't me" from the email about a sign-in from a new network or browser (specs/138 contracts). Opening the
 * link shows what will happen; only the form's POST signs the account out everywhere, so a mail scanner that follows
 * the link changes nothing. A link acts only at the address its own project's pages are served at, the one its email
 * named: a project's own, or the instance's root for the administrators' project and any project without an address
 * of its own.
 */

const TokenQuery = t.Object({ token: t.Optional(t.String()) });
const TokenBody = t.Object({ token: t.Optional(t.String()) });

function addressed(params: unknown, request: Request): Promise<RequestBucket> {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

function acceptsAt(bucket: UserBucket, at: RequestBucket): boolean {
	return (
		bucket._id === at._id || accountPageBase(bucket) === accountPageBase(at)
	);
}

interface Found {
	link: NotMeLinkPayload;
	user: User;
	bucket: UserBucket;
}

async function found(
	token: string,
	at: RequestBucket
): Promise<Found | undefined> {
	const link = await readNotMeLink(token);
	if (!link) return undefined;
	const [user, bucket] = await Promise.all([
		getUserStore(link.bucketId).find(link.accountId),
		getBucketStore().find(link.bucketId)
	]);
	return user && bucket && acceptsAt(bucket, at)
		? { link, user, bucket }
		: undefined;
}

function serviceOf(
	bucket: UserBucket,
	language: 'en' | 'ru' | 'zh-Hans'
): string {
	return bucket._id === ADMIN_BUCKET_ID
		? EMAIL_TEXTS[language].newSignIn.console
		: shownNameOf(bucket);
}

/* What confirming will do to the password, decided as Sign out everywhere decides it (specs/135). */
function afterOf(user: User, bucket: UserBucket): NotMeAfter {
	if (bucket._id === ADMIN_BUCKET_ID) return { kind: 'administrator' };
	if (
		user.passwordSet !== false &&
		selfServiceResetAllowed(bucket._id, bucket)
	) {
		return { kind: 'reset' };
	}
	const linked = new Set(
		(user.federated ?? []).map((identity) => identity.providerId)
	);
	const providers = bucket.federation
		.filter((provider) => linked.has(provider.id))
		.map((provider) => provider.displayName);
	return providers.length ? { kind: 'provider', providers } : { kind: 'none' };
}

export const accountNotMeRoutes = new Elysia({ name: 'account-not-me' })
	.get(
		routeNames.account_not_me,
		async ({ query, params, request }) => {
			const at = await addressed(params, request);
			const hit = await found(query.token ?? '', at);
			const language = languageOfRequest(
				request,
				hit ? [storedLocaleRanges(hit.user)] : []
			).language;
			const forgot = SIGN_IN_TEXTS[language].login.forgotPassword;
			if (!hit) return notMeGonePage(language, shownNameOf(at), forgot);
			return notMeConfirmPage(
				language,
				new URL(`${accountPageBase(hit.bucket)}${routeNames.account_not_me}`)
					.pathname,
				query.token ?? '',
				{ service: serviceOf(hit.bucket, language), email: hit.user.email },
				afterOf(hit.user, hit.bucket)
			);
		},
		{ query: TokenQuery }
	)
	.post(
		routeNames.account_not_me,
		async ({ body, params, request }) => {
			const at = await addressed(params, request);
			const token = body.token ?? '';
			const hit = await found(token, at);
			const language = languageOfRequest(
				request,
				hit ? [storedLocaleRanges(hit.user)] : []
			).language;
			if (!fromThisOrigin(request, new URL(accountPageBase(at)).origin)) {
				return outcomePage(
					'refused',
					new URL(accountPageUrl(at)).pathname,
					403,
					language
				);
			}
			const forgot = SIGN_IN_TEXTS[language].login.forgotPassword;
			if (!hit || !(await spendNotMeLink(token))) {
				return notMeGonePage(language, shownNameOf(at), forgot);
			}
			const { link, user, bucket } = hit;
			if (bucket._id === ADMIN_BUCKET_ID) {
				await recordEndUserAudit(bucket._id, user._id, 'admin.signout', {
					targetScope: bucket._id
				});
				let done = true;
				try {
					await signOutAdministrator(user._id);
				} catch (error) {
					console.error('an administrator reporting a sign-in kept access', {
						error
					});
					done = false;
				}
				await reportToSuperAdministrators(user, bucket, link.signInId);
				return notMeAdministratorDonePage(language, done);
			}
			const service = shownNameOf(bucket);
			const accountHref = accountPageUrl(bucket);
			const swept = await signOutOwnAccount(bucket, user._id, () =>
				recordEndUserAudit(bucket._id, user._id, 'enduser.signout', {
					targetScope: bucket._id,
					ownerGroupId: bucket.ownerGroupId
				})
			);
			if (swept.failedAreas.length > 0) {
				console.error('This wasn’t me left access behind', {
					failedAreas: swept.failedAreas
				});
				return signOutOutcomePage(language, service, accountHref, {
					done: false
				});
			}
			let mailed: 'sent' | 'refused' | 'none' = 'none';
			if (afterOf(user, bucket).kind === 'reset') {
				const asked = await requestPasswordReset(
					user.email,
					bucket._id,
					language
				);
				mailed = asked.ok && asked.sent ? 'sent' : 'refused';
			}
			return signOutOutcomePage(language, service, accountHref, {
				done: true,
				mail: mailed,
				email: user.email,
				forgot
			});
		},
		{ body: TokenBody, parse: 'urlencoded' }
	);
