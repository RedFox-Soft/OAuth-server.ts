import { randomBytes } from 'node:crypto';
import { Elysia, t } from 'elysia';

import { getBucketStore } from '../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { shownNameOf, type RequestBucket } from '../configs/issuer.js';
import { endUserCookieAttributes, routeNames } from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import { languageOfRequest } from '../i18n/request.js';
import { storedLocaleRanges } from '../i18n/resolve.js';
import { versionedAsset } from '../html/versionedAsset.js';
import { notMeBucketId } from '../passkeys/account.js';
import {
	completeAdminPasskeyLink,
	getAdminLinkCeremony,
	loadAdminPasskeyLink,
	markAdminLinkTotpVerified,
	prepareAdminLinkCreation
} from '../passkeys/admin_link.js';
import { verifyForAccount } from '../totp/verify.js';
import { accountPageBase } from './client.js';
import {
	outcomePage,
	passkeySetupCreatePage,
	passkeySetupDonePage,
	passkeySetupInvalidPage,
	passkeySetupTotpPage
} from './html.js';
import { fromThisOrigin } from './session.js';

/*
 * Standalone administrator-sent passkey enrollment link page (specs/145 S14): mounted bare and beneath `/:bucket` so
 * WebAuthn runs on the project's exact origin (`relyingPartyOf(bucket).origin`). Works in any browser for 24 hours;
 * GET reads without consuming (scanner-safe); requires TOTP first whenever enrolled; POST consumes atomically.
 */

const SETUP_COOKIE = '_pk_setup';

const SetupQuery = t.Object({
	token: t.Optional(t.String()),
	project: t.Optional(t.String()),
	notice: t.Optional(t.String())
});

const SetupBody = t.Object({
	action: t.Optional(t.String()),
	token: t.Optional(t.String()),
	project: t.Optional(t.String()),
	code: t.Optional(t.String()),
	credential: t.Optional(t.String())
});

const SetupCookies = t.Cookie(
	{ [SETUP_COOKIE]: t.Optional(t.String()) },
	endUserCookieAttributes
);

function addressOfRequest(params: unknown, request: Request) {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

function setupPathOf(bucket: RequestBucket): string {
	return new URL(
		`${accountPageBase(bucket)}${routeNames.account_passkey_setup}`
	).pathname;
}

function ensureHolder(cookie: {
	[SETUP_COOKIE]: {
		value?: unknown;
		set: (opts: Record<string, unknown>) => void;
	};
}): string {
	const existing = cookie[SETUP_COOKIE].value;
	if (typeof existing === 'string' && existing.length >= 24) return existing;
	const fresh = randomBytes(24).toString('base64url');
	cookie[SETUP_COOKIE].set({
		...endUserCookieAttributes,
		value: fresh,
		maxAge: 60 * 60,
		path: '/'
	});
	return fresh;
}

function redirectUrl(
	path: string,
	token: string,
	project?: string,
	notice?: string
): string {
	const params = new URLSearchParams({ token });
	if (project) params.set('project', project);
	if (notice) params.set('notice', notice);
	return `${path}?${params.toString()}`;
}

export const passkeySetupRoutes = new Elysia({ name: 'account-passkey-setup' })
	.guard({ cookie: SetupCookies })
	.get(
		routeNames.account_passkey_setup,
		async ({ query, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const bucketId = await notMeBucketId(addressed, query.project);
			const bucket = bucketId ? await getBucketStore().find(bucketId) : null;
			const token = query.token ?? '';
			const loaded = await loadAdminPasskeyLink(token, bucket);
			const language = languageOfRequest(
				request,
				loaded ? [storedLocaleRanges(loaded.user)] : []
			).language;
			if (!loaded || !bucket) {
				return passkeySetupInvalidPage(language, shownNameOf(addressed));
			}

			const holder = ensureHolder(cookie);
			const path = setupPathOf(bucket);
			const service = shownNameOf(bucket);
			const existingCeremony = await getAdminLinkCeremony(
				holder,
				loaded.id,
				bucket._id,
				loaded.user._id
			);
			const totpVerified = existingCeremony?.totpVerified === true;

			if (loaded.user.totp !== undefined && !totpVerified) {
				return passkeySetupTotpPage({
					language,
					path,
					service,
					email: loaded.user.email,
					token,
					...(query.project ? { project: query.project } : {}),
					wrong: query.notice === 'code'
				});
			}

			const options = await prepareAdminLinkCreation(
				bucket,
				loaded.user,
				holder,
				loaded.id,
				totpVerified
			);
			return passkeySetupCreatePage({
				language,
				path,
				service,
				email: loaded.user.email,
				token,
				...(query.project ? { project: query.project } : {}),
				options: JSON.stringify(options),
				script: versionedAsset('passkeyButton.js'),
				notice: query.notice
			});
		},
		{ query: SetupQuery }
	)
	.post(
		routeNames.account_passkey_setup,
		async ({ body, cookie, params, request }) => {
			const addressed = await addressOfRequest(params, request);
			const path = setupPathOf(addressed);
			const reqLanguage = languageOfRequest(request).language;
			if (
				!fromThisOrigin(request, new URL(accountPageBase(addressed)).origin)
			) {
				return outcomePage('refused', path, 403, reqLanguage);
			}

			const bucketId = await notMeBucketId(addressed, body.project);
			const bucket = bucketId ? await getBucketStore().find(bucketId) : null;
			const token = body.token ?? '';
			const loaded = await loadAdminPasskeyLink(token, bucket);
			const language = languageOfRequest(
				request,
				loaded ? [storedLocaleRanges(loaded.user)] : []
			).language;
			if (!loaded || !bucket) {
				return passkeySetupInvalidPage(language, shownNameOf(addressed));
			}

			const holder = ensureHolder(cookie);
			const targetPath = setupPathOf(bucket);

			if (body.action === 'totp') {
				const outcome = await verifyForAccount(
					bucket._id,
					loaded.user._id,
					body.code ?? ''
				);
				if (!outcome.ok) {
					return new Response(null, {
						status: 303,
						headers: {
							location: redirectUrl(targetPath, token, body.project, 'code')
						}
					});
				}
				await markAdminLinkTotpVerified(bucket, loaded.user, holder, loaded.id);
				return new Response(null, {
					status: 303,
					headers: { location: redirectUrl(targetPath, token, body.project) }
				});
			}

			if (body.action === 'create') {
				const done = await completeAdminPasskeyLink({
					bucket,
					token,
					holder,
					credential: body.credential ?? '',
					request
				});
				if (!done.ok) {
					if (done.reason === 'invalid') {
						return passkeySetupInvalidPage(language, shownNameOf(bucket));
					}
					const notice =
						done.reason === 'totp_required'
							? 'code'
							: done.reason === 'exists'
								? 'exists'
								: done.reason === 'no_user_verification'
									? 'no_uv'
									: done.reason === 'expired'
										? 'expired'
										: 'failed';
					return new Response(null, {
						status: 303,
						headers: {
							location: redirectUrl(targetPath, token, body.project, notice)
						}
					});
				}
				const isAdmin = bucket._id === ADMIN_BUCKET_ID;
				return passkeySetupDonePage({
					language,
					service: shownNameOf(bucket),
					email: done.user.email,
					isAdmin,
					href: isAdmin ? '/admin' : accountPageBase(bucket)
				});
			}

			return new Response(null, {
				status: 303,
				headers: { location: redirectUrl(targetPath, token, body.project) }
			});
		},
		{ body: SetupBody, parse: 'urlencoded' }
	);
