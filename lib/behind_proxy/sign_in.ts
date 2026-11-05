import { kindOf } from '../activity/kinds.js';
import { markActivity } from '../activity/note.js';
import type { BehindProxyApp } from '../adapters/types.js';
import { findAccount } from '../addon/index.js';
import { servingBucketIdOf } from '../admin/auth/bucketAddress.js';
import { issuerFor, type RequestBucket } from '../configs/issuer.js';
import { routeNames } from '../consts/param_list.js';
import constantEquals from '../helpers/constant_equals.js';
import epochTime from '../helpers/epoch_time.js';
import { InvalidGrant } from '../helpers/errors.js';
import { verifyPKCE } from '../helpers/pkce.js';
import { languageOfRequest } from '../i18n/request.js';
import { AuthorizationCode } from '../models/authorization_code.js';
import { Grant } from '../models/grant.js';
import { redirect, withReason, type AnswerReason } from './answers.js';
import { behindProxyCallbackUri, behindProxyClientId } from './client.js';
import { hasControlCharacter } from './decide.js';
import { signInFailedPage } from './pages.js';
import { pendingSignIns, savePendingSignIn } from './records.js';
import {
	cookieHeader,
	cookieOf,
	createAppSession,
	digestOf,
	endAppSession,
	expiredCookieHeader,
	markerCookieName,
	randomValue,
	readAppSession,
	sessionCookieName
} from './session.js';
import { ttl } from '../configs/liveTime.js';
import { noteSignedIn } from './usage.js';

/*
 * Signing a person in to an app behind a proxy, and out of it (specs/122 R5, R6). The sign-in is the project's own:
 * an authorization code request with PKCE through the project's implicit client, returning to a path reserved on
 * the app's host that the proxy relays here. The code is redeemed in-process and only here — no token is minted —
 * and what the person ends up with is an app session.
 */

export interface SignInContext {
	bucket: RequestBucket;
	app: BehindProxyApp;
	request: Request;
}

/* How long a sign-in may take between its start and its callback. */
const SIGN_IN_SECONDS = 10 * 60;

export const START_PATH = '/_foxauth/start';
export const SIGN_OUT_PATH = '/_foxauth/sign_out';
const RESERVED_PREFIX = /^\/_foxauth(?:[/?#]|$)/i;
const MAX_RETURN_LENGTH = 2048;

/*
 * Where the person lands after signing in: a path on the app's own origin, or its root (FR-024). An absolute
 * address is accepted only on the app's origin; `//host` and `/\host` are other origins to a browser, and a
 * reserved path would sign out or start over instead of landing.
 */
export function returnToOf(
	raw: string | null | undefined,
	appAddress: string
): string {
	if (!raw || raw.length > MAX_RETURN_LENGTH) return '/';
	if (hasControlCharacter(raw) || raw.includes('\\')) return '/';
	if (raw.startsWith('//')) return '/';
	let url: URL;
	try {
		url = new URL(raw, appAddress);
	} catch {
		return '/';
	}
	if (url.origin !== appAddress || url.username || url.password) return '/';
	if (!raw.startsWith('/') && !/^https:\/\//i.test(raw)) return '/';
	const path = `${url.pathname}${url.search}`;
	return RESERVED_PREFIX.test(path) ? '/' : path;
}

/*
 * Starts a sign-in: a pending record held by the server (where to return, the PKCE verifier, the digest of a
 * marker), and the marker itself set on the app's host, so the callback is honoured only in the browser that
 * started it (FR-025).
 */
export async function startSignIn(
	{ bucket, app }: SignInContext,
	returnTo: string,
	reason: AnswerReason,
	options: { prompt?: 'login' } = {}
): Promise<Response> {
	const state = randomValue();
	const marker = randomValue();
	const verifier = randomValue();
	await savePendingSignIn(
		state,
		{
			appId: app._id,
			bucketId: bucket._id,
			returnTo,
			codeVerifier: verifier,
			markerDigest: digestOf(marker),
			used: false,
			exp: epochTime() + SIGN_IN_SECONDS
		},
		SIGN_IN_SECONDS
	);
	const params = new URLSearchParams({
		client_id: behindProxyClientId(bucket._id),
		response_type: 'code',
		scope: 'openid email',
		redirect_uri: behindProxyCallbackUri(app.address),
		state,
		code_challenge: digestOf(verifier),
		code_challenge_method: 'S256'
	});
	if (options.prompt) params.set('prompt', options.prompt);
	return redirect(
		`${issuerFor(bucket)}${routeNames.authorization}?${params.toString()}`,
		reason,
		[cookieHeader(markerCookieName(app._id), marker, SIGN_IN_SECONDS)]
	);
}

/* An OAuth error code from the sign-in is shown as it is only when it looks like one. */
function shownError(error: string | null): string {
	return error && /^[a-z_]{1,64}$/.test(error) ? error : 'sign_in_failed';
}

function failed(ctx: SignInContext, shown: string): Response {
	const { app, request } = ctx;
	return withReason(
		signInFailedPage({
			host: new URL(app.address).host,
			reason: shown,
			startHref: START_PATH,
			language: languageOfRequest(request).language
		}),
		'sign_in_failed'
	);
}

/*
 * The callback: honoured once, in the browser that started the sign-in, for the app and project it was started
 * for. The marker is compared before the record is consumed, so a crafted link carrying someone else's `state`
 * cannot use up the sign-in a person is in the middle of.
 */
export async function completeSignIn(
	ctx: SignInContext,
	query: URLSearchParams
): Promise<Response> {
	const { bucket, app, request } = ctx;
	const state = query.get('state');
	const pending = state ? await pendingSignIns().find(state) : undefined;
	const marker = cookieOf(request, markerCookieName(app._id));
	if (
		!state ||
		!pending ||
		pending.exp <= epochTime() ||
		pending.appId !== app._id ||
		pending.bucketId !== bucket._id ||
		!marker ||
		!constantEquals(digestOf(marker), pending.markerDigest)
	) {
		return failed(ctx, 'sign_in_failed');
	}
	if (!(await pendingSignIns().consume(state))) {
		return failed(ctx, 'sign_in_failed');
	}

	const code = query.get('code');
	if (query.has('error') || !code) {
		return failed(ctx, shownError(query.get('error')));
	}
	const accountId = await redeem(ctx, code, pending.codeVerifier);
	if (!accountId) return failed(ctx, 'sign_in_failed');

	const value = await createAppSession(
		{ appId: app._id, bucketId: bucket._id },
		accountId
	);
	noteSignedIn(app);
	return redirect(`${app.address}${pending.returnTo}`, 'signed_in', [
		cookieHeader(sessionCookieName(app._id), value, ttl.Session),
		expiredCookieHeader(markerCookieName(app._id))
	]);
}

/*
 * The code grant's checks that apply to a code nobody presents at the token endpoint
 * (lib/actions/grants/authorization_code.ts): issued to this project's proxy client, by the project this check
 * was addressed at, for this app's callback, to the verifier this sign-in holds, and consumed once. The account is
 * resolved as every grant resolves it, and the sign-in counts as activity in the project (FR-026). Answers the
 * account, or nothing for a code that does not hold up; a datastore fault is left to throw.
 */
async function redeem(
	{ bucket, app }: SignInContext,
	value: string,
	verifier: string
): Promise<string | undefined> {
	const clientId = behindProxyClientId(bucket._id);
	const code = await AuthorizationCode.tryFind(value, {
		ignoreExpiration: true
	});
	if (!code || code.isExpired) return undefined;
	const { payload } = code;
	if (payload.clientId !== clientId) return undefined;
	if ((await servingBucketIdOf(payload.bucketId)) !== bucket._id) {
		return undefined;
	}
	if (payload.redirectUri !== behindProxyCallbackUri(app.address)) {
		return undefined;
	}
	if (!payload.codeChallenge || payload.codeChallengeMethod !== 'S256') {
		return undefined;
	}
	try {
		verifyPKCE(verifier, payload.codeChallenge, payload.codeChallengeMethod);
	} catch (error) {
		if (error instanceof InvalidGrant) return undefined;
		throw error;
	}
	if (!payload.grantId || !payload.accountId) return undefined;
	const grant = await Grant.tryFind(payload.grantId);
	if (
		!grant ||
		grant.payload.clientId !== clientId ||
		grant.payload.accountId !== payload.accountId
	) {
		return undefined;
	}
	if (payload.consumed || !(await code.consume())) return undefined;

	const account = await findAccount(undefined, payload.accountId, {
		payload: { clientId }
	});
	if (!account) return undefined;
	markActivity(account, kindOf('authorization_code', payload.signIn), {
		route: routeNames.authorization,
		method: 'GET',
		clientId
	});
	return account.accountId;
}

/*
 * Ends the person's session at this app and expires its cookie with the attributes it was set with. With
 * `then=start` it goes on to a sign-in that asks who the person is, which is how "use another account" lets them
 * be someone else even while their project session is still open.
 */
export async function signOut(
	{ bucket, app, request }: SignInContext,
	query: URLSearchParams
): Promise<Response> {
	const session = await readAppSession(
		{ appId: app._id, bucketId: bucket._id },
		cookieOf(request, sessionCookieName(app._id))
	);
	if (session) await endAppSession(session.id);
	const then =
		query.get('then') === 'start' ? `${START_PATH}?prompt=login` : '/';
	return redirect(`${app.address}${then}`, 'signed_out', [
		expiredCookieHeader(sessionCookieName(app._id))
	]);
}
