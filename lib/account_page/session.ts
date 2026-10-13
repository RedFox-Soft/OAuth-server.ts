import crypto from 'node:crypto';

import { getBucketStore, getUserStore } from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import {
	bucketIsScheduled,
	issuingBucket
} from '../admin/auth/bucketAddress.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import {
	ACCOUNT_PAGE_COOKIE,
	ACCOUNT_PAGE_PENDING_SECONDS
} from '../consts/account_page.js';
import {
	endUserCookieAttributes,
	routeNames,
	sessionCookieName
} from '../consts/param_list.js';
import type { RequestBucket } from '../configs/issuer.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import constantEquals from '../helpers/constant_equals.js';
import epochTime from '../helpers/epoch_time.js';
import { Session } from '../models/session.js';
import { accountPageBase, accountPageClientId } from './client.js';

/*
 * Who is looking at a bucket's connected-applications page, from that bucket's own sign-in session and
 * nothing else (specs/095 R2). The server is the authorization server: it knows who is signed in without a
 * token, and the page mints none.
 */

export interface PagePerson {
	session: Session;
	bucket: UserBucket;
	user: User;
}

type CookieJar = Record<
	string,
	{ value: unknown; set(options: Record<string, unknown>): unknown }
>;

export async function usablePerson(
	addressed: RequestBucket,
	cookie: CookieJar
): Promise<PagePerson | undefined> {
	const id = cookie[sessionCookieName(addressed)].value;
	if (typeof id !== 'string' || !id) return undefined;
	/*
	 * Read, never saved: a save renews the whole sign-in, and looking at one's applications is not a reason
	 * for a sign-in to last longer.
	 */
	const session = await Session.tryFind(id);
	const accountId = session?.payload.accountId;
	const bucketId = session?.payload.bucketId;
	if (!session || !accountId || !bucketId) return undefined;
	if (bucketId === ADMIN_BUCKET_ID) return undefined;
	/*
	 * The default bucket and every bucket with no address of its own share the root and its cookie, so at the
	 * root the session says which of them it is. It must still be one that signs in here — the check sign-out
	 * makes — or a bucket given an address since would be readable at an address it no longer has.
	 */
	if (
		bucketId !== addressed._id &&
		sessionCookieName(await issuingBucket(bucketId)) !==
			sessionCookieName(addressed)
	) {
		return undefined;
	}
	if (await bucketIsScheduled(bucketId)) return undefined;
	const bucket = await getBucketStore().find(bucketId);
	if (!bucket || isScheduledForDeletion(bucket)) return undefined;
	const user = await getUserStore(bucketId).find(accountId);
	/* The rule every sign-in obeys: a person who may not sign in may not use what a sign-in gives. */
	if (!user || !canSignIn(user)) return undefined;
	return { session, bucket, user };
}

/* The page's anti-forgery value for this session, created the first time a form needs one. */
export async function ensureXsrf(session: Session): Promise<string> {
	const existing = session.payload.accountPageXsrf;
	if (existing) return existing;
	const value = crypto.randomBytes(24).toString('hex');
	session.payload.accountPageXsrf = value;
	/* With what is left of its life: adding a form value must not extend the sign-in. */
	const remaining = (session.payload.exp ?? 0) - epochTime();
	if (remaining > 0) await session.save(remaining);
	return value;
}

export function xsrfMatches(session: Session, value: unknown): boolean {
	const expected = session.payload.accountPageXsrf;
	return (
		typeof value === 'string' &&
		typeof expected === 'string' &&
		value.length === expected.length &&
		constantEquals(value, expected)
	);
}

/*
 * A removal is a form this page served, posted back to the same origin. A browser says where a request came
 * from in `Sec-Fetch-Site` and `Origin`; when either names somewhere else, the request did not come from this
 * page. Absent, the anti-forgery value decides alone — older browsers send neither.
 *
 * `Origin: null` says nothing either way and is not a refusal. Every page here is served with
 * `Referrer-Policy: no-referrer`, under which a browser serializes even a same-origin form's origin as "null"
 * (Fetch, "serializing a request origin") — refusing it refused the page's own form in Chrome while every
 * test, which sent no such header, passed. A sandboxed frame elsewhere sends "null" too, but its post is
 * cross-site: `Sec-Fetch-Site` says so, the `Lax` session cookie stays behind, and it has no anti-forgery value.
 */
export function fromThisOrigin(request: Request, pageOrigin: string): boolean {
	const site = request.headers.get('sec-fetch-site');
	if (site !== null && site !== 'same-origin') return false;
	const origin = request.headers.get('origin');
	if (origin !== null && origin !== 'null' && origin !== pageOrigin) {
		return false;
	}
	return true;
}

/* A sign-in the page started, kept in the browser until it comes back. */
export interface PendingSignIn {
	state: string;
	startedAt: number;
	/* Set for a re-authentication: the person who asked for it. */
	accountId?: string;
	/* The application whose confirmation to return to; never acted on by itself. */
	revoke?: string;
}

/*
 * The page's own path, which is where the pending cookie lives: named on set and on clear, or the clear
 * writes a second cookie beside the first (wiki cookie-path-scoping).
 */
function pagePath(bucket: RequestBucket): string {
	return new URL(`${accountPageBase(bucket)}${routeNames.account_apps}`)
		.pathname;
}

export function setPending(
	cookie: CookieJar,
	bucket: RequestBucket,
	pending: PendingSignIn
): void {
	/*
	 * Encoded, because the framework parses a JSON-looking cookie value into an object on the way back in, and
	 * a value whose type depends on its contents is one more thing to get wrong.
	 */
	cookie[ACCOUNT_PAGE_COOKIE].set({
		...endUserCookieAttributes,
		value: Buffer.from(JSON.stringify(pending)).toString('base64url'),
		path: pagePath(bucket),
		maxAge: ACCOUNT_PAGE_PENDING_SECONDS
	});
}

export function readPending(cookie: CookieJar): PendingSignIn | undefined {
	const raw = cookie[ACCOUNT_PAGE_COOKIE].value;
	if (typeof raw !== 'string' || !raw) return undefined;
	try {
		const parsed: unknown = JSON.parse(
			Buffer.from(raw, 'base64url').toString('utf8')
		);
		if (
			typeof parsed !== 'object' ||
			parsed === null ||
			typeof (parsed as PendingSignIn).state !== 'string' ||
			typeof (parsed as PendingSignIn).startedAt !== 'number'
		) {
			return undefined;
		}
		/* Narrowed field by field above; the browser holds this value, so nothing else in it is trusted. */
		const { state, startedAt, accountId, revoke } = parsed as PendingSignIn;
		return {
			state,
			startedAt,
			...(typeof accountId === 'string' ? { accountId } : undefined),
			...(typeof revoke === 'string' ? { revoke } : undefined)
		};
	} catch {
		return undefined;
	}
}

export function clearPending(cookie: CookieJar, bucket: RequestBucket): void {
	cookie[ACCOUNT_PAGE_COOKIE].set({
		...endUserCookieAttributes,
		value: '',
		path: pagePath(bucket),
		maxAge: 0,
		expires: new Date(0)
	});
}

/*
 * Starts a sign-in in the bucket, through its page client, and remembers it. `response_type=none`: the page
 * wants the person signed in, not a code (R3).
 */
export function signInRedirect(
	cookie: CookieJar,
	bucket: RequestBucket,
	options: { reauthenticate?: { accountId: string; revoke?: string } } = {}
): string {
	const state = crypto.randomBytes(32).toString('base64url');
	setPending(cookie, bucket, {
		state,
		startedAt: epochTime(),
		...(options.reauthenticate
			? {
					accountId: options.reauthenticate.accountId,
					...(options.reauthenticate.revoke
						? { revoke: options.reauthenticate.revoke }
						: undefined)
				}
			: undefined)
	});
	const base = accountPageBase(bucket);
	const params = new URLSearchParams({
		client_id: accountPageClientId(bucket._id),
		response_type: 'none',
		scope: 'openid',
		redirect_uri: `${base}${routeNames.account_apps_callback}`,
		state
	});
	if (options.reauthenticate) params.set('prompt', 'login');
	return `${base}${routeNames.authorization}?${params.toString()}`;
}
