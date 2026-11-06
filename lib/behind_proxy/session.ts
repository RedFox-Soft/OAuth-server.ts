import crypto from 'node:crypto';

import QuickLRU from 'quick-lru';

import { getUserStore } from '../adapters/index.js';
import type { User } from '../adapters/types.js';
import { groupIdsOfUser, groupNamesOf } from '../bucket_groups/service.js';
import { ttl } from '../configs/liveTime.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import epochTime from '../helpers/epoch_time.js';
import { storedLocaleRanges } from '../i18n/resolve.js';
import { attributesOfRecord } from './conditions.js';
import { appSessions, saveAppSession } from './records.js';

/*
 * A person's session at one app behind a proxy (specs/122 R6, R7): a reference held in a cookie on the app's own
 * host, never a self-contained token, so every path that ends a person's access ends it here too by removing the
 * record (lib/helpers/cascade.ts sweeps the area by account).
 */

const PREFIX = '__Host-foxauth-';

export function sessionCookieName(appId: string): string {
	return `${PREFIX}${appId}`;
}

export function markerCookieName(appId: string): string {
	return `${PREFIX}signin-${appId}`;
}

/*
 * The one place the attributes of both cookies are written, for setting and for expiring alike: a cookie is named
 * by its name, domain and path together, so an expiry written with other attributes would clear a different
 * cookie and leave this one in the browser (wiki/concepts/cookie-path-scoping.md). `__Host-` makes the browser
 * refuse a `Domain`, so the cookie stays on the app's own host.
 */
export function cookieHeader(
	name: string,
	value: string,
	maxAgeSeconds: number
): string {
	return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${String(maxAgeSeconds)}`;
}

export function expiredCookieHeader(name: string): string {
	return cookieHeader(name, '', 0);
}

/* The value of one cookie the browser sent with the original request, as the proxy relayed it. */
export function cookieOf(request: Request, name: string): string | undefined {
	const header = request.headers.get('cookie');
	if (!header) return undefined;
	for (const part of header.split(';')) {
		const at = part.indexOf('=');
		if (at === -1) continue;
		if (part.slice(0, at).trim() === name) {
			const value = part.slice(at + 1).trim();
			return value === '' ? undefined : value;
		}
	}
	return undefined;
}

export function digestOf(value: string): string {
	return crypto.createHash('sha256').update(value).digest('base64url');
}

export function randomValue(): string {
	return crypto.randomBytes(32).toString('base64url');
}

export interface AppScope {
	appId: string;
	bucketId: string;
}

/* A new session; answers the cookie value, which is stored nowhere but in the browser. */
export interface SignedInHow {
	/* Epoch seconds. */
	authTime?: number;
	acr?: string;
	amr?: string[];
}

export async function createAppSession(
	scope: AppScope,
	accountId: string,
	how: SignedInHow = {}
): Promise<string> {
	const value = randomValue();
	const now = epochTime();
	/* No sliding: the session lasts as long as a sign-in session would (FR-029), and no longer. */
	await saveAppSession(
		digestOf(value),
		{
			accountId,
			appId: scope.appId,
			bucketId: scope.bucketId,
			createdAt: now,
			exp: now + ttl.Session,
			...(how.authTime === undefined ? {} : { authTime: how.authTime }),
			...(how.acr === undefined ? {} : { acr: how.acr }),
			...(how.amr === undefined ? {} : { amr: how.amr })
		},
		ttl.Session
	);
	return value;
}

export interface AppSession {
	id: string;
	accountId: string;
	/* Epoch seconds the person signed in; null for a session made before conditions. */
	authTime: number | null;
}

/*
 * The session a cookie value names, accepted only at the app and project it was created for: a cookie of another
 * app of the same project names a record of that app, and is no session here (US4.3).
 */
export async function readAppSession(
	scope: AppScope,
	value: string | undefined
): Promise<AppSession | null> {
	if (!value) return null;
	const id = digestOf(value);
	const record = await appSessions().find(id);
	if (!record) return null;
	/* A lazily reaping datastore can still answer a record past its expiry. */
	if (record.exp <= epochTime()) return null;
	if (record.appId !== scope.appId || record.bucketId !== scope.bucketId) {
		return null;
	}
	return {
		id,
		accountId: record.accountId,
		authTime: record.authTime ?? null
	};
}

export async function endAppSession(id: string): Promise<void> {
	standings.delete(id);
	await appSessions().destroy(id);
}

/* What the decision, the headers and the denial page need to know about the person now. */
export interface Standing {
	accountId: string;
	canSignIn: boolean;
	email: string;
	groupIds: string[];
	groupNames: string[];
	/* The person's stored language, for the denial page. */
	localeRanges: string[];
	/* What an attribute condition may name (specs/124 FR-014): string values only, keyed by attribute name. */
	attributes: Record<string, string>;
	/* When the person signed in (epoch seconds), from the sign-in this session came from; null for an older one. */
	signedInAt: number | null;
}

/*
 * Standing and groups are read live but kept for at most a minute per session (FR-012): every page asset is a
 * check, and groups change rarely. Locking, deactivating and signing out are not delayed by this, because they
 * remove the session record, which is read on every check.
 */
const STANDING_SECONDS = 60;

const standings = new QuickLRU<string, { standing: Standing; at: number }>({
	maxSize: 10_000
});

/*
 * The values an attribute condition may name (specs/124 FR-014): what an administrator or a provisioning connection
 * sets on the person — the enterprise profile, the title, and claims an administrator wrote — as strings only. A
 * claim the person's outside provider copies in is excluded by the condition, not here.
 */
export function attributesOf(
	user: Pick<User, 'profile' | 'claims'>
): Record<string, string> {
	return attributesOfRecord(user);
}

/* Null when the person no longer exists in the project. */
export async function standingOf(
	session: AppSession,
	bucketId: string
): Promise<Standing | null> {
	const cached = standings.get(session.id);
	const now = epochTime();
	if (cached && now - cached.at < STANDING_SECONDS) return cached.standing;

	const user = await getUserStore(bucketId).find(session.accountId);
	if (!user) {
		standings.delete(session.id);
		return null;
	}
	const [groupIds, groupNames] = await Promise.all([
		groupIdsOfUser(bucketId, user._id),
		groupNamesOf(bucketId, user._id)
	]);
	const standing: Standing = {
		accountId: user._id,
		canSignIn: canSignIn(user),
		email: user.email,
		groupIds: [...groupIds].sort(),
		groupNames,
		localeRanges: storedLocaleRanges(user),
		attributes: attributesOf(user),
		signedInAt: session.authTime
	};
	standings.set(session.id, { standing, at: now });
	return standing;
}
