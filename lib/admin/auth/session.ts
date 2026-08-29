import { adminSessionStore, getGroupStore } from '../../adapters/index.js';
import {
	ADMIN_SESSION_COOKIE,
	ADMIN_SESSION_TTL_SECONDS,
	ADMIN_SESSION_ABSOLUTE_TTL_SECONDS
} from '../consts.js';
import type { AdminSession } from '../../adapters/types.js';

/*
 * A new session starts in the administrator's personal group. Resolved here rather than defaulted in
 * the store, because the store has no way to look one up and a wrong default would silently point a
 * console at a group the caller does not belong to.
 *
 * Falls back to the empty string for a super administrator, who belongs to no group by virtue of the
 * role. `resolveActiveGroup` in rbac.ts re-derives the scope on every request anyway, so this value is
 * a starting point rather than a lasting claim.
 */
export async function createAdminSession(data: {
	userId: string;
	bucketId: string;
	tokens: AdminSession['tokens'];
}) {
	const personal = await getGroupStore().findPersonalFor(data.userId);
	return adminSessionStore.create({
		...data,
		activeGroupId: personal?._id ?? '',
		ttlSeconds: ADMIN_SESSION_TTL_SECONDS,
		absoluteTtlSeconds: ADMIN_SESSION_ABSOLUTE_TTL_SECONDS
	});
}

export function sessionCookieAttributes() {
	return {
		httpOnly: true,
		sameSite: 'strict' as const,
		secure: true,
		path: '/admin',
		maxAge: ADMIN_SESSION_TTL_SECONDS
	};
}

/*
 * The attributes that remove the session cookie, derived from the ones that set it.
 *
 * Elysia's `cookie.remove()` emits only `value`/`expires`/`maxAge` — no `Path` — so the browser
 * falls back to RFC 6265's default-path, the directory of the *request* URI. Logout is served from
 * `/admin/api/logout`, giving `/admin/api`, while the live cookie was stored under `/admin`. A
 * different path is a different cookie, so the real one was never removed and the operator stayed
 * signed in. Spreading the setter's attributes is what keeps the two from drifting apart again.
 */
export function expiredSessionCookieAttributes() {
	return {
		...sessionCookieAttributes(),
		value: '',
		maxAge: 0,
		expires: new Date(0)
	};
}

export const SESSION_COOKIE_NAME = ADMIN_SESSION_COOKIE;
