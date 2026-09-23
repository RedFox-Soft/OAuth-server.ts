import { Session } from 'lib/models/session.js';
import {
	cookieNames,
	endUserCookieAttributes,
	sessionCookieName
} from '../consts/param_list.js';

/*
 * The session cookie's path, written explicitly on every set.
 *
 * Left implicit, the browser applies RFC 6265's default-path — the directory of the *request* URI —
 * so the same cookie name landed on `/` when written from `/auth` and on `/logout` when written
 * from `/logout/confirm`. Two cookies under one name, and the clearing one at sign-out was not the
 * one the browser kept sending back. Naming the path makes a session cookie a single cookie wherever
 * it is written, which is what makes destroying it observable to the browser.
 *
 * The path stays `/` for every bucket, and deliberately does not carry the bucket. It would, if every
 * bucket were prefixed — but the default bucket is served at the root, so its cookie must live at `/`,
 * and a cookie at `/` is sent to every other bucket's path anyway. Path scoping would isolate the
 * named buckets from each other and fail on the one bucket every existing deployment uses. The name
 * carries the partition instead.
 */
export const SESSION_COOKIE_PATH = '/';

/*
 * Clearing a cookie only removes it when the attributes identify the *same* cookie, so this is
 * derived from the one path constant above rather than restating it at each call site.
 */
export function expiredSessionCookie() {
	return {
		// Restated rather than inherited from the route's cookie schema: this clear is also issued from
		// the admin console's sign-out (lib/admin/auth/login.ts), whose cookie jar carries none of the
		// end-user defaults.
		...endUserCookieAttributes,
		value: '',
		path: SESSION_COOKIE_PATH,
		maxAge: 0,
		expires: new Date(0)
	};
}

/*
 * The un-suffixed name every session cookie carried before buckets were populations of their own.
 *
 * Expired rather than ignored on the first request that presents it. Left in place the browser keeps
 * sending it forever, and a later change that reintroduced the bare name would find a stale value
 * waiting for it — a sign-in nobody can account for.
 */
export function clearLegacySessionCookie(cookie): void {
	if (!cookie[cookieNames.session]?.value) return;
	cookie[cookieNames.session].set(expiredSessionCookie());
}

export default async function sessionHandler(oidc) {
	await Session.get(oidc);

	return async function setCookies() {
		clearLegacySessionCookie(oidc.cookie);
		// The bucket the sign-in is for, exactly as `Session.get` read it — a cookie written under one
		// name and read back under another is a sign-in that completes and then does not exist.
		const cookie =
			oidc.cookie[sessionCookieName(oidc.signInBucket ?? oidc.bucket)];
		// Persist and (re)issue the session cookie when the session is worth
		// keeping: it already had a cookie (returning user — refresh it), it now
		// carries an authenticated account (a login just resolved), or it was
		// otherwise mutated. Guarding only on the pre-existing cookie value meant a
		// first-time login was never saved, so session-bound artifacts (e.g. an
		// authorization code with expiresWithSession) could never be validated at
		// the token endpoint — Session.findByUid returned nothing.
		if (
			cookie.value ||
			oidc.session.payload.accountId ||
			oidc.session.touched
		) {
			await oidc.session.save();
			/*
			 * The end user's "remember me" answer, and the only place it becomes observable. A cookie
			 * carrying neither `Expires` nor `Max-Age` is non-persistent (RFC 6265 §4.1.2.1-2), so the
			 * browser drops it when the browsing session ends — which is what declining asks for.
			 *
			 * Omission is enough: `set()` assigns onto the route schema's initial attributes rather than
			 * merging onto the cookie's current state, and those attributes carry no lifetime. Were it
			 * the other way round, this would silently do nothing on a request that wrote the cookie twice.
			 */
			cookie.set({
				value: oidc.session.id,
				path: SESSION_COOKIE_PATH,
				...(oidc.session.payload.transient
					? undefined
					: { expires: new Date(oidc.session.payload.exp * 1000) })
			});
		}
	};
}
