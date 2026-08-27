import { Session } from 'lib/models/session.js';
import { cookieNames } from '../consts/param_list.js';

/*
 * The session cookie's path, written explicitly on every set.
 *
 * Left implicit, the browser applies RFC 6265's default-path — the directory of the *request* URI —
 * so the same cookie name landed on `/` when written from `/auth` and on `/logout` when written
 * from `/logout/confirm`. Two cookies under one name, and the clearing one at sign-out was not the
 * one the browser kept sending back. Naming the path makes `_session` a single cookie wherever it
 * is written, which is what makes destroying it observable to the browser.
 */
export const SESSION_COOKIE_PATH = '/';

/*
 * Clearing a cookie only removes it when the attributes identify the *same* cookie, so this is
 * derived from the one path constant above rather than restating it at each call site.
 */
export function expiredSessionCookie() {
	return {
		value: '',
		path: SESSION_COOKIE_PATH,
		maxAge: 0,
		expires: new Date(0)
	};
}

export default async function sessionHandler(oidc) {
	oidc.session = await Session.get(oidc);

	return async function setCookies() {
		const cookie = oidc.cookie[cookieNames.session];
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
			cookie.set({
				value: oidc.session.id,
				path: SESSION_COOKIE_PATH,
				expires: new Date(oidc.session.payload.exp * 1000)
			});
		}
	};
}
