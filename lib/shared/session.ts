import { Session } from 'lib/models/session.js';
import { cookieNames } from '../consts/param_list.js';

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
		if (cookie.value || oidc.session.payload.accountId || oidc.session.touched) {
			await oidc.session.save();
			cookie.set({
				value: oidc.session.id,
				expires: new Date(oidc.session.payload.exp * 1000)
			});
		}
	};
}
