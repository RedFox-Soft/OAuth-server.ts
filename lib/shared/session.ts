import { Session } from 'lib/models/session.js';
import { cookieNames } from '../consts/param_list.js';

export default async function sessionHandler(oidc) {
	oidc.session = await Session.get(oidc);

	return async function setCookies() {
		const session = oidc.cookie[cookieNames.session];
		if (session.value) {
			await oidc.session.save();
			session.set({
				value: oidc.session.id,
				expires: new Date(oidc.session.payload.exp * 1000)
			});
		}
	};
}
