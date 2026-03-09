import { Session } from 'lib/models/session.js';
import { cookieNames } from '../consts/param_list.js';

export default async function sessionHandler(ctx) {
	ctx.oidc.session = await Session.get(ctx);

	return async function setCookies() {
		const session = ctx.cookie[cookieNames.session];
		if (session.value) {
			await ctx.oidc.session.save();
			session.set({
				value: ctx.oidc.session.id,
				expires: new Date(ctx.oidc.session.payload.exp * 1000)
			});
		}
	};
}
