import { Session } from 'lib/models/session.js';
import { cookieNames } from '../consts/param_list.js';
import { ttl } from 'lib/configs/liveTime.js';

export default async function sessionHandler(ctx) {
	ctx.oidc.session = new Proxy(await Session.get(ctx), {
		set(obj, prop, value) {
			switch (prop) {
				case 'touched':
					Reflect.defineProperty(obj, 'touched', { writable: true, value });
					break;
				case 'destroyed':
					Reflect.defineProperty(obj, 'destroyed', {
						configurable: false,
						writable: true,
						value
					});
					Reflect.defineProperty(obj, 'touched', {
						configurable: false,
						writable: false,
						value: false
					});
					break;
				case 'accountId':
					if (typeof value !== 'string' || !value) {
						throw new TypeError(
							`accountId must be a non-empty string, got: ${typeof value}`
						);
					}
				default: // eslint-disable-line no-fallthrough
					Reflect.set(obj, prop, value);
					Reflect.defineProperty(obj, 'touched', {
						writable: true,
						value: true
					});
			}

			return true;
		}
	});

	return async function setCookies() {
		const session = ctx.cookie[cookieNames.session];

		// refresh the session duration
		if (
			(!ctx.oidc.session.new || ctx.oidc.session.touched) &&
			!ctx.oidc.session.destroyed
		) {
			session.value = ctx.oidc.session.id;
			await ctx.oidc.session.save(ttl.Session);
		}

		if (session) {
			session?.set({
				expires: new Date(ctx.oidc.session.exp * 1000)
			});
		}
	};
}
