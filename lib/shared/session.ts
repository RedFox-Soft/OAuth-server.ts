import { globalConfiguration } from '../globalConfiguration.ts';

export default async function sessionHandler(ctx) {
	ctx.oidc.session = new Proxy(await ctx.oidc.provider.Session.get(ctx), {
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
		const sessionCookieName = ctx.oidc.provider.cookieName('session');
		const session = ctx.cookie[sessionCookieName];

		// refresh the session duration
		if (
			(!ctx.oidc.session.new || ctx.oidc.session.touched) &&
			!ctx.oidc.session.destroyed
		) {
			let ttl = globalConfiguration.ttl.Session;

			if (typeof ttl === 'function') {
				ttl = ttl(ctx, ctx.oidc.session);
			}

			session.value = ctx.oidc.session.id;
			await ctx.oidc.session.save(ttl);
		}

		if (session) {
			session?.set({
				expires: new Date(ctx.oidc.session.exp * 1000)
			});
		}
	};
}
