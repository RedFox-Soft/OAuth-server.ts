import { Elysia, t } from 'elysia';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { tokenAuth } from 'lib/shared/token_auth.js';

export const authHeaders = t.Object({
	authorization: t.Optional(t.String()),
	dpop: t.Optional(t.String())
});

export const AuthPlugin = new Elysia().derive(
	{ as: 'scoped' },
	async function ({ headers, route, body }) {
		const ctx = {
			headers,
			_matchedRouteName: route
		};
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = body;
		ctx.oidc.body = body;

		await tokenAuth(body, headers, ctx);

		return { ctx };
	}
);
