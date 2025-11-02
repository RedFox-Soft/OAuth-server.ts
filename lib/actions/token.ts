import { Elysia, t } from 'elysia';

import { provider } from 'lib/provider.js';
import instance from '../helpers/weak_cache.ts';
import { UnsupportedGrantType, InvalidRequest } from '../helpers/errors.ts';
import getTokenAuth from '../shared/token_auth.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import {
	codeGrantParameters,
	deviceCodeGrantParameters,
	executeGrant,
	grantStore,
	refreshTokenGrantParameters
} from './grants/index.js';
import { routeNames } from 'lib/consts/param_list.js';

const grantTypes = Array.from(grantStore.keys());

export const tokenAction = new Elysia().post(
	routeNames.token,
	async ({ body, headers, route }) => {
		const ctx = {
			headers,
			_matchedRouteName: route
		};
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = body;
		ctx.oidc.body = body;

		const { params: authParams, middleware: tokenAuth } =
			getTokenAuth(provider);
		const { grantTypeParams } = instance(provider);

		for (const middleware of tokenAuth) {
			await middleware(ctx);
		}

		const grantParams = grantTypeParams.get(ctx.oidc.params.grant_type);
		if (grantParams) {
			Object.keys(ctx.oidc.params).forEach((key) => {
				if (!(authParams.has(key) || grantParams.has(key))) {
					delete ctx.oidc.params[key];
				}
			});
		}

		if (!ctx.oidc.client.grantTypeAllowed(ctx.oidc.params.grant_type)) {
			throw new InvalidRequest(
				'requested grant type is not allowed for this client'
			);
		}

		const grantType = body.grant_type;
		return executeGrant(grantType, ctx);
	},
	{
		body: t.Composite([
			t.Object({
				client_id: t.Optional(t.String()),
				client_assertion: t.Optional(t.String()),
				client_assertion_type: t.Optional(t.String()),
				client_secret: t.Optional(t.String()),
				scope: t.Optional(t.String()),
				grant_type: t.Union(
					grantTypes.map((gt) => t.Literal(gt)),
					{ error: 'invalid grant_type' }
				)
			}),
			t.Partial(codeGrantParameters),
			t.Partial(refreshTokenGrantParameters),
			t.Partial(deviceCodeGrantParameters)
		]),
		headers: t.Object({
			authorization: t.Optional(t.String())
		})
	}
);
