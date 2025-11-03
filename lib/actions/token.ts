import { Elysia, t } from 'elysia';
import { InvalidRequest } from '../helpers/errors.ts';
import getTokenAuth, { authParams } from '../shared/token_auth.ts';
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

		const tokenAuth = getTokenAuth();
		for (const middleware of tokenAuth) {
			await middleware(ctx);
		}

		const grantType = body.grant_type;
		if (!ctx.oidc.client.grantTypeAllowed(grantType)) {
			throw new InvalidRequest(
				'requested grant type is not allowed for this client'
			);
		}

		return executeGrant(grantType, ctx);
	},
	{
		body: t.Composite([
			authParams,
			t.Object({
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
