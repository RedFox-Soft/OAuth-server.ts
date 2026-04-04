import { Elysia, t } from 'elysia';
import { InvalidRequest } from '../helpers/errors.js';
import { authParams } from '../shared/token_auth.js';
import {
	codeGrantParameters,
	deviceCodeGrantParameters,
	executeGrant,
	grantStore,
	refreshTokenGrantParameters
} from './grants/index.js';
import { routeNames } from 'lib/consts/param_list.js';
import {
	dpopValidate,
	setNonceHeader,
	validateReplay
} from 'lib/helpers/validate_dpop.js';
import { AuthPlugin, authHeaders } from 'lib/plugins/auth.js';

const grantTypes = Array.from(grantStore.keys());

export const tokenAction = new Elysia().use(AuthPlugin).post(
	routeNames.token,
	async ({ body, headers, route, set, oidc }) => {
		const client = oidc.client;
		const dPoP = await dpopValidate(headers.dpop, { route });
		setNonceHeader(set.headers, dPoP);
		await validateReplay(client.clientId, dPoP);

		const grantType = body.grant_type;
		if (!client.grantTypeAllowed(grantType)) {
			throw new InvalidRequest(
				'requested grant type is not allowed for this client'
			);
		}

		return executeGrant(grantType, { oidc }, dPoP);
	},
	{
		body: t.Composite([
			authParams,
			t.Object({
				scope: t.Optional(t.String()),
				resource: t.Optional(t.String({ format: 'uri' })),
				grant_type: t.Union(
					grantTypes.map((gt) => t.Literal(gt)),
					{ error: 'invalid grant_type' }
				)
			}),
			t.Partial(codeGrantParameters),
			t.Partial(refreshTokenGrantParameters),
			t.Partial(deviceCodeGrantParameters)
		]),
		headers: authHeaders
	}
);
