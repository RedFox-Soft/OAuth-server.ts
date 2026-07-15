import { Elysia, t } from 'elysia';
import { InvalidRequest } from '../helpers/errors.js';
import {
	cibaGrantParameters,
	codeGrantParameters,
	deviceCodeGrantParameters,
	executeGrant,
	grantTypeSchema,
	refreshTokenGrantParameters
} from './grants/index.js';
import { routeNames } from 'lib/consts/param_list.js';
import {
	dpopValidate,
	setNonceHeader,
	validateReplay
} from 'lib/helpers/validate_dpop.js';
import { AuthPlugin, authHeaders, authParams } from 'lib/plugins/auth.js';
import { TokenResponse } from 'lib/shared/response_schemas.js';

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

		return executeGrant(grantType, oidc, dPoP);
	},
	{
		body: t.Composite([
			authParams,
			t.Object({
				scope: t.Optional(t.String()),
				resource: t.Optional(t.String({ format: 'uri' })),
				// Literal union of the grant types the project supports (single source of truth in
				// grants/index.ts). A proper literal union — not a `keys().map(t.Literal)` array,
				// whose TypeBox static type collapses to `never` and makes the handler fail Elysia's
				// InlineHandlerNonMacro check (which is what previously blocked the `response` map).
				grant_type: grantTypeSchema
			}),
			t.Partial(codeGrantParameters),
			t.Partial(refreshTokenGrantParameters),
			t.Partial(deviceCodeGrantParameters),
			t.Partial(cibaGrantParameters)
		]),
		headers: authHeaders,
		// Success body varies by grant_type (access-token-only for client_credentials, +id_token/
		// refresh_token for the code/device/ciba flows). Modelled as a grant-dependent union in
		// TokenResponse. See contracts/endpoint-responses.md.
		response: TokenResponse
	}
);
